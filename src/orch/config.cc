#include "orch/config.h"

#include <algorithm>

namespace nanonos {

std::vector<std::string_view> Tokenize(std::string_view line) {
  std::vector<std::string_view> out;
  size_t i = 0;
  while (i < line.size()) {
    while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
    const size_t start = i;
    while (i < line.size() && line[i] != ' ' && line[i] != '\t') ++i;
    if (i > start) out.push_back(line.substr(start, i - start));
  }
  return out;
}

const InterfaceConfig* SwitchConfig::FindInterface(std::string_view name) const {
  for (const InterfaceConfig& i : interfaces) {
    if (i.name == name) return &i;
  }
  return nullptr;
}

namespace {

using Tokens = std::vector<std::string_view>;

std::optional<uint16_t> ParseNamedIndex(std::string_view name, std::string_view prefix, int max) {
  if (name.size() <= prefix.size() || name.substr(0, prefix.size()) != prefix) return std::nullopt;
  const auto n = ParseInt(name.substr(prefix.size()), 0, max);
  if (!n) return std::nullopt;
  return static_cast<uint16_t>(*n);
}

// "100000000", "100m", "10g", "500k" (bits per second).
std::optional<uint64_t> ParseRate(std::string_view text) {
  uint64_t scale = 1;
  if (!text.empty()) {
    switch (text.back()) {
      case 'k':
      case 'K':
        scale = 1000;
        break;
      case 'm':
      case 'M':
        scale = 1000 * 1000;
        break;
      case 'g':
      case 'G':
        scale = 1000 * 1000 * 1000;
        break;
      default:
        break;
    }
    if (scale != 1) text.remove_suffix(1);
  }
  const auto v = ParseInt(text, 0, 400'000'000'000LL);
  if (!v) return std::nullopt;
  return static_cast<uint64_t>(*v) * scale;
}

bool ParseVlanList(std::string_view text, std::vector<uint16_t>* out) {
  while (!text.empty()) {
    const size_t comma = text.find(',');
    const std::string_view item = text.substr(0, comma);
    const size_t dash = item.find('-');
    const auto lo = ParseInt(item.substr(0, dash), 1, 4094);
    const auto hi = dash == std::string_view::npos ? lo : ParseInt(item.substr(dash + 1), 1, 4094);
    if (!lo || !hi || *hi < *lo) return false;
    for (int64_t v = *lo; v <= *hi; ++v) out->push_back(static_cast<uint16_t>(v));
    if (comma == std::string_view::npos) break;
    text.remove_prefix(comma + 1);
  }
  std::sort(out->begin(), out->end());
  out->erase(std::unique(out->begin(), out->end()), out->end());
  return !out->empty();
}

std::optional<PortRange> ParsePortRange(std::string_view text) {
  const size_t dash = text.find('-');
  const auto lo = ParseInt(text.substr(0, dash), 0, 65535);
  const auto hi = dash == std::string_view::npos ? lo : ParseInt(text.substr(dash + 1), 0, 65535);
  if (!lo || !hi || *hi < *lo) return std::nullopt;
  return PortRange{static_cast<uint16_t>(*lo), static_cast<uint16_t>(*hi)};
}

std::optional<Ipv4Prefix> ParsePrefixOrAny(std::string_view text) {
  if (text == "any") return Ipv4Prefix{};
  return Ipv4Prefix::Parse(text);
}

std::string JoinFrom(const Tokens& t, size_t first) {
  std::string out;
  for (size_t i = first; i < t.size(); ++i) {
    if (i > first) out += ' ';
    out += t[i];
  }
  return out;
}

class Parser {
 public:
  explicit Parser(ConfigError* error) : error_(error) {}

  std::optional<SwitchConfig> Run(std::string_view text) {
    while (!text.empty()) {
      ++line_no_;
      const size_t nl = text.find('\n');
      std::string_view line = text.substr(0, nl);
      text.remove_prefix(nl == std::string_view::npos ? text.size() : nl + 1);
      if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
      const size_t comment = line.find_first_of("!#");
      if (comment != std::string_view::npos) line = line.substr(0, comment);
      const Tokens t = Tokenize(line);
      if (t.empty()) continue;
      const bool indented = line[0] == ' ' || line[0] == '\t';
      bool ok = false;
      if (!indented) {
        block_ = Block::kNone;
        ok = TopLevel(t);
      } else {
        switch (block_) {
          case Block::kNone:
            ok = Fail("indented line outside of a block");
            break;
          case Block::kInterface:
            ok = InterfaceCommand(t, &cfg_.interfaces[current_]);
            break;
          case Block::kSvi:
            ok = SviCommand(t, &cfg_.svis[current_]);
            break;
          case Block::kBgp:
            ok = BgpCommand(t);
            break;
          case Block::kAcl:
            ok = AclCommand(t);
            break;
          case Block::kLldp:
            ok = LldpCommand(t);
            break;
        }
      }
      if (!ok) return std::nullopt;
    }
    if (!Validate()) return std::nullopt;
    return std::move(cfg_);
  }

 private:
  enum class Block { kNone, kInterface, kSvi, kBgp, kAcl, kLldp };

  bool Fail(std::string message) {
    error_->line = line_no_;
    error_->message = std::move(message);
    return false;
  }

  bool TopLevel(const Tokens& t) {
    const std::string_view cmd = t[0];
    if (cmd == "end") return true;
    if (cmd == "hostname" && t.size() == 2) {
      cfg_.hostname = std::string(t[1]);
      return true;
    }
    if (cmd == "switch-mac" && t.size() == 2) {
      const auto mac = MacAddress::Parse(t[1]);
      if (!mac || mac->IsMulticast() || mac->IsZero()) return Fail("invalid switch MAC");
      cfg_.switch_mac = *mac;
      return true;
    }
    if (cmd == "ecmp-hash-seed" && t.size() == 2) {
      const auto v = ParseInt(t[1], 0, 0xffffffffLL);
      if (!v) return Fail("invalid hash seed");
      cfg_.ecmp_hash_seed = static_cast<uint32_t>(*v);
      return true;
    }
    if (cmd == "fdb" && t.size() == 3 && t[1] == "aging") {
      const auto v = ParseInt(t[2], 0, 1000000);
      if (!v) return Fail("invalid FDB aging time");
      cfg_.fdb_aging_s = static_cast<uint32_t>(*v);
      return true;
    }
    if (cmd == "vlan" && t.size() == 2) {
      if (!ParseVlanList(t[1], &cfg_.vlans)) return Fail("invalid VLAN list");
      return true;
    }
    if (cmd == "interface" && t.size() == 2) return OpenInterface(t[1]);
    if (cmd == "ip" && t.size() >= 4 && t[1] == "route") return StaticRoute(t);
    if (cmd == "qos" && t.size() == 5 && t[1] == "dscp" && t[3] == "tc") {
      const auto dscp = ParseInt(t[2], 0, 63);
      const auto tc = ParseInt(t[4], 0, kNumQueues - 1);
      if (!dscp || !tc) return Fail("invalid DSCP to TC mapping");
      cfg_.dscp_to_tc.emplace_back(static_cast<uint8_t>(*dscp), static_cast<uint8_t>(*tc));
      return true;
    }
    if (cmd == "copp" && (t.size() == 4 || t.size() == 6) && t[2] == "pps") return Copp(t);
    if (cmd == "access-list" && t.size() == 1) {
      block_ = Block::kAcl;
      return true;
    }
    if (cmd == "lldp" && t.size() == 1) {
      cfg_.lldp.enabled = true;
      block_ = Block::kLldp;
      return true;
    }
    if (cmd == "no" && t.size() == 2 && t[1] == "lldp") {
      cfg_.lldp.enabled = false;
      return true;
    }
    if (cmd == "router" && t.size() == 3 && t[1] == "bgp") {
      const auto asn = ParseInt(t[2], 1, 0xffffffffLL);
      if (!asn) return Fail("invalid AS number");
      cfg_.bgp.enabled = true;
      cfg_.bgp.asn = static_cast<uint32_t>(*asn);
      block_ = Block::kBgp;
      return true;
    }
    return Fail("unknown command: " + std::string(cmd));
  }

  bool OpenInterface(std::string_view name) {
    if (const auto vid = ParseNamedIndex(name, "Vlan", 4094)) {
      if (*vid == 0) return Fail("invalid VLAN interface");
      for (size_t i = 0; i < cfg_.svis.size(); ++i) {
        if (cfg_.svis[i].vlan == *vid) {
          current_ = i;
          block_ = Block::kSvi;
          return true;
        }
      }
      cfg_.svis.push_back(SviConfig{*vid, std::nullopt, 1500});
      current_ = cfg_.svis.size() - 1;
      block_ = Block::kSvi;
      return true;
    }
    const auto index = ParseNamedIndex(name, "Ethernet", 1023);
    if (!index) return Fail("interface names are EthernetN or VlanN");
    for (size_t i = 0; i < cfg_.interfaces.size(); ++i) {
      if (cfg_.interfaces[i].index == *index) {
        current_ = i;
        block_ = Block::kInterface;
        return true;
      }
    }
    InterfaceConfig ic;
    ic.name = std::string(name);
    ic.index = *index;
    cfg_.interfaces.push_back(std::move(ic));
    current_ = cfg_.interfaces.size() - 1;
    block_ = Block::kInterface;
    return true;
  }

  bool InterfaceCommand(const Tokens& t, InterfaceConfig* ic) {
    const std::string_view cmd = t[0];
    if (cmd == "port" && t.size() == 2) {
      ic->netdev = std::string(t[1]);
      return true;
    }
    if (cmd == "description" && t.size() >= 2) {
      ic->description = JoinFrom(t, 1);
      return true;
    }
    if (cmd == "shutdown" && t.size() == 1) {
      ic->shutdown = true;
      return true;
    }
    if (cmd == "no" && t.size() == 2 && t[1] == "shutdown") {
      ic->shutdown = false;
      return true;
    }
    if (cmd == "mtu" && t.size() == 2) {
      const auto v = ParseInt(t[1], 68, 2026);
      if (!v) return Fail("invalid MTU");
      ic->mtu = static_cast<uint16_t>(*v);
      return true;
    }
    if (cmd == "switchport") return Switchport(t, ic);
    if (cmd == "ip" && t.size() == 3 && t[1] == "address") {
      const auto a = InterfaceAddress::Parse(t[2]);
      if (!a || a->len == 0 || a->len > 31) return Fail("invalid interface address");
      ic->address = *a;
      ic->mode = sai::PortMode::kRouted;
      return true;
    }
    if (cmd == "storm-control" && t.size() == 4 && t[2] == "pps") {
      const auto pps = ParseInt(t[3], 0, 100'000'000);
      if (!pps) return Fail("invalid storm-control rate");
      sai::StormType type;
      if (t[1] == "broadcast") {
        type = sai::StormType::kBroadcast;
      } else if (t[1] == "multicast") {
        type = sai::StormType::kMulticast;
      } else if (t[1] == "unknown-unicast") {
        type = sai::StormType::kUnknownUnicast;
      } else {
        return Fail("storm-control type is broadcast, multicast or unknown-unicast");
      }
      ic->storm_pps[static_cast<size_t>(type)] = static_cast<uint64_t>(*pps);
      return true;
    }
    if (cmd == "port-security" && t.size() == 3 && t[1] == "max-mac") {
      const auto v = ParseInt(t[2], 0, 1'000'000);
      if (!v) return Fail("invalid MAC limit");
      ic->max_macs = static_cast<uint32_t>(*v);
      return true;
    }
    if (cmd == "qos" && t.size() >= 2) return InterfaceQos(t, ic);
    return Fail("unknown interface command: " + std::string(cmd));
  }

  bool Switchport(const Tokens& t, InterfaceConfig* ic) {
    if (t.size() == 3 && t[1] == "mode") {
      if (t[2] == "access") {
        ic->mode = sai::PortMode::kAccess;
      } else if (t[2] == "trunk") {
        ic->mode = sai::PortMode::kTrunk;
      } else {
        return Fail("switchport mode is access or trunk");
      }
      ic->address.reset();
      return true;
    }
    if (t.size() == 4 && t[1] == "access" && t[2] == "vlan") {
      const auto v = ParseInt(t[3], 1, 4094);
      if (!v) return Fail("invalid VLAN");
      ic->access_vlan = static_cast<uint16_t>(*v);
      return true;
    }
    if (t.size() == 5 && t[1] == "trunk" && t[2] == "allowed" && t[3] == "vlan") {
      ic->trunk_vlans.clear();
      if (!ParseVlanList(t[4], &ic->trunk_vlans)) return Fail("invalid VLAN list");
      return true;
    }
    if (t.size() == 5 && t[1] == "trunk" && t[2] == "native" && t[3] == "vlan") {
      const auto v = ParseInt(t[4], 1, 4094);
      if (!v) return Fail("invalid VLAN");
      ic->native_vlan = static_cast<uint16_t>(*v);
      return true;
    }
    return Fail("unknown switchport command");
  }

  bool InterfaceQos(const Tokens& t, InterfaceConfig* ic) {
    if (t.size() >= 4 && t[1] == "scheduler" && t[2] == "strict") {
      ic->scheduler_set = true;
      ic->scheduler.strict_mask = 0;
      for (size_t i = 3; i < t.size(); ++i) {
        const auto q = ParseInt(t[i], 0, kNumQueues - 1);
        if (!q) return Fail("invalid queue");
        ic->scheduler.strict_mask = static_cast<uint8_t>(ic->scheduler.strict_mask | (1u << *q));
      }
      return true;
    }
    if (t.size() == 3 + kNumQueues && t[1] == "scheduler" && t[2] == "weights") {
      ic->scheduler_set = true;
      for (int q = 0; q < kNumQueues; ++q) {
        const auto w = ParseInt(t[3 + static_cast<size_t>(q)], 1, 100);
        if (!w) return Fail("DWRR weights are 1-100");
        ic->scheduler.weights[static_cast<size_t>(q)] = static_cast<uint16_t>(*w);
      }
      return true;
    }
    if (t.size() == 3 && t[1] == "shaper") {
      const auto rate = ParseRate(t[2]);
      if (!rate) return Fail("invalid shaper rate");
      ic->shaper_bps = *rate;
      return true;
    }
    // qos wred queue Q min BYTES max BYTES probability PCT [ecn|no-ecn]
    if ((t.size() == 10 || t.size() == 11) && t[1] == "wred" && t[2] == "queue" && t[4] == "min" &&
        t[6] == "max" && t[8] == "probability") {
      const auto q = ParseInt(t[3], 0, kNumQueues - 1);
      const auto lo = ParseInt(t[5], 0, 100'000'000);
      const auto hi = ParseInt(t[7], 0, 100'000'000);
      const auto p = ParseInt(t[9], 0, 100);
      if (!q || !lo || !hi || !p || *hi < *lo) return Fail("invalid WRED profile");
      WredProfile w;
      w.enabled = true;
      w.min_bytes = static_cast<uint32_t>(*lo);
      w.max_bytes = static_cast<uint32_t>(*hi);
      w.max_prob_pct = static_cast<uint32_t>(*p);
      w.ecn = t.size() == 10 || t[10] == "ecn";
      if (t.size() == 11 && t[10] != "ecn" && t[10] != "no-ecn")
        return Fail("expected ecn or no-ecn");
      ic->wred.emplace_back(static_cast<uint8_t>(*q), w);
      return true;
    }
    return Fail("unknown qos command");
  }

  bool SviCommand(const Tokens& t, SviConfig* svi) {
    if (t[0] == "ip" && t.size() == 3 && t[1] == "address") {
      const auto a = InterfaceAddress::Parse(t[2]);
      if (!a || a->len == 0 || a->len > 31) return Fail("invalid interface address");
      svi->address = *a;
      return true;
    }
    if (t[0] == "mtu" && t.size() == 2) {
      const auto v = ParseInt(t[1], 68, 2026);
      if (!v) return Fail("invalid MTU");
      svi->mtu = static_cast<uint16_t>(*v);
      return true;
    }
    if (t[0] == "description" || (t[0] == "no" && t.size() == 2 && t[1] == "shutdown")) return true;
    return Fail("unknown VLAN interface command: " + std::string(t[0]));
  }

  bool StaticRoute(const Tokens& t) {
    StaticRouteConfig r;
    const auto prefix = Ipv4Prefix::Parse(t[2]);
    if (!prefix || t[2].find('/') == std::string_view::npos) return Fail("invalid route prefix");
    r.prefix = *prefix;
    if (t.size() == 4 && t[3] == "blackhole") {
      r.blackhole = true;
    } else {
      for (size_t i = 3; i < t.size(); ++i) {
        const auto nh = ParseIpv4(t[i]);
        if (!nh) return Fail("invalid next hop");
        r.next_hops.push_back(*nh);
      }
    }
    cfg_.static_routes.push_back(std::move(r));
    return true;
  }

  bool Copp(const Tokens& t) {
    static constexpr std::pair<std::string_view, sai::TrapType> kTraps[] = {
        {"lldp", sai::TrapType::kLldp},    {"arp", sai::TrapType::kArp},
        {"bgp", sai::TrapType::kBgp},      {"icmp", sai::TrapType::kIcmpToMe},
        {"ip2me", sai::TrapType::kIpToMe},
    };
    const auto pps = ParseInt(t[3], 0, 10'000'000);
    if (!pps) return Fail("invalid CoPP rate");
    std::optional<int64_t> burst = pps;
    if (t.size() == 6) {
      if (t[4] != "burst") return Fail("expected burst");
      burst = ParseInt(t[5], 1, 10'000'000);
      if (!burst) return Fail("invalid CoPP burst");
    }
    for (const auto& [name, trap] : kTraps) {
      if (t[1] == name) {
        cfg_.copp.pps[static_cast<size_t>(trap)] = static_cast<uint64_t>(*pps);
        cfg_.copp.burst[static_cast<size_t>(trap)] = static_cast<uint64_t>(*burst);
        return true;
      }
    }
    return Fail("CoPP trap is lldp, arp, bgp, icmp or ip2me");
  }

  // rule SEQ (permit|deny|set-tc N) [ip|tcp|udp|icmp|proto N] [src P] [dst P]
  //      [sport R] [dport R] [dscp N] [in-port EthernetN]
  bool AclCommand(const Tokens& t) {
    if (t[0] != "rule" || t.size() < 3) return Fail("expected: rule SEQ ACTION ...");
    const auto seq = ParseInt(t[1], 1, 1'000'000);
    if (!seq) return Fail("invalid rule sequence number");
    AclRule r;
    r.seq = static_cast<uint32_t>(*seq);
    size_t i = 2;
    if (t[i] == "permit") {
      r.action = AclAction::kPermit;
      ++i;
    } else if (t[i] == "deny") {
      r.action = AclAction::kDeny;
      ++i;
    } else if (t[i] == "set-tc" && i + 1 < t.size()) {
      const auto tc = ParseInt(t[i + 1], 0, kNumQueues - 1);
      if (!tc) return Fail("invalid traffic class");
      r.action = AclAction::kSetTc;
      r.set_tc = static_cast<uint8_t>(*tc);
      i += 2;
    } else {
      return Fail("rule action is permit, deny or set-tc N");
    }
    while (i < t.size()) {
      const std::string_view key = t[i];
      if (key == "ip") {
        ++i;
        continue;
      }
      if (key == "tcp" || key == "udp" || key == "icmp") {
        r.ip_proto = key == "tcp" ? kIpProtoTcp : (key == "udp" ? kIpProtoUdp : kIpProtoIcmp);
        ++i;
        continue;
      }
      if (i + 1 >= t.size()) return Fail("missing value for " + std::string(key));
      const std::string_view value = t[i + 1];
      if (key == "proto") {
        const auto p = ParseInt(value, 0, 255);
        if (!p) return Fail("invalid protocol");
        r.ip_proto = static_cast<int>(*p);
      } else if (key == "src" || key == "dst") {
        const auto p = ParsePrefixOrAny(value);
        if (!p) return Fail("invalid prefix");
        (key == "src" ? r.src : r.dst) = *p;
      } else if (key == "sport" || key == "dport") {
        const auto range = ParsePortRange(value);
        if (!range) return Fail("invalid port range");
        (key == "sport" ? r.src_ports : r.dst_ports) = *range;
      } else if (key == "dscp") {
        const auto d = ParseInt(value, 0, 63);
        if (!d) return Fail("invalid DSCP");
        r.dscp = static_cast<int>(*d);
      } else if (key == "in-port") {
        const auto port = ParseNamedIndex(value, "Ethernet", 1023);
        if (!port) return Fail("invalid in-port");
        r.in_port = *port;
      } else {
        return Fail("unknown rule field: " + std::string(key));
      }
      i += 2;
    }
    if ((!r.src_ports.any() || !r.dst_ports.any()) && r.ip_proto != kIpProtoTcp &&
        r.ip_proto != kIpProtoUdp) {
      return Fail("port ranges need tcp or udp");
    }
    cfg_.acl_rules.push_back(r);
    return true;
  }

  bool LldpCommand(const Tokens& t) {
    if (t.size() == 2 && (t[0] == "tx-interval" || t[0] == "hold-multiplier")) {
      const auto v = ParseInt(t[1], 1, 3600);
      if (!v) return Fail("invalid LLDP timer");
      (t[0] == "tx-interval" ? cfg_.lldp.tx_interval_s : cfg_.lldp.hold_multiplier) =
          static_cast<uint16_t>(*v);
      return true;
    }
    if (t.size() == 1 && t[0] == "disable") {
      cfg_.lldp.enabled = false;
      return true;
    }
    return Fail("unknown lldp command");
  }

  bool BgpCommand(const Tokens& t) {
    BgpConfig& b = cfg_.bgp;
    const std::string_view cmd = t[0];
    if (cmd == "router-id" && t.size() == 2) {
      const auto id = ParseIpv4(t[1]);
      if (!id || *id == 0) return Fail("invalid router-id");
      b.router_id = *id;
      return true;
    }
    if (cmd == "timers" && t.size() == 3 && t[1] == "connect-retry") {
      const auto v = ParseInt(t[2], 1, 3600);
      if (!v) return Fail("invalid connect-retry timer");
      b.connect_retry_s = static_cast<uint16_t>(*v);
      return true;
    }
    if (cmd == "timers" && t.size() == 3) {
      const auto ka = ParseInt(t[1], 0, 21845);
      const auto hold = ParseInt(t[2], 0, 65535);
      if (!ka || !hold || (*hold != 0 && *hold < 3) || (*hold != 0 && *ka >= *hold)) {
        return Fail("timers: hold must be 0 or >= 3 and larger than keepalive");
      }
      b.keepalive_s = static_cast<uint16_t>(*ka);
      b.hold_s = static_cast<uint16_t>(*hold);
      return true;
    }
    if (cmd == "maximum-paths" && t.size() == 2) {
      const auto v = ParseInt(t[1], 1, 64);
      if (!v) return Fail("maximum-paths is 1-64");
      b.max_paths = static_cast<uint16_t>(*v);
      return true;
    }
    if (cmd == "network" && t.size() == 2) {
      const auto p = Ipv4Prefix::Parse(t[1]);
      if (!p || t[1].find('/') == std::string_view::npos) return Fail("invalid network");
      b.networks.push_back(*p);
      return true;
    }
    if (cmd == "neighbor" && t.size() >= 3) {
      const auto addr = ParseIpv4(t[1]);
      if (!addr) return Fail("invalid neighbor address");
      BgpNeighborConfig* n = nullptr;
      for (BgpNeighborConfig& existing : b.neighbors) {
        if (existing.address == *addr) n = &existing;
      }
      if (n == nullptr) {
        b.neighbors.push_back(BgpNeighborConfig{});
        n = &b.neighbors.back();
        n->address = *addr;
      }
      const std::string_view attr = t[2];
      if (attr == "remote-as" && t.size() == 4) {
        const auto asn = ParseInt(t[3], 1, 0xffffffffLL);
        if (!asn) return Fail("invalid remote-as");
        n->remote_as = static_cast<uint32_t>(*asn);
        return true;
      }
      if (attr == "description" && t.size() >= 4) {
        n->description = JoinFrom(t, 3);
        return true;
      }
      if (attr == "password" && t.size() == 4) {
        if (t[3].size() > 80) return Fail("TCP-MD5 keys are at most 80 characters");
        n->password = std::string(t[3]);
        return true;
      }
      if (attr == "ttl-security" && t.size() == 5 && t[3] == "hops") {
        const auto hops = ParseInt(t[4], 1, 254);
        if (!hops) return Fail("invalid ttl-security hops");
        n->ttl_security_hops = static_cast<int>(*hops);
        return true;
      }
      if (attr == "passive" && t.size() == 3) {
        n->passive = true;
        return true;
      }
      if (attr == "shutdown" && t.size() == 3) {
        n->shutdown = true;
        return true;
      }
      return Fail("unknown neighbor command");
    }
    return Fail("unknown bgp command: " + std::string(cmd));
  }

  bool Validate() {
    line_no_ = 0;
    for (const BgpNeighborConfig& n : cfg_.bgp.neighbors) {
      if (n.remote_as == 0)
        return Fail("neighbor " + Ipv4ToString(n.address) + " has no remote-as");
      if (n.remote_as == cfg_.bgp.asn) return Fail("iBGP neighbors are not supported");
    }
    if (cfg_.bgp.enabled && cfg_.bgp.router_id == 0) {
      // Default router-id: the first interface address, like most routers.
      for (const InterfaceConfig& ic : cfg_.interfaces) {
        if (ic.address) {
          cfg_.bgp.router_id = ic.address->ip;
          break;
        }
      }
      if (cfg_.bgp.router_id == 0) return Fail("bgp needs a router-id");
    }
    return true;
  }

  ConfigError* error_;
  SwitchConfig cfg_;
  Block block_ = Block::kNone;
  size_t current_ = 0;
  int line_no_ = 0;
};

}  // namespace

std::optional<SwitchConfig> ParseConfig(std::string_view text, ConfigError* error) {
  ConfigError ignored;
  Parser parser(error != nullptr ? error : &ignored);
  return parser.Run(text);
}

}  // namespace nanonos
