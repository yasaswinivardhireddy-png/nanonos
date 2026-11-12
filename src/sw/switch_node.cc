#include "sw/switch_node.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "common/byte_order.h"
#include "common/logging.h"
#include "packet/builder.h"
#include "sw/json.h"

namespace nanonos {
namespace {

constexpr TimeUs kArpRetry = 1 * kUsPerSec;

std::string Pad(std::string s, size_t width) {
  if (s.size() < width) s.append(width - s.size(), ' ');
  return s;
}

std::string Uptime(TimeUs us) {
  const int64_t s = us / kUsPerSec;
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%02lld:%02lld:%02lld", static_cast<long long>(s / 3600),
                static_cast<long long>((s / 60) % 60), static_cast<long long>(s % 60));
  return buf;
}

std::string JoinIps(const std::vector<uint32_t>& ips) {
  std::string out;
  for (size_t i = 0; i < ips.size(); ++i) {
    if (i > 0) out += ", ";
    out += Ipv4ToString(ips[i]);
  }
  return out;
}

}  // namespace

SwitchNode::SwitchNode(Platform platform)
    : platform_(std::move(platform)),
      asic_(platform_.asic, platform_.clock),
      lldp_(platform_.clock) {
  sai::SwitchApi* api = &asic_;
  if (platform_.sai_record) {
    recorder_ = std::make_unique<sai::RecordingSwitchApi>(&asic_, platform_.sai_record);
    api = recorder_.get();
  }
  orch_ = std::make_unique<Orchagent>(api);
  asic_.SetTxHandler(platform_.transmit);
  asic_.SetCpuHandler([this](const CpuPacket& p) { OnCpuPacket(p); });
  started_ = platform_.clock->Now();
}

bool SwitchNode::Configure(const SwitchConfig& config, std::vector<std::string>* errors) {
  config_ = config;
  SetLogTag(config.hostname);
  bool ok = orch_->Apply(config, errors);

  lldp_.Configure(config.hostname, std::string("NanoNOS ") + kNanonosVersion, orch_->switch_mac(),
                  config.lldp.tx_interval_s, config.lldp.hold_multiplier);
  for (const InterfaceConfig& ic : config.interfaces) {
    if (ic.shutdown || ic.index >= asic_.num_ports()) continue;
    lldp_.AddPort(ic.index, ic.name, ic.description, ic.address ? ic.address->ip : 0);
  }

  if (config.bgp.enabled && platform_.bgp_transport != nullptr) {
    bgp::SpeakerConfig sc;
    sc.local_as = config.bgp.asn;
    sc.router_id = config.bgp.router_id;
    sc.hold_time = config.bgp.hold_s;
    sc.keepalive = config.bgp.keepalive_s;
    sc.connect_retry = config.bgp.connect_retry_s;
    sc.max_paths = config.bgp.max_paths;
    sc.networks = config.bgp.networks;
    for (const BgpNeighborConfig& n : config.bgp.neighbors) {
      const RouterInterfaceInfo* rif = nullptr;
      for (const RouterInterfaceInfo& r : orch_->rifs()) {
        if (r.address.Subnet().Contains(n.address)) rif = &r;
      }
      if (rif == nullptr) {
        const std::string msg =
            "bgp neighbor " + Ipv4ToString(n.address) + " is not on a connected subnet";
        LOG_ERROR("%s", msg.c_str());
        if (errors != nullptr) errors->push_back(msg);
        ok = false;
        continue;
      }
      bgp::NeighborConfig nc;
      nc.address = n.address;
      nc.local_address = rif->address.ip;
      nc.remote_as = n.remote_as;
      nc.description = n.description;
      nc.password = n.password;
      nc.ttl_security_hops = n.ttl_security_hops;
      nc.passive = n.passive;
      nc.shutdown = n.shutdown;
      sc.neighbors.push_back(nc);
    }
    speaker_ = std::make_unique<bgp::Speaker>(sc, platform_.bgp_transport, this, platform_.clock);
  }
  return ok;
}

void SwitchNode::ReceiveFrame(uint16_t port, std::span<const uint8_t> frame) {
  asic_.Receive(port, frame);
}

void SwitchNode::ReceiveFromHost(int rif, std::span<const uint8_t> frame) {
  const RouterInterfaceInfo* info = orch_->RifByIndex(rif);
  if (info != nullptr) asic_.SendFromCpu(info->oid, frame);
}

void SwitchNode::SetPortOperStatus(uint16_t port, bool up) {
  if (port >= asic_.num_ports()) return;
  LOG_INFO("%s link %s", orch_->PortName(port).c_str(), up ? "up" : "down");
  // Data plane first (ECMP pruning), then the control plane.
  asic_.SetPortOperStatus(port, up);
  orch_->OnPortOperStatus(port, up);
  lldp_.SetPortUp(port, up);
  if (!up && speaker_) {
    // Fast external failover: drop BGP sessions over this link immediately
    // instead of waiting for the hold timer.
    for (const RouterInterfaceInfo& r : orch_->rifs()) {
      if (r.is_svi || r.port != port) continue;
      for (const bgp::NeighborConfig& n : speaker_->config().neighbors) {
        if (r.address.Subnet().Contains(n.address)) speaker_->ResetNeighbor(n.address, "link down");
      }
    }
  }
}

void SwitchNode::Tick() {
  const TimeUs now = platform_.clock->Now();
  asic_.Drain();
  ResolveNeighbors();
  if (config_.lldp.enabled) {
    lldp_.Tick([this](uint16_t port, std::span<const uint8_t> f) { asic_.SendOnPort(port, f); });
  }
  if (speaker_) speaker_->Tick();
  if (now >= next_slow_tick_) {
    next_slow_tick_ = now + kUsPerSec;
    asic_.AgeFdb();
    orch_->Tick();
  }
  asic_.Drain();
}

void SwitchNode::OnBgpRoute(const Ipv4Prefix& prefix, const std::vector<uint32_t>& next_hops) {
  if (next_hops.empty()) {
    orch_->DeleteRoute(prefix, RouteSource::kBgp);
  } else {
    orch_->SetRoute(prefix, RouteSource::kBgp, next_hops);
  }
}

void SwitchNode::OnCpuPacket(const CpuPacket& p) {
  if (p.trap == sai::TrapType::kLldp) {
    lldp_.OnFrame(p.in_port, p.frame);
    return;
  }
  const RouterInterfaceInfo* rif = orch_->RifByIndex(p.rif);
  if (p.trap == sai::TrapType::kArp) {
    ParsedPacket pkt;
    if (ParseFrame(p.frame, &pkt) != ParseStatus::kOk || !pkt.is_arp() || rif == nullptr) return;
    orch_->OnArpLearned(p.rif, pkt.arp_spa, pkt.arp_sha);  // ARP snooping fills the neighbor table
    if (platform_.deliver_to_host) {
      platform_.deliver_to_host(p.rif, p.frame);
      return;
    }
    if (pkt.arp_op == kArpOpRequest && pkt.arp_tpa == rif->address.ip) {
      uint8_t buf[kMinFrameSize + kVlanTagLen];
      const size_t len = BuildArpFrame(buf, pkt.arp_sha, kArpOpReply, rif->mac, rif->address.ip,
                                       pkt.arp_sha, pkt.arp_spa);
      asic_.SendFromCpu(rif->oid, std::span<const uint8_t>(buf, len));
    }
    return;
  }
  if (platform_.deliver_to_host) {
    platform_.deliver_to_host(p.rif, p.frame);
    return;
  }
  if (p.trap == sai::TrapType::kIcmpToMe && rif != nullptr) AnswerPing(*rif, p.frame);
}

// Built-in ICMP echo responder, used when no host stack is attached.
void SwitchNode::AnswerPing(const RouterInterfaceInfo& rif, std::span<const uint8_t> frame) {
  ParsedPacket pkt;
  if (ParseFrame(frame, &pkt) != ParseStatus::kOk || !pkt.is_ipv4() ||
      pkt.ip_proto != kIpProtoIcmp || pkt.icmp_type != 8 || pkt.ip_fragment) {
    return;
  }
  uint8_t buf[kMaxFrameSize];
  const size_t len = kEthHeaderLen + pkt.ip_total_len;
  std::memcpy(buf, pkt.src_mac.bytes.data(), 6);
  std::memcpy(buf + 6, rif.mac.bytes.data(), 6);
  StoreBe16(buf + 12, kEtherTypeIpv4);
  std::memcpy(buf + kEthHeaderLen, frame.data() + pkt.l3_offset, pkt.ip_total_len);
  uint8_t* ip = buf + kEthHeaderLen;
  StoreBe32(ip + 12, pkt.dst_ip);
  StoreBe32(ip + 16, pkt.src_ip);
  ip[8] = 64;
  StoreBe16(ip + 10, 0);
  StoreBe16(ip + 10, InternetChecksum(ip, pkt.ip_header_len));
  uint8_t* icmp = ip + pkt.ip_header_len;
  const size_t icmp_len = pkt.ip_total_len - pkt.ip_header_len;
  icmp[0] = 0;  // echo reply
  StoreBe16(icmp + 2, 0);
  StoreBe16(icmp + 2, InternetChecksum(icmp, icmp_len));
  asic_.SendFromCpu(rif.oid, std::span<const uint8_t>(buf, std::max(len, kMinFrameSize)));
}

void SwitchNode::ResolveNeighbors() {
  NeighborMiss miss;
  while (asic_.PopNeighborMiss(&miss)) SendArpRequest(miss.rif, miss.ip);
  // Resolve next hops in use (BGP and static) before traffic needs them.
  for (const auto& [rif, ip] : orch_->UnresolvedNextHops()) SendArpRequest(rif, ip);
}

void SwitchNode::SendArpRequest(int rif_index, uint32_t target) {
  const RouterInterfaceInfo* rif = orch_->RifByIndex(rif_index);
  if (rif == nullptr || !rif->up) return;
  const TimeUs now = platform_.clock->Now();
  TimeUs& last = arp_sent_[target];
  if (last != 0 && now - last < kArpRetry) return;
  last = now;
  uint8_t buf[kMinFrameSize + kVlanTagLen];
  const size_t len = BuildArpFrame(buf, MacAddress::Broadcast(), kArpOpRequest, rif->mac,
                                   rif->address.ip, MacAddress{}, target);
  asic_.SendFromCpu(rif->oid, std::span<const uint8_t>(buf, len));
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

std::string SwitchNode::Execute(std::string_view command) {
  const std::vector<std::string_view> t = Tokenize(command);
  const bool json = !t.empty() && t.back() == "json";
  const size_t n = json ? t.size() - 1 : t.size();
  const auto is = [&](std::initializer_list<std::string_view> words) {
    if (words.size() != n) return false;
    size_t i = 0;
    for (std::string_view w : words) {
      if (t[i++] != w) return false;
    }
    return true;
  };

  if (n == 0 || is({"help"})) {
    return "show version | interfaces | mac | arp | ip route | bgp summary | bgp routes |\n"
           "     lldp neighbors | queue counters | drops | copp | acl | resources   [json]\n"
           "clear counters\n"
           "interface NAME shutdown | interface NAME no shutdown\n"
           "ip route PREFIX NEXTHOP... | no ip route PREFIX\n";
  }
  if (is({"show", "version"})) {
    if (json) {
      JsonWriter w;
      w.BeginObject().Field("version", kNanonosVersion).Field("hostname", config_.hostname);
      w.Field("uptime_s", static_cast<uint64_t>((platform_.clock->Now() - started_) / kUsPerSec));
      return w.EndObject().str() + "\n";
    }
    return std::string("NanoNOS ") + kNanonosVersion + " on " + config_.hostname + ", up " +
           Uptime(platform_.clock->Now() - started_) + "\n";
  }
  if (is({"show", "interfaces"})) return ShowInterfaces(json);
  if (is({"show", "mac"})) return ShowMac(json);
  if (is({"show", "arp"})) return ShowArp(json);
  if (is({"show", "ip", "route"})) return ShowRoutes(json);
  if (is({"show", "bgp", "summary"})) return ShowBgpSummary(json);
  if (is({"show", "bgp", "routes"})) return ShowBgpRoutes(json);
  if (is({"show", "lldp", "neighbors"})) return ShowLldp(json);
  if (is({"show", "queue", "counters"})) return ShowQueues(json);
  if (is({"show", "drops"})) return ShowDrops(json);
  if (is({"show", "copp"})) return ShowCopp(json);
  if (is({"show", "acl"})) return ShowAcl(json);
  if (is({"show", "resources"})) return ShowResources(json);
  if (is({"clear", "counters"})) {
    orch_->sai()->ClearCounters();
    return "counters cleared\n";
  }
  if (n == 3 && t[0] == "interface" && t[2] == "shutdown") {
    return orch_->SetInterfaceAdmin(t[1], false) ? "ok\n" : "% Error: unknown interface\n";
  }
  if (n == 4 && t[0] == "interface" && t[2] == "no" && t[3] == "shutdown") {
    return orch_->SetInterfaceAdmin(t[1], true) ? "ok\n" : "% Error: unknown interface\n";
  }
  if (n >= 4 && t[0] == "ip" && t[1] == "route") {
    const auto prefix = Ipv4Prefix::Parse(t[2]);
    std::vector<uint32_t> nhs;
    for (size_t i = 3; i < n; ++i) {
      const auto ip = ParseIpv4(t[i]);
      if (!ip) return "% Error: invalid next hop\n";
      nhs.push_back(*ip);
    }
    if (!prefix) return "% Error: invalid prefix\n";
    orch_->SetRoute(*prefix, RouteSource::kStatic, nhs);
    return "ok\n";
  }
  if (n == 4 && t[0] == "no" && t[1] == "ip" && t[2] == "route") {
    const auto prefix = Ipv4Prefix::Parse(t[3]);
    if (!prefix) return "% Error: invalid prefix\n";
    orch_->DeleteRoute(*prefix, RouteSource::kStatic);
    return "ok\n";
  }
  return "% Error: unknown command (try \"help\")\n";
}

std::string SwitchNode::ShowInterfaces(bool json) const {
  sai::SwitchApi* api = orch_->sai();
  JsonWriter w;
  std::string out =
      "Interface    Admin Oper Mode    Address/VLAN        RX pkts    TX pkts    "
      "RX drop  TX drop\n";
  if (json) w.BeginArray();
  for (const InterfaceConfig& ic : config_.interfaces) {
    if (ic.index >= asic_.num_ports()) continue;
    const sai::ObjectId port = api->GetPortId(ic.index);
    const sai::PortCounters c = api->GetPortCounters(port);
    const bool admin = orch_->PortAdminUp(ic.index);
    const bool oper = api->GetPortOperStatus(port);
    const char* mode =
        ic.address ? "routed" : (ic.mode == sai::PortMode::kTrunk ? "trunk" : "access");
    std::string where =
        ic.address ? ic.address->ToString() : "vlan " + std::to_string(ic.access_vlan);
    if (!ic.address && ic.mode == sai::PortMode::kTrunk) {
      where = std::to_string(ic.trunk_vlans.size()) + " vlans";
    }
    if (json) {
      w.BeginObject()
          .Field("name", ic.name)
          .Field("admin_up", admin)
          .Field("oper_up", oper)
          .Field("mode", mode)
          .Field("address", ic.address ? ic.address->ToString() : "")
          .Field("rx_pkts", c.rx_pkts)
          .Field("rx_bytes", c.rx_bytes)
          .Field("tx_pkts", c.tx_pkts)
          .Field("tx_bytes", c.tx_bytes)
          .Field("rx_drops", c.rx_drops)
          .Field("tx_drops", c.tx_drops)
          .Field("mac_moves", c.mac_moves)
          .EndObject();
      continue;
    }
    char line[200];
    std::snprintf(
        line, sizeof(line), "%-12s %-5s %-4s %-7s %-19s %-10llu %-10llu %-8llu %llu\n",
        ic.name.c_str(), admin ? "up" : "down", oper ? "up" : "down", mode, where.c_str(),
        static_cast<unsigned long long>(c.rx_pkts), static_cast<unsigned long long>(c.tx_pkts),
        static_cast<unsigned long long>(c.rx_drops), static_cast<unsigned long long>(c.tx_drops));
    out += line;
  }
  if (json) return w.EndArray().str() + "\n";
  return out;
}

std::string SwitchNode::ShowMac(bool json) const {
  std::vector<sai::FdbView> entries;
  orch_->sai()->ForEachFdbEntry([&](const sai::FdbView& v) { entries.push_back(v); });
  std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
    return a.vlan != b.vlan ? a.vlan < b.vlan : a.mac < b.mac;
  });
  JsonWriter w;
  std::string out = "VLAN  MAC address        Port          Type\n";
  if (json) w.BeginArray();
  for (const sai::FdbView& e : entries) {
    if (json) {
      w.BeginObject()
          .Field("vlan", e.vlan)
          .Field("mac", e.mac.ToString())
          .Field("port", orch_->PortName(e.port))
          .Field("static", e.is_static)
          .EndObject();
      continue;
    }
    out += Pad(std::to_string(e.vlan), 6) + Pad(e.mac.ToString(), 19) +
           Pad(orch_->PortName(e.port), 14) + (e.is_static ? "static" : "dynamic") + "\n";
  }
  if (json) return w.EndArray().str() + "\n";
  return out + std::to_string(entries.size()) + " entries\n";
}

std::string SwitchNode::ShowArp(bool json) const {
  JsonWriter w;
  std::string out = "Address          MAC address        Interface\n";
  if (json) w.BeginArray();
  for (const NeighborInfo& n : orch_->Neighbors()) {
    const RouterInterfaceInfo* rif = orch_->RifByIndex(n.rif);
    const std::string ifname = rif != nullptr ? rif->name : "?";
    if (json) {
      w.BeginObject()
          .Field("ip", Ipv4ToString(n.ip))
          .Field("mac", n.mac.ToString())
          .Field("interface", ifname)
          .EndObject();
      continue;
    }
    out += Pad(Ipv4ToString(n.ip), 17) + Pad(n.mac.ToString(), 19) + ifname + "\n";
  }
  if (json) return w.EndArray().str() + "\n";
  return out;
}

std::string SwitchNode::ShowRoutes(bool json) const {
  JsonWriter w;
  std::string out =
      "Codes: C connected, S static, B bgp; * offloaded to the ASIC, ! not offloaded\n\n";
  if (json) w.BeginArray();
  for (const RouteInfo& r : orch_->Routes()) {
    if (json) {
      w.BeginObject()
          .Field("prefix", r.prefix.ToString())
          .Field("source", RouteSourceName(r.source))
          .Field("state", RouteStateName(r.state))
          .Field("blackhole", r.blackhole)
          .Field("interface", r.interface);
      w.Key("next_hops").BeginArray();
      for (uint32_t nh : r.next_hops) w.String(Ipv4ToString(nh));
      w.EndArray().EndObject();
      continue;
    }
    const char code = r.source == RouteSource::kConnected ? 'C'
                      : r.source == RouteSource::kStatic  ? 'S'
                                                          : 'B';
    std::string via = r.blackhole ? "blackhole"
                      : !r.interface.empty()
                          ? "directly connected, " + r.interface
                          : "via " + JoinIps(r.next_hops);
    if (r.state != RouteState::kOffloaded) via += std::string(" (") + RouteStateName(r.state) + ")";
    out += std::string(1, code) + (r.state == RouteState::kOffloaded ? "* " : "! ") +
           Pad(r.prefix.ToString(), 20) + via + "\n";
  }
  if (json) return w.EndArray().str() + "\n";
  return out;
}

std::string SwitchNode::ShowBgpSummary(bool json) const {
  if (!speaker_) return json ? "[]\n" : "BGP is not configured\n";
  const TimeUs now = platform_.clock->Now();
  JsonWriter w;
  std::string out = "BGP router identifier " + Ipv4ToString(config_.bgp.router_id) + ", local AS " +
                    std::to_string(config_.bgp.asn) + "\n\n" +
                    "Neighbor         AS          State        Up/Down   PfxRcd PfxSnt MsgRcvd "
                    "MsgSent\n";
  if (json) w.BeginArray();
  for (const bgp::NeighborStatus& s : speaker_->Neighbors()) {
    const bool up = s.state == bgp::SessionState::kEstablished;
    if (json) {
      w.BeginObject()
          .Field("neighbor", Ipv4ToString(s.address))
          .Field("remote_as", s.remote_as)
          .Field("state", bgp::SessionStateName(s.state))
          .Field("uptime_s",
                 up ? static_cast<uint64_t>((now - s.established_since) / kUsPerSec) : 0)
          .Field("prefixes_received", s.prefixes_received)
          .Field("prefixes_sent", s.prefixes_sent)
          .Field("messages_in", s.messages_in)
          .Field("messages_out", s.messages_out)
          .Field("established_count", s.established_count)
          .Field("last_error", s.last_error)
          .EndObject();
      continue;
    }
    char line[200];
    std::snprintf(line, sizeof(line), "%-16s %-11u %-12s %-9s %-6zu %-6zu %-7llu %llu\n",
                  Ipv4ToString(s.address).c_str(), s.remote_as, bgp::SessionStateName(s.state),
                  up ? Uptime(now - s.established_since).c_str() : "never", s.prefixes_received,
                  s.prefixes_sent, static_cast<unsigned long long>(s.messages_in),
                  static_cast<unsigned long long>(s.messages_out));
    out += line;
    if (!up && !s.last_error.empty()) out += "  last error: " + s.last_error + "\n";
  }
  if (json) return w.EndArray().str() + "\n";
  return out;
}

std::string SwitchNode::ShowBgpRoutes(bool json) const {
  if (!speaker_) return json ? "[]\n" : "BGP is not configured\n";
  JsonWriter w;
  std::string out = "Network             Next hop(s)                     Paths  AS path\n";
  if (json) w.BeginArray();
  for (const bgp::RouteView& r : speaker_->Routes()) {
    std::string path;
    for (uint32_t asn : r.as_path) path += std::to_string(asn) + " ";
    path += r.origin == bgp::Origin::kIgp ? "i" : (r.origin == bgp::Origin::kEgp ? "e" : "?");
    if (json) {
      w.BeginObject().Field("prefix", r.prefix.ToString()).Field("local", r.local);
      w.Key("next_hops").BeginArray();
      for (uint32_t nh : r.next_hops) w.String(Ipv4ToString(nh));
      w.EndArray();
      w.Key("as_path").BeginArray();
      for (uint32_t asn : r.as_path) w.Number(asn);
      w.EndArray().Field("paths", r.paths).EndObject();
      continue;
    }
    out += Pad(r.prefix.ToString(), 20) + Pad(r.local ? "local" : JoinIps(r.next_hops), 32) +
           Pad(std::to_string(r.paths), 7) + path + "\n";
  }
  if (json) return w.EndArray().str() + "\n";
  return out;
}

std::string SwitchNode::ShowLldp(bool json) const {
  JsonWriter w;
  std::string out = "Local port   Neighbor            Neighbor port   Chassis id         TTL\n";
  if (json) w.BeginArray();
  for (const auto& [port, n] : lldp_.neighbors()) {
    if (json) {
      w.BeginObject()
          .Field("local_port", orch_->PortName(port))
          .Field("system_name", n.info.system_name)
          .Field("port_id", n.info.port_id)
          .Field("chassis_id", n.info.chassis_id)
          .Field("mgmt_ip", n.info.mgmt_ip != 0 ? Ipv4ToString(n.info.mgmt_ip) : "")
          .Field("ttl", n.info.ttl)
          .EndObject();
      continue;
    }
    out += Pad(orch_->PortName(port), 13) + Pad(n.info.system_name, 20) + Pad(n.info.port_id, 16) +
           Pad(n.info.chassis_id, 19) + std::to_string(n.info.ttl) + "\n";
  }
  if (json) return w.EndArray().str() + "\n";
  return out;
}

std::string SwitchNode::ShowQueues(bool json) const {
  sai::SwitchApi* api = orch_->sai();
  JsonWriter w;
  std::string out =
      "Port         Q  Enq pkts    Deq pkts    Tail drop  WRED drop  ECN marked  Watermark B\n";
  if (json) w.BeginArray();
  for (const InterfaceConfig& ic : config_.interfaces) {
    if (ic.index >= asic_.num_ports()) continue;
    for (uint8_t q = 0; q < kNumQueues; ++q) {
      const QueueCounters c = api->GetQueueCounters(api->GetPortId(ic.index), q);
      if (c.enq_pkts == 0 && c.tail_drops == 0 && c.wred_drops == 0) continue;
      if (json) {
        w.BeginObject()
            .Field("port", ic.name)
            .Field("queue", q)
            .Field("enq_pkts", c.enq_pkts)
            .Field("enq_bytes", c.enq_bytes)
            .Field("deq_pkts", c.deq_pkts)
            .Field("deq_bytes", c.deq_bytes)
            .Field("tail_drops", c.tail_drops)
            .Field("wred_drops", c.wred_drops)
            .Field("ecn_marked", c.ecn_marked)
            .Field("watermark_bytes", c.watermark_bytes)
            .EndObject();
        continue;
      }
      char line[200];
      std::snprintf(line, sizeof(line), "%-12s %-2u %-11llu %-11llu %-10llu %-10llu %-11llu %u\n",
                    ic.name.c_str(), q, static_cast<unsigned long long>(c.enq_pkts),
                    static_cast<unsigned long long>(c.deq_pkts),
                    static_cast<unsigned long long>(c.tail_drops),
                    static_cast<unsigned long long>(c.wred_drops),
                    static_cast<unsigned long long>(c.ecn_marked), c.watermark_bytes);
      out += line;
    }
  }
  if (json) return w.EndArray().str() + "\n";
  return out;
}

std::string SwitchNode::ShowDrops(bool json) const {
  sai::SwitchApi* api = orch_->sai();
  JsonWriter w;
  std::string out = "Drop reason          Packets\n";
  if (json) w.BeginObject();
  for (size_t r = 0; r < sai::kDropReasonCount; ++r) {
    const auto reason = static_cast<sai::DropReason>(r);
    const uint64_t count = api->GetDropCount(reason);
    if (json) {
      w.Field(sai::DropReasonName(reason), count);
    } else if (count > 0) {
      out += Pad(sai::DropReasonName(reason), 21) + std::to_string(count) + "\n";
    }
  }
  if (json) return w.EndObject().str() + "\n";
  return out;
}

std::string SwitchNode::ShowCopp(bool json) const {
  sai::SwitchApi* api = orch_->sai();
  JsonWriter w;
  std::string out = "Trap    Rate (pps)  To CPU      Policed\n";
  if (json) w.BeginArray();
  for (size_t t = 0; t < sai::kTrapTypeCount; ++t) {
    const auto trap = static_cast<sai::TrapType>(t);
    const sai::TrapCounters c = api->GetTrapCounters(trap);
    if (json) {
      w.BeginObject()
          .Field("trap", sai::TrapTypeName(trap))
          .Field("pps", config_.copp.pps[t])
          .Field("to_cpu", c.packets)
          .Field("policed", c.policed)
          .EndObject();
      continue;
    }
    out += Pad(sai::TrapTypeName(trap), 8) + Pad(std::to_string(config_.copp.pps[t]), 12) +
           Pad(std::to_string(c.packets), 12) + std::to_string(c.policed) + "\n";
  }
  if (json) return w.EndArray().str() + "\n";
  return out;
}

std::string SwitchNode::ShowAcl(bool json) const {
  JsonWriter w;
  std::string out = "Rule      TCAM entries  Hits\n";
  if (json) w.BeginArray();
  for (const sai::AclRuleStats& s : orch_->sai()->GetAclStats()) {
    if (json) {
      w.BeginObject()
          .Field("seq", s.seq)
          .Field("tcam_entries", s.tcam_entries)
          .Field("hits", s.hits)
          .EndObject();
      continue;
    }
    out += Pad(std::to_string(s.seq), 10) + Pad(std::to_string(s.tcam_entries), 14) +
           std::to_string(s.hits) + "\n";
  }
  if (json) return w.EndArray().str() + "\n";
  return out;
}

std::string SwitchNode::ShowResources(bool json) const {
  JsonWriter w;
  std::string out = "Resource           Used      Capacity  Use%\n";
  if (json) w.BeginArray();
  for (const sai::ResourceUsage& r : orch_->sai()->GetResources()) {
    const size_t pct = r.capacity != 0 ? r.used * 100 / r.capacity : 0;
    if (json) {
      w.BeginObject()
          .Field("resource", r.name)
          .Field("used", r.used)
          .Field("capacity", r.capacity)
          .EndObject();
      continue;
    }
    out += Pad(r.name, 19) + Pad(std::to_string(r.used), 10) + Pad(std::to_string(r.capacity), 10) +
           std::to_string(pct) + "%\n";
  }
  if (json) return w.EndArray().str() + "\n";
  return out;
}

}  // namespace nanonos
