#include "orch/orchagent.h"

#include <algorithm>
#include <set>

#include "common/hash.h"
#include "common/logging.h"

namespace nanonos {

const char* RouteSourceName(RouteSource source) {
  switch (source) {
    case RouteSource::kConnected:
      return "connected";
    case RouteSource::kStatic:
      return "static";
    case RouteSource::kBgp:
      return "bgp";
  }
  return "?";
}

uint8_t AdminDistance(RouteSource source) {
  switch (source) {
    case RouteSource::kConnected:
      return 0;
    case RouteSource::kStatic:
      return 1;
    case RouteSource::kBgp:
      return 20;  // eBGP
  }
  return 255;
}

const char* RouteStateName(RouteState state) {
  switch (state) {
    case RouteState::kOffloaded:
      return "offloaded";
    case RouteState::kUnresolved:
      return "unresolved";
    case RouteState::kFailed:
      return "failed";
  }
  return "?";
}

Orchagent::Orchagent(sai::SwitchApi* sai, const Clock* clock)
    : sai_(sai),
      clock_(clock),
      port_admin_(sai->GetPortCount(), false),
      port_oper_(sai->GetPortCount(), true) {
  for (uint16_t i = 0; i < sai->GetPortCount(); ++i) {
    port_names_.push_back("Ethernet" + std::to_string(i));
  }
}

void Orchagent::Error(std::vector<std::string>* errors, std::string message) const {
  LOG_ERROR("%s", message.c_str());
  if (errors != nullptr) errors->push_back(std::move(message));
}

bool Orchagent::Apply(const SwitchConfig& config, std::vector<std::string>* errors) {
  config_ = config;
  const size_t errors_before = errors != nullptr ? errors->size() : 0;
  const auto check = [&](Status s, const std::string& what) {
    if (s != Status::kOk) Error(errors, what + ": " + StatusName(s));
  };

  // Switch-wide attributes. The MAC and ECMP seed default to values derived
  // from the hostname so every switch in a fabric gets distinct ones (distinct
  // hash seeds avoid ECMP polarization between tiers).
  const uint32_t host_hash =
      Crc32(reinterpret_cast<const uint8_t*>(config.hostname.data()), config.hostname.size());
  switch_mac_ = config.switch_mac.value_or(
      MacAddress::FromU64(0x020000000000ULL | (uint64_t{host_hash & 0xffffff} << 8)));
  check(sai_->SetSwitchMac(switch_mac_), "switch MAC");
  check(sai_->SetEcmpHashSeed(config.ecmp_hash_seed != 0 ? config.ecmp_hash_seed : host_hash),
        "ECMP hash seed");
  check(sai_->SetFdbAgingTime(config.fdb_aging_s), "FDB aging");

  // VLANs: declared ones plus every VLAN an interface refers to.
  std::set<uint16_t> vlans(config.vlans.begin(), config.vlans.end());
  for (const InterfaceConfig& ic : config.interfaces) {
    if (ic.address) continue;
    if (ic.mode == sai::PortMode::kAccess && ic.access_vlan != 0) vlans.insert(ic.access_vlan);
    if (ic.mode == sai::PortMode::kTrunk) {
      vlans.insert(ic.trunk_vlans.begin(), ic.trunk_vlans.end());
      if (ic.native_vlan != 0) vlans.insert(ic.native_vlan);
    }
  }
  for (const SviConfig& svi : config.svis) vlans.insert(svi.vlan);
  for (uint16_t vid : vlans) {
    sai::ObjectId oid = sai::kNullObjectId;
    check(sai_->CreateVlan(vid, &oid), "vlan " + std::to_string(vid));
  }

  // Ports.
  for (const InterfaceConfig& ic : config.interfaces) {
    if (ic.index >= sai_->GetPortCount()) {
      Error(errors,
            ic.name + ": the switch has only " + std::to_string(sai_->GetPortCount()) + " ports");
      continue;
    }
    const sai::ObjectId port = sai_->GetPortId(ic.index);
    port_names_[ic.index] = ic.name;
    const bool routed = ic.address.has_value();
    const sai::PortMode mode = routed ? sai::PortMode::kRouted : ic.mode;
    const uint16_t pvid = mode == sai::PortMode::kAccess  ? ic.access_vlan
                          : mode == sai::PortMode::kTrunk ? ic.native_vlan
                                                          : 0;
    check(sai_->SetPortMode(port, mode, pvid), ic.name + " mode");
    check(sai_->SetPortMtu(port, ic.mtu), ic.name + " mtu");
    if (ic.max_macs != 0)
      check(sai_->SetPortMacLimit(port, ic.max_macs), ic.name + " port-security");
    for (size_t s = 0; s < sai::kStormTypeCount; ++s) {
      if (ic.storm_pps[s] != 0) {
        check(sai_->SetPortStormControl(port, static_cast<sai::StormType>(s), ic.storm_pps[s]),
              ic.name + " storm-control");
      }
    }
    if (ic.scheduler_set) check(sai_->SetPortScheduler(port, ic.scheduler), ic.name + " scheduler");
    if (ic.shaper_bps != 0) check(sai_->SetPortShaper(port, ic.shaper_bps), ic.name + " shaper");
    for (const auto& [queue, profile] : ic.wred) {
      check(sai_->SetQueueWred(port, queue, profile), ic.name + " wred");
    }
    if (mode == sai::PortMode::kAccess && ic.access_vlan != 0) {
      sai::ObjectId member = sai::kNullObjectId;
      check(sai_->CreateVlanMember(sai::MakeObjectId(sai::ObjectType::kVlan, ic.access_vlan), port,
                                   false, &member),
            ic.name + " vlan member");
    } else if (mode == sai::PortMode::kTrunk) {
      std::set<uint16_t> tagged(ic.trunk_vlans.begin(), ic.trunk_vlans.end());
      if (ic.native_vlan != 0) tagged.erase(ic.native_vlan);
      for (uint16_t vid : tagged) {
        sai::ObjectId member = sai::kNullObjectId;
        check(sai_->CreateVlanMember(sai::MakeObjectId(sai::ObjectType::kVlan, vid), port, true,
                                     &member),
              ic.name + " vlan member");
      }
      if (ic.native_vlan != 0) {
        sai::ObjectId member = sai::kNullObjectId;
        check(sai_->CreateVlanMember(sai::MakeObjectId(sai::ObjectType::kVlan, ic.native_vlan),
                                     port, false, &member),
              ic.name + " native vlan");
      }
    }
    port_admin_[ic.index] = !ic.shutdown;
    check(sai_->SetPortAdminState(port, !ic.shutdown), ic.name + " admin state");
  }

  // Router interfaces: routed ports and SVIs.
  const auto add_rif = [&](const std::string& name, const sai::RouterInterfaceAttrs& attrs,
                           const InterfaceAddress& address) {
    sai::ObjectId oid = sai::kNullObjectId;
    const Status s = sai_->CreateRouterInterface(attrs, &oid);
    if (s != Status::kOk) {
      Error(errors, name + " router interface: " + StatusName(s));
      return;
    }
    RouterInterfaceInfo info;
    info.name = name;
    info.oid = oid;
    info.index = static_cast<int>(sai::IndexOf(oid));
    info.address = address;
    info.mac = switch_mac_;
    info.is_svi = attrs.type == sai::RouterInterfaceType::kVlan;
    info.port = static_cast<uint16_t>(sai::IndexOf(attrs.port));
    info.vlan = attrs.vlan;
    rifs_.push_back(info);
  };
  for (const InterfaceConfig& ic : config.interfaces) {
    if (!ic.address || ic.index >= sai_->GetPortCount()) continue;
    sai::RouterInterfaceAttrs attrs;
    attrs.type = sai::RouterInterfaceType::kPort;
    attrs.port = sai_->GetPortId(ic.index);
    attrs.mtu = ic.mtu;
    add_rif(ic.name, attrs, *ic.address);
  }
  for (const SviConfig& svi : config.svis) {
    if (!svi.address) continue;
    sai::RouterInterfaceAttrs attrs;
    attrs.type = sai::RouterInterfaceType::kVlan;
    attrs.vlan = svi.vlan;
    attrs.mtu = svi.mtu;
    add_rif("Vlan" + std::to_string(svi.vlan), attrs, *svi.address);
  }
  UpdateRifStates();
  for (const RouterInterfaceInfo& rif : rifs_) {
    // ip2me: the interface address traps to the CPU (a /32 route with action trap).
    check(sai_->CreateRoute(Ipv4Prefix::Make(rif.address.ip, 32),
                            sai::RouteAttrs{sai::RouteAction::kTrapToCpu, rif.oid}),
          rif.name + " local address");
    RouteEntry& e = routes_[rif.address.Subnet()];
    e.candidates[RouteSource::kConnected] = Candidate{{}, false, rif.index};
    Program(rif.address.Subnet(), e);
  }

  for (const StaticRouteConfig& r : config.static_routes) {
    SetRoute(r.prefix, RouteSource::kStatic, r.next_hops, r.blackhole);
  }
  for (const AclRule& rule : config.acl_rules) {
    sai::ObjectId entry = sai::kNullObjectId;
    check(sai_->CreateAclEntry(rule, &entry), "acl rule " + std::to_string(rule.seq));
  }
  for (const auto& [dscp, tc] : config.dscp_to_tc) check(sai_->SetDscpToTc(dscp, tc), "qos map");
  for (size_t t = 0; t < sai::kTrapTypeCount; ++t) {
    check(sai_->SetTrapPolicer(static_cast<sai::TrapType>(t), config.copp.pps[t],
                               config.copp.burst[t]),
          std::string("copp ") + sai::TrapTypeName(static_cast<sai::TrapType>(t)));
  }
  return errors == nullptr || errors->size() == errors_before;
}

// ---------------------------------------------------------------------------
// Interfaces and neighbors
// ---------------------------------------------------------------------------

RouterInterfaceInfo* Orchagent::MutableRif(int index) {
  for (RouterInterfaceInfo& r : rifs_) {
    if (r.index == index) return &r;
  }
  return nullptr;
}

const RouterInterfaceInfo* Orchagent::RifByIndex(int index) const {
  return const_cast<Orchagent*>(this)->MutableRif(index);
}

const RouterInterfaceInfo* Orchagent::RifByName(std::string_view name) const {
  for (const RouterInterfaceInfo& r : rifs_) {
    if (r.name == name) return &r;
  }
  return nullptr;
}

const RouterInterfaceInfo* Orchagent::RifForAddress(uint32_t ip) const {
  for (const RouterInterfaceInfo& r : rifs_) {
    if (r.up && r.address.Subnet().Contains(ip)) return &r;
  }
  return nullptr;
}

bool Orchagent::IsLocalAddress(uint32_t ip) const {
  for (const RouterInterfaceInfo& r : rifs_) {
    if (r.address.ip == ip) return true;
  }
  return false;
}

int Orchagent::PortByName(std::string_view name) const {
  for (size_t i = 0; i < port_names_.size(); ++i) {
    if (port_names_[i] == name) return static_cast<int>(i);
  }
  return -1;
}

std::string Orchagent::PortName(uint16_t port) const {
  return port < port_names_.size() ? port_names_[port] : "?";
}

void Orchagent::UpdateRifStates() {
  for (RouterInterfaceInfo& r : rifs_) {
    const bool up = r.is_svi || (port_admin_[r.port] && port_oper_[r.port]);
    if (r.up == up) continue;
    r.up = up;
    LOG_INFO("%s is %s", r.name.c_str(), up ? "up" : "down");
    if (!up) {
      // Neighbors behind a dead link are stale; drop them with the link.
      for (auto it = neighbors_.begin(); it != neighbors_.end();) {
        if (it->second.rif == r.index) {
          sai_->RemoveNeighbor(r.oid, it->first);
          it = neighbors_.erase(it);
        } else {
          ++it;
        }
      }
    }
  }
}

void Orchagent::OnPortOperStatus(uint16_t port, bool up) {
  if (port >= port_oper_.size() || port_oper_[port] == up) return;
  port_oper_[port] = up;
  UpdateRifStates();
  ReevaluateAll();
}

bool Orchagent::SetInterfaceAdmin(std::string_view name, bool up) {
  const int port = PortByName(name);
  if (port < 0) return false;
  port_admin_[static_cast<size_t>(port)] = up;
  sai_->SetPortAdminState(sai_->GetPortId(static_cast<uint16_t>(port)), up);
  UpdateRifStates();
  ReevaluateAll();
  return true;
}

void Orchagent::OnArpLearned(int rif_index, uint32_t ip, const MacAddress& mac) {
  const RouterInterfaceInfo* rif = RifByIndex(rif_index);
  if (rif == nullptr || !rif->up || !rif->address.Subnet().Contains(ip) || ip == rif->address.ip ||
      mac.IsMulticast() || mac.IsZero()) {
    return;
  }
  const auto it = neighbors_.find(ip);
  if (it != neighbors_.end() && it->second.mac == mac && it->second.rif == rif_index) return;
  const Status s = sai_->CreateNeighbor(rif->oid, ip, mac);
  if (s != Status::kOk) {
    LOG_WARN("neighbor %s on %s: %s", Ipv4ToString(ip).c_str(), rif->name.c_str(), StatusName(s));
    return;
  }
  LOG_INFO("neighbor %s is %s on %s", Ipv4ToString(ip).c_str(), mac.ToString().c_str(),
           rif->name.c_str());
  neighbors_[ip] = NeighborInfo{ip, mac, rif_index};
}

std::vector<NeighborInfo> Orchagent::Neighbors() const {
  std::vector<NeighborInfo> out;
  for (const auto& [ip, n] : neighbors_) out.push_back(n);
  return out;
}

std::vector<std::pair<int, uint32_t>> Orchagent::UnresolvedNextHops() const {
  std::vector<std::pair<int, uint32_t>> out;
  for (const auto& [key, ref] : next_hops_) {
    if (neighbors_.find(key.ip) == neighbors_.end()) out.emplace_back(key.rif, key.ip);
  }
  return out;
}

// ---------------------------------------------------------------------------
// RouteOrch
// ---------------------------------------------------------------------------

void Orchagent::SetRoute(const Ipv4Prefix& raw, RouteSource source, std::vector<uint32_t> next_hops,
                         bool blackhole) {
  const Ipv4Prefix prefix = Ipv4Prefix::Make(raw.addr, raw.len);
  std::sort(next_hops.begin(), next_hops.end());
  next_hops.erase(std::unique(next_hops.begin(), next_hops.end()), next_hops.end());
  RouteEntry& e = routes_[prefix];
  Candidate& c = e.candidates[source];
  c.next_hops = std::move(next_hops);
  c.blackhole = blackhole;
  c.connected_rif = -1;
  Program(prefix, e);
}

void Orchagent::DeleteRoute(const Ipv4Prefix& raw, RouteSource source) {
  const Ipv4Prefix prefix = Ipv4Prefix::Make(raw.addr, raw.len);
  const auto it = routes_.find(prefix);
  if (it == routes_.end()) return;
  it->second.candidates.erase(source);
  Program(prefix, it->second);
  if (it->second.candidates.empty() && !it->second.installed) routes_.erase(it);
}

void Orchagent::ReevaluateAll() {
  for (auto& [prefix, entry] : routes_) Program(prefix, entry);
}

sai::ObjectId Orchagent::AcquireNextHop(const NhKey& key) {
  NhRef& ref = next_hops_[key];
  if (ref.refs == 0) {
    const RouterInterfaceInfo* rif = RifByIndex(key.rif);
    const Status s =
        rif == nullptr ? Status::kNotFound : sai_->CreateNextHop(rif->oid, key.ip, &ref.oid);
    if (s != Status::kOk) {
      next_hops_.erase(key);
      return sai::kNullObjectId;
    }
  }
  ++ref.refs;
  return ref.oid;
}

void Orchagent::ReleaseNextHop(const NhKey& key) {
  const auto it = next_hops_.find(key);
  if (it == next_hops_.end()) return;
  if (--it->second.refs == 0) {
    sai_->RemoveNextHop(it->second.oid);
    next_hops_.erase(it);
  }
}

// Takes one reference on the next hop (single key) or on the ECMP group
// (several keys), creating SAI objects on first use.
bool Orchagent::Acquire(const std::vector<NhKey>& keys, sai::ObjectId* target) {
  if (keys.size() == 1) {
    *target = AcquireNextHop(keys[0]);
    return *target != sai::kNullObjectId;
  }
  GroupRef& g = groups_[keys];
  if (g.refs == 0) {
    if (sai_->CreateNextHopGroup(&g.oid) != Status::kOk) {
      groups_.erase(keys);
      return false;
    }
    for (const NhKey& k : keys) {
      const sai::ObjectId nh = AcquireNextHop(k);
      if (nh == sai::kNullObjectId || sai_->AddNextHopGroupMember(g.oid, nh) != Status::kOk) {
        LOG_WARN("could not add next hop %s to an ECMP group", Ipv4ToString(k.ip).c_str());
      }
    }
  }
  ++g.refs;
  *target = g.oid;
  return true;
}

void Orchagent::ReleaseTarget(const std::vector<NhKey>& keys) {
  if (keys.empty()) return;
  if (keys.size() == 1) {
    ReleaseNextHop(keys[0]);
    return;
  }
  const auto it = groups_.find(keys);
  if (it == groups_.end() || --it->second.refs > 0) return;
  for (const NhKey& k : keys) {
    const auto nh = next_hops_.find(k);
    if (nh != next_hops_.end()) sai_->RemoveNextHopGroupMember(it->second.oid, nh->second.oid);
    ReleaseNextHop(k);
  }
  sai_->RemoveNextHopGroup(it->second.oid);
  groups_.erase(it);
}

void Orchagent::Uninstall(const Ipv4Prefix& prefix, RouteEntry& entry) {
  if (!entry.installed) return;
  sai_->RemoveRoute(prefix);
  ReleaseTarget(entry.installed_nhs);
  entry.installed = false;
  entry.installed_nhs.clear();
}

void Orchagent::Program(const Ipv4Prefix& prefix, RouteEntry& entry) {
  if (entry.candidates.empty()) {
    Uninstall(prefix, entry);
    return;
  }
  // Lowest admin distance wins (std::map orders sources by distance).
  const auto best = std::min_element(
      entry.candidates.begin(), entry.candidates.end(),
      [](const auto& a, const auto& b) { return AdminDistance(a.first) < AdminDistance(b.first); });
  const RouteSource source = best->first;
  const Candidate& c = best->second;

  sai::RouteAttrs attrs;
  std::vector<NhKey> keys;
  if (c.blackhole) {
    attrs.action = sai::RouteAction::kDrop;
  } else if (c.connected_rif >= 0) {
    const RouterInterfaceInfo* rif = RifByIndex(c.connected_rif);
    if (rif == nullptr || !rif->up) {
      Uninstall(prefix, entry);
      entry.state = RouteState::kUnresolved;
      return;
    }
    attrs.next_hop = rif->oid;
  } else {
    for (uint32_t ip : c.next_hops) {
      if (const RouterInterfaceInfo* rif = RifForAddress(ip)) keys.push_back(NhKey{rif->index, ip});
    }
    std::sort(keys.begin(), keys.end());
    if (keys.empty()) {
      Uninstall(prefix, entry);
      entry.state = RouteState::kUnresolved;
      return;
    }
  }

  const bool same_target = entry.installed && entry.installed_source == source &&
                           entry.installed_attrs.action == attrs.action &&
                           entry.installed_nhs == keys &&
                           (!keys.empty() || entry.installed_attrs.next_hop == attrs.next_hop);
  if (same_target && entry.state == RouteState::kOffloaded) return;

  if (!keys.empty() && !Acquire(keys, &attrs.next_hop)) {
    entry.state = RouteState::kFailed;
    return;
  }
  // Make before break: point the route at the new target, then release the old one.
  const Status s =
      entry.installed ? sai_->SetRoute(prefix, attrs) : sai_->CreateRoute(prefix, attrs);
  if (s != Status::kOk) {
    ReleaseTarget(keys);
    entry.state = RouteState::kFailed;
    LOG_WARN("route %s not offloaded: %s", prefix.ToString().c_str(), StatusName(s));
    return;
  }
  if (entry.installed) ReleaseTarget(entry.installed_nhs);
  entry.installed = true;
  entry.installed_source = source;
  entry.installed_attrs = attrs;
  entry.installed_nhs = std::move(keys);
  entry.state = RouteState::kOffloaded;
}

void Orchagent::Tick() {
  for (auto& [prefix, entry] : routes_) {
    if (entry.state == RouteState::kFailed) Program(prefix, entry);
  }
  // Critical resource monitoring: warn once when a table crosses 85%, re-arm below 70%.
  for (const sai::ResourceUsage& r : sai_->GetResources()) {
    if (r.capacity == 0) continue;
    const size_t pct = r.used * 100 / r.capacity;
    bool& warned = crm_warned_[r.name];
    if (!warned && pct >= 85) {
      warned = true;
      LOG_WARN("CRM: %s at %zu%% (%zu of %zu)", r.name, pct, r.used, r.capacity);
    } else if (warned && pct < 70) {
      warned = false;
    }
  }
}

std::vector<RouteInfo> Orchagent::Routes() const {
  std::vector<RouteInfo> out;
  for (const auto& [prefix, entry] : routes_) {
    if (entry.candidates.empty()) continue;
    const auto best = std::min_element(entry.candidates.begin(), entry.candidates.end(),
                                       [](const auto& a, const auto& b) {
                                         return AdminDistance(a.first) < AdminDistance(b.first);
                                       });
    RouteInfo info;
    info.prefix = prefix;
    info.source = best->first;
    info.blackhole = best->second.blackhole;
    if (best->second.connected_rif >= 0) {
      const RouterInterfaceInfo* rif = RifByIndex(best->second.connected_rif);
      info.interface = rif != nullptr ? rif->name : "?";
    }
    if (entry.installed) {
      for (const NhKey& k : entry.installed_nhs) info.next_hops.push_back(k.ip);
    } else {
      info.next_hops = best->second.next_hops;
    }
    info.state = entry.state;
    out.push_back(std::move(info));
  }
  return out;
}

}  // namespace nanonos
