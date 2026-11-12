#include "sai/recorder.h"

#include <cstdio>

namespace nanonos::sai {
namespace {

const char* PortModeName(PortMode mode) {
  switch (mode) {
    case PortMode::kAccess:
      return "access";
    case PortMode::kTrunk:
      return "trunk";
    case PortMode::kRouted:
      return "routed";
  }
  return "?";
}

const char* RouteActionName(RouteAction action) {
  switch (action) {
    case RouteAction::kForward:
      return "forward";
    case RouteAction::kDrop:
      return "drop";
    case RouteAction::kTrapToCpu:
      return "trap";
  }
  return "?";
}

std::string Num(uint64_t v) { return std::to_string(v); }

}  // namespace

std::string OidString(ObjectId id) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "oid:0x%llx", static_cast<unsigned long long>(id));
  return buf;
}

Status RecordingSwitchApi::Record(char op, const char* object, const std::string& args,
                                  Status status) {
  std::string line(1, op);
  line += '|';
  line += object;
  line += '|';
  line += args;
  line += '|';
  line += StatusName(status);
  sink_(line);
  return status;
}

Status RecordingSwitchApi::SetSwitchMac(const MacAddress& mac) {
  return Record('s', "SWITCH", "mac=" + mac.ToString(), t_->SetSwitchMac(mac));
}

Status RecordingSwitchApi::SetEcmpHashSeed(uint32_t seed) {
  return Record('s', "SWITCH", "ecmp_hash_seed=" + Num(seed), t_->SetEcmpHashSeed(seed));
}

Status RecordingSwitchApi::SetFdbAgingTime(uint32_t seconds) {
  return Record('s', "SWITCH", "fdb_aging=" + Num(seconds), t_->SetFdbAgingTime(seconds));
}

Status RecordingSwitchApi::SetPortAdminState(ObjectId port, bool up) {
  return Record('s', "PORT", OidString(port) + " admin=" + (up ? "up" : "down"),
                t_->SetPortAdminState(port, up));
}

Status RecordingSwitchApi::SetPortMode(ObjectId port, PortMode mode, uint16_t pvid) {
  return Record('s', "PORT", OidString(port) + " mode=" + PortModeName(mode) + " pvid=" + Num(pvid),
                t_->SetPortMode(port, mode, pvid));
}

Status RecordingSwitchApi::SetPortMtu(ObjectId port, uint16_t mtu) {
  return Record('s', "PORT", OidString(port) + " mtu=" + Num(mtu), t_->SetPortMtu(port, mtu));
}

Status RecordingSwitchApi::SetPortMacLimit(ObjectId port, uint32_t max_macs) {
  return Record('s', "PORT", OidString(port) + " mac_limit=" + Num(max_macs),
                t_->SetPortMacLimit(port, max_macs));
}

Status RecordingSwitchApi::SetPortStormControl(ObjectId port, StormType type, uint64_t pps) {
  return Record('s', "PORT",
                OidString(port) + " storm[" + Num(static_cast<uint8_t>(type)) + "]=" + Num(pps),
                t_->SetPortStormControl(port, type, pps));
}

Status RecordingSwitchApi::SetPortScheduler(ObjectId port, const SchedulerConfig& config) {
  std::string args = OidString(port) + " strict_mask=" + Num(config.strict_mask) + " weights=";
  for (int q = 0; q < kNumQueues; ++q) {
    if (q > 0) args += ',';
    args += Num(config.weights[static_cast<size_t>(q)]);
  }
  return Record('s', "SCHEDULER", args, t_->SetPortScheduler(port, config));
}

Status RecordingSwitchApi::SetPortShaper(ObjectId port, uint64_t bits_per_second) {
  return Record('s', "PORT", OidString(port) + " shaper_bps=" + Num(bits_per_second),
                t_->SetPortShaper(port, bits_per_second));
}

Status RecordingSwitchApi::SetQueueWred(ObjectId port, uint8_t queue, const WredProfile& p) {
  return Record('s', "WRED",
                OidString(port) + " queue=" + Num(queue) + " min=" + Num(p.min_bytes) +
                    " max=" + Num(p.max_bytes) + " prob=" + Num(p.max_prob_pct) +
                    " ecn=" + (p.ecn ? "1" : "0"),
                t_->SetQueueWred(port, queue, p));
}

Status RecordingSwitchApi::CreateVlan(uint16_t vid, ObjectId* vlan) {
  const Status s = t_->CreateVlan(vid, vlan);
  return Record('c', "VLAN", "vid=" + Num(vid), s);
}

Status RecordingSwitchApi::RemoveVlan(ObjectId vlan) {
  return Record('r', "VLAN", OidString(vlan), t_->RemoveVlan(vlan));
}

Status RecordingSwitchApi::CreateVlanMember(ObjectId vlan, ObjectId port, bool tagged,
                                            ObjectId* member) {
  const Status s = t_->CreateVlanMember(vlan, port, tagged, member);
  return Record('c', "VLAN_MEMBER",
                OidString(vlan) + " " + OidString(port) + (tagged ? " tagged" : " untagged"), s);
}

Status RecordingSwitchApi::RemoveVlanMember(ObjectId member) {
  return Record('r', "VLAN_MEMBER", OidString(member), t_->RemoveVlanMember(member));
}

Status RecordingSwitchApi::CreateStaticFdbEntry(uint16_t vid, const MacAddress& mac,
                                                ObjectId port) {
  return Record('c', "FDB_ENTRY",
                "vid=" + Num(vid) + " mac=" + mac.ToString() + " " + OidString(port),
                t_->CreateStaticFdbEntry(vid, mac, port));
}

Status RecordingSwitchApi::FlushFdb(ObjectId port) {
  return Record('f', "FDB_ENTRY", OidString(port), t_->FlushFdb(port));
}

Status RecordingSwitchApi::CreateRouterInterface(const RouterInterfaceAttrs& attrs, ObjectId* rif) {
  const Status s = t_->CreateRouterInterface(attrs, rif);
  std::string args = attrs.type == RouterInterfaceType::kPort ? "type=port " + OidString(attrs.port)
                                                              : "type=vlan vid=" + Num(attrs.vlan);
  args += " mtu=" + Num(attrs.mtu);
  return Record('c', "ROUTER_INTERFACE", args, s);
}

Status RecordingSwitchApi::RemoveRouterInterface(ObjectId rif) {
  return Record('r', "ROUTER_INTERFACE", OidString(rif), t_->RemoveRouterInterface(rif));
}

Status RecordingSwitchApi::CreateNeighbor(ObjectId rif, uint32_t ip, const MacAddress& mac) {
  return Record('c', "NEIGHBOR",
                OidString(rif) + " ip=" + Ipv4ToString(ip) + " mac=" + mac.ToString(),
                t_->CreateNeighbor(rif, ip, mac));
}

Status RecordingSwitchApi::RemoveNeighbor(ObjectId rif, uint32_t ip) {
  return Record('r', "NEIGHBOR", OidString(rif) + " ip=" + Ipv4ToString(ip),
                t_->RemoveNeighbor(rif, ip));
}

Status RecordingSwitchApi::CreateNextHop(ObjectId rif, uint32_t ip, ObjectId* next_hop) {
  const Status s = t_->CreateNextHop(rif, ip, next_hop);
  return Record('c', "NEXT_HOP", OidString(rif) + " ip=" + Ipv4ToString(ip), s);
}

Status RecordingSwitchApi::RemoveNextHop(ObjectId next_hop) {
  return Record('r', "NEXT_HOP", OidString(next_hop), t_->RemoveNextHop(next_hop));
}

Status RecordingSwitchApi::CreateNextHopGroup(ObjectId* group) {
  const Status s = t_->CreateNextHopGroup(group);
  return Record('c', "NEXT_HOP_GROUP", s == Status::kOk ? OidString(*group) : "", s);
}

Status RecordingSwitchApi::RemoveNextHopGroup(ObjectId group) {
  return Record('r', "NEXT_HOP_GROUP", OidString(group), t_->RemoveNextHopGroup(group));
}

Status RecordingSwitchApi::AddNextHopGroupMember(ObjectId group, ObjectId next_hop) {
  return Record('c', "NEXT_HOP_GROUP_MEMBER", OidString(group) + " " + OidString(next_hop),
                t_->AddNextHopGroupMember(group, next_hop));
}

Status RecordingSwitchApi::RemoveNextHopGroupMember(ObjectId group, ObjectId next_hop) {
  return Record('r', "NEXT_HOP_GROUP_MEMBER", OidString(group) + " " + OidString(next_hop),
                t_->RemoveNextHopGroupMember(group, next_hop));
}

Status RecordingSwitchApi::CreateRoute(const Ipv4Prefix& prefix, const RouteAttrs& attrs) {
  return Record('c', "ROUTE",
                prefix.ToString() + " action=" + RouteActionName(attrs.action) + " " +
                    OidString(attrs.next_hop),
                t_->CreateRoute(prefix, attrs));
}

Status RecordingSwitchApi::SetRoute(const Ipv4Prefix& prefix, const RouteAttrs& attrs) {
  return Record('s', "ROUTE",
                prefix.ToString() + " action=" + RouteActionName(attrs.action) + " " +
                    OidString(attrs.next_hop),
                t_->SetRoute(prefix, attrs));
}

Status RecordingSwitchApi::RemoveRoute(const Ipv4Prefix& prefix) {
  return Record('r', "ROUTE", prefix.ToString(), t_->RemoveRoute(prefix));
}

Status RecordingSwitchApi::CreateAclEntry(const AclRule& rule, ObjectId* entry) {
  const Status s = t_->CreateAclEntry(rule, entry);
  return Record('c', "ACL_ENTRY", "seq=" + Num(rule.seq), s);
}

Status RecordingSwitchApi::RemoveAclEntry(ObjectId entry) {
  return Record('r', "ACL_ENTRY", OidString(entry), t_->RemoveAclEntry(entry));
}

Status RecordingSwitchApi::SetDscpToTc(uint8_t dscp, uint8_t tc) {
  return Record('s', "QOS_MAP", "dscp=" + Num(dscp) + " tc=" + Num(tc), t_->SetDscpToTc(dscp, tc));
}

Status RecordingSwitchApi::SetTrapPolicer(TrapType trap, uint64_t pps, uint64_t burst) {
  return Record('s', "COPP",
                std::string(TrapTypeName(trap)) + " pps=" + Num(pps) + " burst=" + Num(burst),
                t_->SetTrapPolicer(trap, pps, burst));
}

}  // namespace nanonos::sai
