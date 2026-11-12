#include "sai/sai.h"

namespace nanonos::sai {

const char* TrapTypeName(TrapType trap) {
  switch (trap) {
    case TrapType::kLldp:
      return "lldp";
    case TrapType::kArp:
      return "arp";
    case TrapType::kBgp:
      return "bgp";
    case TrapType::kIcmpToMe:
      return "icmp";
    case TrapType::kIpToMe:
      return "ip2me";
    case TrapType::kCount:
      break;
  }
  return "?";
}

const char* DropReasonName(DropReason reason) {
  static constexpr const char* kNames[] = {
      "port_down",       "egress_port_down", "oversize",          "malformed",      "ip_checksum",
      "src_mac_invalid", "reserved_mac",     "vlan_filter",       "acl_deny",       "port_security",
      "storm_control",   "same_interface",   "l2_on_routed_port", "unsupported_l3", "ttl_expired",
      "no_route",        "blackhole",        "neighbor_miss",     "mtu_exceeded",   "copp_policer",
      "tail_drop",       "wred_drop",        "no_buffer",
  };
  static_assert(sizeof(kNames) / sizeof(kNames[0]) == kDropReasonCount);
  const size_t i = static_cast<size_t>(reason);
  return i < kDropReasonCount ? kNames[i] : "?";
}

}  // namespace nanonos::sai
