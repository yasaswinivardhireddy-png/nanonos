// Switch configuration: a line-oriented, network-OS style language.
//
//   hostname leaf1
//   vlan 10
//   interface Ethernet0
//     port veth0                      <- Linux netdev bound by the daemon
//     switchport access vlan 10
//   interface Ethernet4
//     ip address 10.0.0.1/31          <- routed port
//   interface Vlan10
//     ip address 10.1.1.1/24          <- SVI
//   ip route 0.0.0.0/0 10.0.0.0
//   router bgp 65001
//     neighbor 10.0.0.0 remote-as 65100
//
// Lines in column 0 are top-level commands; indented lines belong to the
// block opened by the last "interface", "router bgp", "access-list" or "lldp".
// "!" and "#" start comments.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "asic/acl.h"
#include "asic/qos.h"
#include "common/types.h"
#include "sai/sai.h"

namespace nanonos {

struct InterfaceConfig {
  std::string name;  // EthernetN
  uint16_t index = 0;
  std::string netdev;
  std::string description;
  bool shutdown = false;
  uint16_t mtu = 1500;
  sai::PortMode mode = sai::PortMode::kAccess;
  uint16_t access_vlan = 0;  // 0 = no VLAN
  std::vector<uint16_t> trunk_vlans;
  uint16_t native_vlan = 0;                 // untagged VLAN on a trunk, 0 = none
  std::optional<InterfaceAddress> address;  // set for routed ports
  std::array<uint64_t, sai::kStormTypeCount> storm_pps{};
  uint32_t max_macs = 0;
  bool scheduler_set = false;
  SchedulerConfig scheduler;
  uint64_t shaper_bps = 0;
  std::vector<std::pair<uint8_t, WredProfile>> wred;
};

struct SviConfig {
  uint16_t vlan = 0;
  std::optional<InterfaceAddress> address;
  uint16_t mtu = 1500;
};

struct StaticRouteConfig {
  Ipv4Prefix prefix;
  std::vector<uint32_t> next_hops;
  bool blackhole = false;
};

struct BgpNeighborConfig {
  uint32_t address = 0;
  uint32_t remote_as = 0;
  std::string description;
  std::string password;       // TCP-MD5 (RFC 2385)
  int ttl_security_hops = 0;  // GTSM (RFC 5082); 0 = off
  bool passive = false;
  bool shutdown = false;
};

struct BgpConfig {
  bool enabled = false;
  uint32_t asn = 0;
  uint32_t router_id = 0;
  uint16_t keepalive_s = 30;
  uint16_t hold_s = 90;
  uint16_t connect_retry_s = 5;
  uint16_t max_paths = 1;
  std::vector<Ipv4Prefix> networks;
  std::vector<BgpNeighborConfig> neighbors;
};

struct LldpConfig {
  bool enabled = true;
  uint16_t tx_interval_s = 30;
  uint16_t hold_multiplier = 4;
};

struct CoppConfig {
  // Packets per second per trap group, indexed by sai::TrapType.
  std::array<uint64_t, sai::kTrapTypeCount> pps{100, 600, 2000, 100, 1000};
  std::array<uint64_t, sai::kTrapTypeCount> burst{100, 600, 2000, 100, 1000};
};

struct SwitchConfig {
  std::string hostname = "nanonos";
  std::optional<MacAddress> switch_mac;
  uint32_t ecmp_hash_seed = 0;  // 0 = derived from the hostname
  uint32_t fdb_aging_s = 300;
  std::vector<uint16_t> vlans;
  std::vector<InterfaceConfig> interfaces;
  std::vector<SviConfig> svis;
  std::vector<StaticRouteConfig> static_routes;
  std::vector<AclRule> acl_rules;
  std::vector<std::pair<uint8_t, uint8_t>> dscp_to_tc;
  CoppConfig copp;
  LldpConfig lldp;
  BgpConfig bgp;

  const InterfaceConfig* FindInterface(std::string_view name) const;
};

struct ConfigError {
  int line = 0;
  std::string message;
};

std::optional<SwitchConfig> ParseConfig(std::string_view text, ConfigError* error);

// Splits on spaces and tabs.
std::vector<std::string_view> Tokenize(std::string_view line);

}  // namespace nanonos
