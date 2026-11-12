// Orchestration agent: turns configuration and routing state into SAI calls,
// the role SONiC's orchagent plays between the databases and syncd.
//
//  * creates ports, VLANs, router interfaces, ACLs, QoS and CoPP in dependency order
//  * RouteOrch: chooses between route sources by admin distance, resolves next
//    hops to router interfaces, shares ref-counted next-hop and ECMP-group
//    objects between routes, programs make-before-break, and keeps routes the
//    ASIC rejected (TABLE_FULL) for retry instead of losing them
//  * NeighOrch: installs neighbors learned from ARP and flushes them on link down
#pragma once

#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/clock.h"
#include "orch/config.h"
#include "sai/sai.h"

namespace nanonos {

enum class RouteSource : uint8_t { kConnected, kStatic, kBgp };
const char* RouteSourceName(RouteSource source);
uint8_t AdminDistance(RouteSource source);

enum class RouteState : uint8_t { kOffloaded, kUnresolved, kFailed };
const char* RouteStateName(RouteState state);

struct RouterInterfaceInfo {
  std::string name;
  sai::ObjectId oid = sai::kNullObjectId;
  int index = -1;  // sai::IndexOf(oid); also the rif index in CpuPacket
  InterfaceAddress address;
  MacAddress mac;
  bool is_svi = false;
  uint16_t port = 0;  // routed port index
  uint16_t vlan = 0;  // SVI VLAN
  bool up = true;
};

struct NeighborInfo {
  uint32_t ip = 0;
  MacAddress mac;
  int rif = -1;
};

struct RouteInfo {
  Ipv4Prefix prefix;
  RouteSource source = RouteSource::kStatic;
  std::vector<uint32_t> next_hops;
  std::string interface;  // connected routes
  bool blackhole = false;
  RouteState state = RouteState::kUnresolved;
};

class Orchagent {
 public:
  explicit Orchagent(sai::SwitchApi* sai);

  bool Apply(const SwitchConfig& config, std::vector<std::string>* errors);

  void OnPortOperStatus(uint16_t port, bool up);
  bool SetInterfaceAdmin(std::string_view name, bool up);
  void OnArpLearned(int rif_index, uint32_t ip, const MacAddress& mac);

  void SetRoute(const Ipv4Prefix& prefix, RouteSource source, std::vector<uint32_t> next_hops,
                bool blackhole = false);
  void DeleteRoute(const Ipv4Prefix& prefix, RouteSource source);

  // Retries routes the ASIC rejected and logs CRM threshold crossings.
  void Tick();

  sai::SwitchApi* sai() const { return sai_; }
  const SwitchConfig& config() const { return config_; }
  const MacAddress& switch_mac() const { return switch_mac_; }
  const std::vector<RouterInterfaceInfo>& rifs() const { return rifs_; }
  const RouterInterfaceInfo* RifByIndex(int index) const;
  const RouterInterfaceInfo* RifByName(std::string_view name) const;
  // The up router interface whose subnet contains `ip`.
  const RouterInterfaceInfo* RifForAddress(uint32_t ip) const;
  bool IsLocalAddress(uint32_t ip) const;
  int PortByName(std::string_view name) const;
  std::string PortName(uint16_t port) const;
  bool PortAdminUp(uint16_t port) const { return port < port_admin_.size() && port_admin_[port]; }
  std::vector<NeighborInfo> Neighbors() const;
  std::vector<RouteInfo> Routes() const;
  // Next hops in use whose MAC is unknown; the control plane should ARP for them.
  std::vector<std::pair<int, uint32_t>> UnresolvedNextHops() const;

 private:
  struct NhKey {
    int rif;
    uint32_t ip;
    friend auto operator<=>(const NhKey&, const NhKey&) = default;
  };
  struct Candidate {
    std::vector<uint32_t> next_hops;
    bool blackhole = false;
    int connected_rif = -1;
  };
  struct RouteEntry {
    std::map<RouteSource, Candidate> candidates;
    bool installed = false;
    RouteSource installed_source = RouteSource::kStatic;
    sai::RouteAttrs installed_attrs;
    std::vector<NhKey> installed_nhs;
    RouteState state = RouteState::kUnresolved;
  };
  struct NhRef {
    sai::ObjectId oid = sai::kNullObjectId;
    uint32_t refs = 0;
  };
  struct GroupRef {
    sai::ObjectId oid = sai::kNullObjectId;
    uint32_t refs = 0;
  };

  void Program(const Ipv4Prefix& prefix, RouteEntry& entry);
  void Uninstall(const Ipv4Prefix& prefix, RouteEntry& entry);
  void ReleaseTarget(const std::vector<NhKey>& keys);
  bool Acquire(const std::vector<NhKey>& keys, sai::ObjectId* target);
  sai::ObjectId AcquireNextHop(const NhKey& key);
  void ReleaseNextHop(const NhKey& key);
  void ReevaluateAll();
  void UpdateRifStates();
  RouterInterfaceInfo* MutableRif(int index);
  void Error(std::vector<std::string>* errors, std::string message) const;

  sai::SwitchApi* sai_;
  SwitchConfig config_;
  MacAddress switch_mac_;
  std::vector<bool> port_admin_;
  std::vector<bool> port_oper_;
  std::vector<std::string> port_names_;
  std::vector<RouterInterfaceInfo> rifs_;
  std::map<uint32_t, NeighborInfo> neighbors_;
  std::map<Ipv4Prefix, RouteEntry> routes_;
  std::map<NhKey, NhRef> next_hops_;
  std::map<std::vector<NhKey>, GroupRef> groups_;
  std::map<std::string, bool> crm_warned_;
};

}  // namespace nanonos
