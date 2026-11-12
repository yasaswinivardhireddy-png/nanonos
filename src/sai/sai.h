// A small switch abstraction interface modelled on SAI (the Switch
// Abstraction Interface used by SONiC). The control plane (orchagent) only
// talks to the switch through this API, so the same control plane could drive
// a hardware ASIC SDK; here it drives the software ASIC in asic/vasic.h.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include "asic/acl.h"
#include "asic/qos.h"
#include "common/clock.h"
#include "common/status.h"
#include "common/types.h"

namespace nanonos::sai {

// Object ids carry their type in the top bits, like SAI object ids.
using ObjectId = uint64_t;
inline constexpr ObjectId kNullObjectId = 0;

enum class ObjectType : uint8_t {
  kNull = 0,
  kPort = 1,
  kVlan = 2,
  kVlanMember = 3,
  kRouterInterface = 4,
  kNextHop = 5,
  kNextHopGroup = 6,
  kAclEntry = 7,
};

constexpr ObjectId MakeObjectId(ObjectType type, uint32_t index) {
  return (uint64_t{static_cast<uint8_t>(type)} << 48) | index;
}
constexpr ObjectType TypeOf(ObjectId id) { return static_cast<ObjectType>(id >> 48); }
constexpr uint32_t IndexOf(ObjectId id) { return static_cast<uint32_t>(id & 0xffffffffu); }

enum class PortMode : uint8_t { kAccess, kTrunk, kRouted };
enum class RouterInterfaceType : uint8_t { kPort, kVlan };

struct RouterInterfaceAttrs {
  RouterInterfaceType type = RouterInterfaceType::kPort;
  ObjectId port = kNullObjectId;  // kPort
  uint16_t vlan = 0;              // kVlan (SVI)
  MacAddress mac;                 // zero = switch MAC
  uint16_t mtu = 1500;
};

enum class RouteAction : uint8_t { kForward, kDrop, kTrapToCpu };

struct RouteAttrs {
  RouteAction action = RouteAction::kForward;
  // kForward: a next hop, a next-hop group, or a router interface (directly
  // connected subnet). kTrapToCpu (/32 "ip2me" routes): the router interface
  // that owns the address.
  ObjectId next_hop = kNullObjectId;
};

// Control-plane traps, each with its own CoPP policer.
enum class TrapType : uint8_t { kLldp, kArp, kBgp, kIcmpToMe, kIpToMe, kCount };
inline constexpr size_t kTrapTypeCount = static_cast<size_t>(TrapType::kCount);
const char* TrapTypeName(TrapType trap);

enum class StormType : uint8_t { kBroadcast, kMulticast, kUnknownUnicast, kCount };
inline constexpr size_t kStormTypeCount = static_cast<size_t>(StormType::kCount);

// Why the pipeline dropped a packet (SONiC calls these debug drop counters).
enum class DropReason : uint8_t {
  kPortDown,
  kEgressPortDown,
  kOversize,
  kMalformed,
  kIpChecksum,
  kSrcMacInvalid,
  kReservedMac,
  kVlanFilter,
  kAclDeny,
  kPortSecurity,
  kStormControl,
  kSameInterface,
  kL2OnRoutedPort,
  kUnsupportedL3,
  kTtlExpired,
  kNoRoute,
  kBlackhole,
  kNeighborMiss,
  kMtuExceeded,
  kCoppPolicer,
  kTailDrop,
  kWredDrop,
  kNoBuffer,
  kCount,
};
inline constexpr size_t kDropReasonCount = static_cast<size_t>(DropReason::kCount);
const char* DropReasonName(DropReason reason);

struct PortCounters {
  uint64_t rx_pkts = 0;
  uint64_t rx_bytes = 0;
  uint64_t tx_pkts = 0;
  uint64_t tx_bytes = 0;
  uint64_t rx_drops = 0;
  uint64_t tx_drops = 0;
  uint64_t rx_broadcast = 0;
  uint64_t rx_multicast = 0;
  uint64_t mac_moves = 0;
  uint64_t rx_pause = 0;
};

struct TrapCounters {
  uint64_t packets = 0;  // delivered to the CPU
  uint64_t policed = 0;  // dropped by the CoPP policer
};

// Critical resource monitoring (CRM): utilization of every hardware table.
struct ResourceUsage {
  const char* name;
  size_t used;
  size_t capacity;
};

struct FdbView {
  uint16_t vlan;
  MacAddress mac;
  uint16_t port;
  bool is_static;
};

struct AclRuleStats {
  uint32_t seq;
  uint64_t hits;
  size_t tcam_entries;
};

class SwitchApi {
 public:
  virtual ~SwitchApi() = default;

  // Switch-wide attributes.
  virtual Status SetSwitchMac(const MacAddress& mac) = 0;
  virtual Status SetEcmpHashSeed(uint32_t seed) = 0;
  virtual Status SetFdbAgingTime(uint32_t seconds) = 0;

  // Ports exist from power-on, like the front-panel ports of an ASIC.
  virtual uint16_t GetPortCount() const = 0;
  virtual ObjectId GetPortId(uint16_t index) const = 0;
  virtual Status SetPortAdminState(ObjectId port, bool up) = 0;
  virtual Status SetPortMode(ObjectId port, PortMode mode, uint16_t pvid) = 0;
  virtual Status SetPortMtu(ObjectId port, uint16_t mtu) = 0;
  virtual Status SetPortMacLimit(ObjectId port, uint32_t max_macs) = 0;
  virtual Status SetPortStormControl(ObjectId port, StormType type, uint64_t pps) = 0;
  virtual Status SetPortScheduler(ObjectId port, const SchedulerConfig& config) = 0;
  virtual Status SetPortShaper(ObjectId port, uint64_t bits_per_second) = 0;
  virtual Status SetQueueWred(ObjectId port, uint8_t queue, const WredProfile& profile) = 0;

  virtual Status CreateVlan(uint16_t vid, ObjectId* vlan) = 0;
  virtual Status RemoveVlan(ObjectId vlan) = 0;
  virtual Status CreateVlanMember(ObjectId vlan, ObjectId port, bool tagged, ObjectId* member) = 0;
  virtual Status RemoveVlanMember(ObjectId member) = 0;

  virtual Status CreateStaticFdbEntry(uint16_t vid, const MacAddress& mac, ObjectId port) = 0;
  virtual Status FlushFdb(ObjectId port) = 0;  // kNullObjectId flushes all ports

  virtual Status CreateRouterInterface(const RouterInterfaceAttrs& attrs, ObjectId* rif) = 0;
  virtual Status RemoveRouterInterface(ObjectId rif) = 0;

  // Creates or updates a neighbor (ARP) entry.
  virtual Status CreateNeighbor(ObjectId rif, uint32_t ip, const MacAddress& mac) = 0;
  virtual Status RemoveNeighbor(ObjectId rif, uint32_t ip) = 0;

  virtual Status CreateNextHop(ObjectId rif, uint32_t ip, ObjectId* next_hop) = 0;
  virtual Status RemoveNextHop(ObjectId next_hop) = 0;
  virtual Status CreateNextHopGroup(ObjectId* group) = 0;
  virtual Status RemoveNextHopGroup(ObjectId group) = 0;
  virtual Status AddNextHopGroupMember(ObjectId group, ObjectId next_hop) = 0;
  virtual Status RemoveNextHopGroupMember(ObjectId group, ObjectId next_hop) = 0;

  virtual Status CreateRoute(const Ipv4Prefix& prefix, const RouteAttrs& attrs) = 0;
  virtual Status SetRoute(const Ipv4Prefix& prefix, const RouteAttrs& attrs) = 0;
  virtual Status RemoveRoute(const Ipv4Prefix& prefix) = 0;

  virtual Status CreateAclEntry(const AclRule& rule, ObjectId* entry) = 0;
  virtual Status RemoveAclEntry(ObjectId entry) = 0;

  virtual Status SetDscpToTc(uint8_t dscp, uint8_t tc) = 0;
  virtual Status SetTrapPolicer(TrapType trap, uint64_t pps, uint64_t burst) = 0;

  // Read-only state and statistics.
  virtual bool GetPortOperStatus(ObjectId port) const = 0;
  virtual PortCounters GetPortCounters(ObjectId port) const = 0;
  virtual QueueCounters GetQueueCounters(ObjectId port, uint8_t queue) const = 0;
  virtual uint64_t GetDropCount(DropReason reason) const = 0;
  virtual TrapCounters GetTrapCounters(TrapType trap) const = 0;
  virtual std::vector<ResourceUsage> GetResources() const = 0;
  virtual std::vector<AclRuleStats> GetAclStats() const = 0;
  virtual void ForEachFdbEntry(const std::function<void(const FdbView&)>& fn) const = 0;
  virtual Status ClearCounters() = 0;
};

}  // namespace nanonos::sai
