// The software ASIC ("vASIC"): a switch pipeline behind the SAI-style API.
//
// Ingress: parse -> link-local trap -> VLAN classification -> ingress ACL
// (TCAM) -> MAC learning (port security) -> router-MAC check ->
//   L2: FDB lookup / flood with storm control
//   L3: ip2me trap (CoPP) -> TTL -> neighbor (host) table -> LPM -> ECMP
//       (resilient hashing) -> rewrite (MACs, TTL, checksum)
// Egress: DSCP -> traffic class -> WRED/ECN -> SP + DWRR scheduler -> shaper.
//
// Like a hardware pipeline it is run-to-completion and allocation-free: all
// tables and packet buffers are sized at construction.
#pragma once

#include <array>
#include <bitset>
#include <cstdint>
#include <functional>
#include <span>
#include <vector>

#include "asic/acl.h"
#include "asic/bucket_hash.h"
#include "asic/ecmp.h"
#include "asic/fdb.h"
#include "asic/lpm.h"
#include "asic/policer.h"
#include "asic/qos.h"
#include "common/clock.h"
#include "packet/packet.h"
#include "sai/sai.h"

namespace nanonos {

// A packet trapped to the CPU. `frame` is always untagged, as a Linux host
// interface would deliver it.
struct CpuPacket {
  sai::TrapType trap;
  uint16_t in_port;
  int rif;        // router interface index, -1 if none
  uint16_t vlan;  // 0 on routed ports
  std::span<const uint8_t> frame;
};

// Traffic hit a next hop without a resolved MAC; the control plane should ARP.
struct NeighborMiss {
  int rif = -1;
  uint32_t ip = 0;
};

class VirtualAsic final : public sai::SwitchApi {
 public:
  static constexpr uint16_t kMaxPorts = 64;

  struct Options {
    uint16_t num_ports = 32;
    size_t fdb_buckets = 4096;
    size_t fdb_ways = 4;
    int hash_choices = 2;
    size_t neighbor_buckets = 1024;
    size_t neighbor_ways = 4;
    size_t lpm_routes = 16384;
    size_t lpm_nodes = 2048;
    size_t max_next_hops = 4096;
    size_t max_groups = 512;
    size_t max_rifs = 128;
    size_t acl_entries = 512;
    size_t packet_buffers = 4096;
    uint32_t queue_packets = 512;
    uint32_t queue_bytes = 512 * 1024;
  };

  VirtualAsic(const Options& options, const Clock* clock);

  using TxHandler = std::function<void(uint16_t port, std::span<const uint8_t> frame)>;
  using CpuHandler = std::function<void(const CpuPacket& packet)>;
  void SetTxHandler(TxHandler handler) { tx_ = std::move(handler); }
  void SetCpuHandler(CpuHandler handler) { cpu_ = std::move(handler); }

  // Ingress pipeline. Forwarded copies wait in egress queues until Drain().
  void Receive(uint16_t port, std::span<const uint8_t> frame);
  // Host-interface transmit: a frame from the CPU leaves through a router
  // interface (bridged within the VLAN for an SVI).
  void SendFromCpu(sai::ObjectId rif, std::span<const uint8_t> frame);
  // Raw transmit on one port, bypassing the pipeline (LLDP).
  void SendOnPort(uint16_t port, std::span<const uint8_t> frame);
  // Moves queued packets to the wire, subject to the schedulers and shapers.
  void Drain();
  // Link state from the PHY. Link down flushes the port's MACs and queues and
  // prunes next hops behind it from every ECMP group before the control
  // plane reacts (data-plane fast failover).
  void SetPortOperStatus(uint16_t port, bool up);
  bool PopNeighborMiss(NeighborMiss* miss);
  void AgeFdb();
  uint16_t num_ports() const { return static_cast<uint16_t>(ports_.size()); }
  size_t free_buffers() const { return pool_.available(); }

  // sai::SwitchApi
  Status SetSwitchMac(const MacAddress& mac) override;
  Status SetEcmpHashSeed(uint32_t seed) override;
  Status SetFdbAgingTime(uint32_t seconds) override;
  uint16_t GetPortCount() const override { return num_ports(); }
  sai::ObjectId GetPortId(uint16_t index) const override;
  Status SetPortAdminState(sai::ObjectId port, bool up) override;
  Status SetPortMode(sai::ObjectId port, sai::PortMode mode, uint16_t pvid) override;
  Status SetPortMtu(sai::ObjectId port, uint16_t mtu) override;
  Status SetPortMacLimit(sai::ObjectId port, uint32_t max_macs) override;
  Status SetPortStormControl(sai::ObjectId port, sai::StormType type, uint64_t pps) override;
  Status SetPortScheduler(sai::ObjectId port, const SchedulerConfig& config) override;
  Status SetPortShaper(sai::ObjectId port, uint64_t bits_per_second) override;
  Status SetQueueWred(sai::ObjectId port, uint8_t queue, const WredProfile& profile) override;
  Status CreateVlan(uint16_t vid, sai::ObjectId* vlan) override;
  Status RemoveVlan(sai::ObjectId vlan) override;
  Status CreateVlanMember(sai::ObjectId vlan, sai::ObjectId port, bool tagged,
                          sai::ObjectId* member) override;
  Status RemoveVlanMember(sai::ObjectId member) override;
  Status CreateStaticFdbEntry(uint16_t vid, const MacAddress& mac, sai::ObjectId port) override;
  Status FlushFdb(sai::ObjectId port) override;
  Status CreateRouterInterface(const sai::RouterInterfaceAttrs& attrs, sai::ObjectId* rif) override;
  Status RemoveRouterInterface(sai::ObjectId rif) override;
  Status CreateNeighbor(sai::ObjectId rif, uint32_t ip, const MacAddress& mac) override;
  Status RemoveNeighbor(sai::ObjectId rif, uint32_t ip) override;
  Status CreateNextHop(sai::ObjectId rif, uint32_t ip, sai::ObjectId* next_hop) override;
  Status RemoveNextHop(sai::ObjectId next_hop) override;
  Status CreateNextHopGroup(sai::ObjectId* group) override;
  Status RemoveNextHopGroup(sai::ObjectId group) override;
  Status AddNextHopGroupMember(sai::ObjectId group, sai::ObjectId next_hop) override;
  Status RemoveNextHopGroupMember(sai::ObjectId group, sai::ObjectId next_hop) override;
  Status CreateRoute(const Ipv4Prefix& prefix, const sai::RouteAttrs& attrs) override;
  Status SetRoute(const Ipv4Prefix& prefix, const sai::RouteAttrs& attrs) override;
  Status RemoveRoute(const Ipv4Prefix& prefix) override;
  Status CreateAclEntry(const AclRule& rule, sai::ObjectId* entry) override;
  Status RemoveAclEntry(sai::ObjectId entry) override;
  Status SetDscpToTc(uint8_t dscp, uint8_t tc) override;
  Status SetTrapPolicer(sai::TrapType trap, uint64_t pps, uint64_t burst) override;
  bool GetPortOperStatus(sai::ObjectId port) const override;
  sai::PortCounters GetPortCounters(sai::ObjectId port) const override;
  QueueCounters GetQueueCounters(sai::ObjectId port, uint8_t queue) const override;
  uint64_t GetDropCount(sai::DropReason reason) const override;
  sai::TrapCounters GetTrapCounters(sai::TrapType trap) const override;
  std::vector<sai::ResourceUsage> GetResources() const override;
  std::vector<sai::AclRuleStats> GetAclStats() const override;
  void ForEachFdbEntry(const std::function<void(const sai::FdbView&)>& fn) const override;
  Status ClearCounters() override;

 private:
  struct Port {
    explicit Port(const Options& o) : queues(o.queue_packets, o.queue_bytes) {}
    bool admin_up = false;
    bool oper_up = true;
    sai::PortMode mode = sai::PortMode::kAccess;
    uint16_t pvid = 1;
    uint16_t mtu = 1500;
    int rif = -1;
    std::array<SrTcmPolicer, sai::kStormTypeCount> storm;
    EgressQueues queues;
    Shaper shaper;
    Xorshift rng;
    sai::PortCounters counters;
  };
  struct Vlan {
    bool exists = false;
    std::bitset<kMaxPorts> members;
    std::bitset<kMaxPorts> tagged;
    int rif = -1;
  };
  struct Rif {
    bool exists = false;
    sai::RouterInterfaceType type = sai::RouterInterfaceType::kPort;
    uint16_t port = 0;
    uint16_t vlan = 0;
    MacAddress mac;
    uint16_t mtu = 1500;
    uint32_t refs = 0;  // neighbors, next hops and routes using this interface
  };
  struct Neighbor {
    uint16_t rif = 0;
    MacAddress mac;
  };
  struct NextHop {
    bool exists = false;
    uint16_t rif = 0;
    uint32_t ip = 0;
    uint32_t refs = 0;  // routes and groups using this next hop
  };
  struct Group {
    bool exists = false;
    std::vector<uint32_t> members;
    EcmpGroup ecmp;
    uint32_t refs = 0;
  };
  struct TrapState {
    SrTcmPolicer policer;
    sai::TrapCounters counters;
  };
  struct IpHash {
    uint64_t operator()(uint32_t ip) const { return Mix64(ip); }
  };
  struct RecentMiss {
    uint32_t ip = 0;
    TimeUs time = 0;
  };

  // LPM values encode the route target: 2 type bits + 22 index bits.
  enum TargetType : uint32_t {
    kTargetNextHop = 0,
    kTargetGroup = 1,
    kTargetRif = 2,
    kTargetDrop = 3
  };
  static uint32_t EncodeTarget(TargetType type, uint32_t index) { return (type << 22) | index; }

  void Bridge(uint16_t in_port, Port& port, uint16_t vid, const ParsedPacket& pkt,
              std::span<const uint8_t> frame, int tc, TimeUs now);
  void Route(uint16_t in_port, Port& port, int in_rif, uint16_t vid, const ParsedPacket& pkt,
             std::span<const uint8_t> frame, int tc_override);
  void FloodVlan(uint16_t vid, int skip_port, std::span<const uint8_t> frame, bool in_tagged,
                 uint8_t pcp, int tc, bool is_ipv4);
  void EmitToVlanMember(uint16_t out_port, uint16_t vid, std::span<const uint8_t> frame,
                        bool in_tagged, uint8_t pcp, int tc, bool is_ipv4);
  void Emit(uint16_t out_port, std::span<const uint8_t> frame, bool in_tagged, int out_vlan,
            uint8_t pcp, int tc, bool is_ipv4);
  void Trap(sai::TrapType trap, uint16_t in_port, int rif, uint16_t vid,
            std::span<const uint8_t> frame, bool tagged);
  void CountDrop(Port* port, sai::DropReason reason, bool egress = false);
  void RaiseNeighborMiss(int rif, uint32_t ip);
  void RefreshGroup(Group& group);
  void RefreshAllGroups();
  bool NextHopUsable(uint32_t nh) const;
  int TrafficClass(const ParsedPacket& pkt, int tc_override) const;

  Status ResolveTarget(const sai::RouteAttrs& attrs, uint32_t* target);
  void ReleaseTarget(uint32_t target);
  int PortIndex(sai::ObjectId port) const;
  int RifIndex(sai::ObjectId rif) const;
  int NextHopIndex(sai::ObjectId nh) const;
  int GroupIndex(sai::ObjectId group) const;

  const Clock* clock_;
  std::vector<Port> ports_;
  std::vector<Vlan> vlans_;
  std::vector<Rif> rifs_;
  std::vector<NextHop> next_hops_;
  std::vector<Group> groups_;
  Fdb fdb_;
  BucketHashTable<uint32_t, Neighbor, IpHash> neighbors_;
  BucketHashTable<uint32_t, uint16_t, IpHash> local_ips_;  // ip2me -> router interface
  LpmTable lpm_;
  AclTable acl_;
  PacketPool pool_;
  std::array<uint8_t, 64> dscp_to_tc_{};
  std::array<TrapState, sai::kTrapTypeCount> traps_;
  std::array<uint64_t, sai::kDropReasonCount> drops_{};
  std::array<NeighborMiss, 256> miss_ring_{};
  size_t miss_head_ = 0;
  size_t miss_count_ = 0;
  std::array<RecentMiss, 64> recent_miss_{};
  MacAddress switch_mac_;
  uint32_t hash_seed_ = 0;
  TimeUs fdb_aging_us_ = 300 * kUsPerSec;
  ParsedPacket parsed_;
  std::array<uint8_t, kMaxFrameSize> scratch_{};
  std::array<uint8_t, kMaxFrameSize> cpu_scratch_{};
  TxHandler tx_;
  CpuHandler cpu_;
};

}  // namespace nanonos
