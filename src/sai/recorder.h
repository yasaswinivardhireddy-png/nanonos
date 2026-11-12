// Decorator that records every programming call made through the SAI API,
// in the spirit of SONiC's sairedis.rec: one line per create/set/remove with
// its arguments and result. Useful for debugging orchestration order and for
// asserting call sequences in tests. Read-only calls are forwarded unrecorded.
#pragma once

#include <functional>
#include <string>

#include "sai/sai.h"

namespace nanonos::sai {

class RecordingSwitchApi final : public SwitchApi {
 public:
  using Sink = std::function<void(const std::string& line)>;
  RecordingSwitchApi(SwitchApi* target, Sink sink) : t_(target), sink_(std::move(sink)) {}

  Status SetSwitchMac(const MacAddress& mac) override;
  Status SetEcmpHashSeed(uint32_t seed) override;
  Status SetFdbAgingTime(uint32_t seconds) override;
  uint16_t GetPortCount() const override { return t_->GetPortCount(); }
  ObjectId GetPortId(uint16_t index) const override { return t_->GetPortId(index); }
  Status SetPortAdminState(ObjectId port, bool up) override;
  Status SetPortMode(ObjectId port, PortMode mode, uint16_t pvid) override;
  Status SetPortMtu(ObjectId port, uint16_t mtu) override;
  Status SetPortMacLimit(ObjectId port, uint32_t max_macs) override;
  Status SetPortStormControl(ObjectId port, StormType type, uint64_t pps) override;
  Status SetPortScheduler(ObjectId port, const SchedulerConfig& config) override;
  Status SetPortShaper(ObjectId port, uint64_t bits_per_second) override;
  Status SetQueueWred(ObjectId port, uint8_t queue, const WredProfile& profile) override;
  Status CreateVlan(uint16_t vid, ObjectId* vlan) override;
  Status RemoveVlan(ObjectId vlan) override;
  Status CreateVlanMember(ObjectId vlan, ObjectId port, bool tagged, ObjectId* member) override;
  Status RemoveVlanMember(ObjectId member) override;
  Status CreateStaticFdbEntry(uint16_t vid, const MacAddress& mac, ObjectId port) override;
  Status FlushFdb(ObjectId port) override;
  Status CreateRouterInterface(const RouterInterfaceAttrs& attrs, ObjectId* rif) override;
  Status RemoveRouterInterface(ObjectId rif) override;
  Status CreateNeighbor(ObjectId rif, uint32_t ip, const MacAddress& mac) override;
  Status RemoveNeighbor(ObjectId rif, uint32_t ip) override;
  Status CreateNextHop(ObjectId rif, uint32_t ip, ObjectId* next_hop) override;
  Status RemoveNextHop(ObjectId next_hop) override;
  Status CreateNextHopGroup(ObjectId* group) override;
  Status RemoveNextHopGroup(ObjectId group) override;
  Status AddNextHopGroupMember(ObjectId group, ObjectId next_hop) override;
  Status RemoveNextHopGroupMember(ObjectId group, ObjectId next_hop) override;
  Status CreateRoute(const Ipv4Prefix& prefix, const RouteAttrs& attrs) override;
  Status SetRoute(const Ipv4Prefix& prefix, const RouteAttrs& attrs) override;
  Status RemoveRoute(const Ipv4Prefix& prefix) override;
  Status CreateAclEntry(const AclRule& rule, ObjectId* entry) override;
  Status RemoveAclEntry(ObjectId entry) override;
  Status SetDscpToTc(uint8_t dscp, uint8_t tc) override;
  Status SetTrapPolicer(TrapType trap, uint64_t pps, uint64_t burst) override;

  bool GetPortOperStatus(ObjectId port) const override { return t_->GetPortOperStatus(port); }
  PortCounters GetPortCounters(ObjectId port) const override { return t_->GetPortCounters(port); }
  QueueCounters GetQueueCounters(ObjectId port, uint8_t queue) const override {
    return t_->GetQueueCounters(port, queue);
  }
  uint64_t GetDropCount(DropReason reason) const override { return t_->GetDropCount(reason); }
  TrapCounters GetTrapCounters(TrapType trap) const override { return t_->GetTrapCounters(trap); }
  std::vector<ResourceUsage> GetResources() const override { return t_->GetResources(); }
  std::vector<AclRuleStats> GetAclStats() const override { return t_->GetAclStats(); }
  void ForEachFdbEntry(const std::function<void(const FdbView&)>& fn) const override {
    t_->ForEachFdbEntry(fn);
  }
  Status ClearCounters() override { return t_->ClearCounters(); }

 private:
  Status Record(char op, const char* object, const std::string& args, Status status);

  SwitchApi* t_;
  Sink sink_;
};

// "oid:0x4000000000003"
std::string OidString(ObjectId id);

}  // namespace nanonos::sai
