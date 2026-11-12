#include "asic/vasic.h"

#include <algorithm>
#include <cstring>

#include "common/byte_order.h"

namespace nanonos {

using sai::DropReason;
using sai::ObjectId;
using sai::ObjectType;

namespace {

constexpr int kCpuTc = 7;  // control traffic from the CPU uses the highest queue
constexpr uint8_t kCpuPcp = 6;
constexpr TimeUs kMissHoldDown = 100 * kUsPerMs;

}  // namespace

VirtualAsic::VirtualAsic(const Options& o, const Clock* clock)
    : clock_(clock),
      vlans_(4096),
      rifs_(o.max_rifs),
      next_hops_(o.max_next_hops),
      groups_(o.max_groups),
      fdb_(o.fdb_buckets, o.fdb_ways, o.hash_choices, kMaxPorts),
      neighbors_(o.neighbor_buckets, o.neighbor_ways, o.hash_choices),
      local_ips_(256, 4, 2),
      lpm_(o.lpm_routes, o.lpm_nodes),
      acl_(o.acl_entries),
      pool_(o.packet_buffers),
      switch_mac_(MacAddress::FromU64(0x020000000001ULL)) {
  const uint16_t n = std::min<uint16_t>(o.num_ports, kMaxPorts);
  ports_.reserve(n);
  for (uint16_t i = 0; i < n; ++i) {
    ports_.emplace_back(o);
    ports_.back().rng = Xorshift(0x5eed0000ULL + i);
  }
  // Default QoS map: the DSCP class selector (top 3 bits) picks the traffic class.
  for (size_t d = 0; d < dscp_to_tc_.size(); ++d) dscp_to_tc_[d] = static_cast<uint8_t>(d >> 3);
}

// ---------------------------------------------------------------------------
// Data plane
// ---------------------------------------------------------------------------

void VirtualAsic::Receive(uint16_t in_port, std::span<const uint8_t> frame) {
  if (in_port >= ports_.size()) return;
  Port& port = ports_[in_port];
  if (!port.admin_up || !port.oper_up) {
    CountDrop(&port, DropReason::kPortDown);
    return;
  }
  ++port.counters.rx_pkts;
  port.counters.rx_bytes += frame.size();
  if (frame.size() > kMaxFrameSize) {
    CountDrop(&port, DropReason::kOversize);
    return;
  }
  ParsedPacket pkt;
  const ParseStatus status = ParseFrame(frame, &pkt);
  if (status != ParseStatus::kOk) {
    CountDrop(&port, status == ParseStatus::kBadIpChecksum ? DropReason::kIpChecksum
                                                           : DropReason::kMalformed);
    return;
  }
  if (pkt.dst_mac.IsBroadcast()) {
    ++port.counters.rx_broadcast;
  } else if (pkt.dst_mac.IsMulticast()) {
    ++port.counters.rx_multicast;
  }
  if (pkt.src_mac.IsMulticast() || pkt.src_mac.IsZero()) {
    CountDrop(&port, DropReason::kSrcMacInvalid);
    return;
  }

  // IEEE 802.1 link-local frames are consumed by the switch, never forwarded.
  if (IsLinkLocalMulticast(pkt.dst_mac)) {
    if (pkt.ethertype == kEtherTypeLldp) {
      Trap(sai::TrapType::kLldp, in_port, -1, 0, frame, pkt.vlan_tagged);
    } else if (pkt.ethertype == kEtherTypeMacControl) {
      ++port.counters.rx_pause;
    } else {
      CountDrop(&port, DropReason::kReservedMac);
    }
    return;
  }

  // VLAN classification and ingress filtering.
  uint16_t vid = 0;
  if (port.mode == sai::PortMode::kRouted) {
    if (pkt.vlan_tagged) {
      CountDrop(&port, DropReason::kVlanFilter);
      return;
    }
  } else {
    const bool has_vid = pkt.vlan_tagged && pkt.vlan_id != 0;  // VID 0 = priority tag
    if (port.mode == sai::PortMode::kAccess && has_vid) {
      CountDrop(&port, DropReason::kVlanFilter);
      return;
    }
    vid = has_vid ? pkt.vlan_id : port.pvid;
    if (vid == 0 || vid >= 4095 || !vlans_[vid].exists || !vlans_[vid].members[in_port]) {
      CountDrop(&port, DropReason::kVlanFilter);
      return;
    }
  }

  // Ingress ACL (TCAM).
  int tc_override = -1;
  if (pkt.is_ipv4() && acl_.rule_count() > 0) {
    AclLookupKey key;
    key.src_ip = pkt.src_ip;
    key.dst_ip = pkt.dst_ip;
    key.ip_proto = pkt.ip_proto;
    key.dscp = pkt.dscp;
    key.in_port = in_port;
    if (pkt.has_l4 && (pkt.ip_proto == kIpProtoTcp || pkt.ip_proto == kIpProtoUdp)) {
      key.src_port = pkt.src_port;
      key.dst_port = pkt.dst_port;
    }
    if (const AclResult* r = acl_.Lookup(key)) {
      if (r->action == AclAction::kDeny) {
        CountDrop(&port, DropReason::kAclDeny);
        return;
      }
      if (r->action == AclAction::kSetTc) tc_override = r->set_tc;
    }
  }

  // Source MAC learning with port security.
  const TimeUs now = clock_->Now();
  if (port.mode != sai::PortMode::kRouted) {
    switch (fdb_.Learn(vid, pkt.src_mac, in_port, now)) {
      case LearnResult::kPortLimit:
      case LearnResult::kStaticConflict:
        CountDrop(&port, DropReason::kPortSecurity);
        return;
      case LearnResult::kMoved:
        ++port.counters.mac_moves;
        break;
      default:
        break;
    }
  }

  // Frames addressed to the router MAC are routed; ARP for our addresses is trapped.
  const int rif_index = port.mode == sai::PortMode::kRouted ? port.rif : vlans_[vid].rif;
  if (rif_index >= 0) {
    const Rif& rif = rifs_[static_cast<size_t>(rif_index)];
    if (pkt.is_arp()) {
      const uint16_t* owner = local_ips_.Find(pkt.arp_tpa);
      const bool for_us = owner != nullptr && *owner == rif_index;
      if (for_us && (pkt.dst_mac.IsBroadcast() || pkt.dst_mac == rif.mac)) {
        Trap(sai::TrapType::kArp, in_port, rif_index, vid, frame, pkt.vlan_tagged);
      }
      if (port.mode == sai::PortMode::kRouted) {
        if (!for_us) CountDrop(&port, DropReason::kL2OnRoutedPort);
        return;
      }
      if (pkt.dst_mac == rif.mac) return;
      // A broadcast ARP on an SVI is also flooded to the hosts in the VLAN.
    } else if (pkt.dst_mac == rif.mac) {
      Route(in_port, port, rif_index, vid, pkt, frame, tc_override);
      return;
    } else if (port.mode == sai::PortMode::kRouted) {
      CountDrop(&port, DropReason::kL2OnRoutedPort);
      return;
    }
  } else if (port.mode == sai::PortMode::kRouted) {
    CountDrop(&port, DropReason::kL2OnRoutedPort);
    return;
  }
  Bridge(in_port, port, vid, pkt, frame, TrafficClass(pkt, tc_override), now);
}

void VirtualAsic::Bridge(uint16_t in_port, Port& port, uint16_t vid, const ParsedPacket& pkt,
                         std::span<const uint8_t> frame, int tc, TimeUs now) {
  const bool ipv4 = pkt.is_ipv4();
  if (pkt.dst_mac.IsMulticast()) {
    const auto type =
        pkt.dst_mac.IsBroadcast() ? sai::StormType::kBroadcast : sai::StormType::kMulticast;
    if (port.storm[static_cast<size_t>(type)].Meter(1, now) == Color::kRed) {
      CountDrop(&port, DropReason::kStormControl);
      return;
    }
    FloodVlan(vid, in_port, frame, pkt.vlan_tagged, pkt.pcp, tc, ipv4);
    return;
  }
  if (const FdbEntry* e = fdb_.Lookup(vid, pkt.dst_mac)) {
    if (e->port == in_port) {
      CountDrop(&port, DropReason::kSameInterface);
      return;
    }
    EmitToVlanMember(e->port, vid, frame, pkt.vlan_tagged, pkt.pcp, tc, ipv4);
    return;
  }
  if (port.storm[static_cast<size_t>(sai::StormType::kUnknownUnicast)].Meter(1, now) ==
      Color::kRed) {
    CountDrop(&port, DropReason::kStormControl);
    return;
  }
  FloodVlan(vid, in_port, frame, pkt.vlan_tagged, pkt.pcp, tc, ipv4);
}

void VirtualAsic::Route(uint16_t in_port, Port& port, int in_rif, uint16_t vid,
                        const ParsedPacket& pkt, std::span<const uint8_t> frame, int tc_override) {
  if (!pkt.is_ipv4()) {
    CountDrop(&port, DropReason::kUnsupportedL3);
    return;
  }
  if (local_ips_.Find(pkt.dst_ip) != nullptr) {
    sai::TrapType trap = sai::TrapType::kIpToMe;
    if (pkt.ip_proto == kIpProtoTcp && pkt.has_l4 &&
        (pkt.dst_port == kBgpPort || pkt.src_port == kBgpPort)) {
      trap = sai::TrapType::kBgp;
    } else if (pkt.ip_proto == kIpProtoIcmp) {
      trap = sai::TrapType::kIcmpToMe;
    }
    Trap(trap, in_port, in_rif, vid, frame, pkt.vlan_tagged);
    return;
  }
  if (pkt.ttl <= 1) {
    CountDrop(&port, DropReason::kTtlExpired);
    return;
  }

  // Next-hop resolution: a directly connected host (neighbor table) first,
  // then the longest-prefix match.
  const Neighbor* nb = neighbors_.Find(pkt.dst_ip);
  if (nb == nullptr) {
    const auto route = lpm_.Lookup(pkt.dst_ip);
    if (!route) {
      CountDrop(&port, DropReason::kNoRoute);
      return;
    }
    const uint32_t type = *route >> 22;
    const uint32_t index = *route & 0x3fffff;
    uint32_t nh_ip = pkt.dst_ip;
    int out_rif = -1;
    switch (type) {
      case kTargetNextHop:
        nh_ip = next_hops_[index].ip;
        out_rif = next_hops_[index].rif;
        break;
      case kTargetGroup: {
        const Group& g = groups_[index];
        if (g.ecmp.empty()) {
          CountDrop(&port, DropReason::kNoRoute);
          return;
        }
        const NextHop& nh = next_hops_[g.ecmp.Select(FlowHash(pkt, hash_seed_))];
        nh_ip = nh.ip;
        out_rif = nh.rif;
        break;
      }
      case kTargetRif:
        out_rif = static_cast<int>(index);  // connected subnet: the destination is the neighbor
        break;
      default:
        CountDrop(&port, DropReason::kBlackhole);
        return;
    }
    nb = neighbors_.Find(nh_ip);
    if (nb == nullptr || nb->rif != out_rif) {
      RaiseNeighborMiss(out_rif, nh_ip);
      CountDrop(&port, DropReason::kNeighborMiss);
      return;
    }
  }

  const Rif& orif = rifs_[nb->rif];
  if (pkt.ip_total_len > orif.mtu) {
    CountDrop(&port, DropReason::kMtuExceeded);
    return;
  }
  // Rewrite: new Ethernet header (untagged), TTL - 1 with an incremental checksum.
  uint8_t* d = scratch_.data();
  std::memcpy(d, nb->mac.bytes.data(), 6);
  std::memcpy(d + 6, orif.mac.bytes.data(), 6);
  StoreBe16(d + 12, kEtherTypeIpv4);
  std::memcpy(d + kEthHeaderLen, frame.data() + pkt.l3_offset, pkt.ip_total_len);
  DecrementTtl(d + kEthHeaderLen);
  const std::span<const uint8_t> out(d, kEthHeaderLen + pkt.ip_total_len);
  const int tc = TrafficClass(pkt, tc_override);
  if (orif.type == sai::RouterInterfaceType::kPort) {
    Emit(orif.port, out, false, -1, 0, tc, true);
  } else if (const FdbEntry* e = fdb_.Lookup(orif.vlan, nb->mac)) {
    EmitToVlanMember(e->port, orif.vlan, out, false, 0, tc, true);
  } else {
    FloodVlan(orif.vlan, -1, out, false, 0, tc, true);
  }
}

void VirtualAsic::FloodVlan(uint16_t vid, int skip_port, std::span<const uint8_t> frame,
                            bool in_tagged, uint8_t pcp, int tc, bool is_ipv4) {
  const Vlan& v = vlans_[vid];
  for (uint16_t p = 0; p < ports_.size(); ++p) {
    if (p == skip_port || !v.members[p] || !ports_[p].admin_up || !ports_[p].oper_up) continue;
    EmitToVlanMember(p, vid, frame, in_tagged, pcp, tc, is_ipv4);
  }
}

void VirtualAsic::EmitToVlanMember(uint16_t out_port, uint16_t vid, std::span<const uint8_t> frame,
                                   bool in_tagged, uint8_t pcp, int tc, bool is_ipv4) {
  const Vlan& v = vlans_[vid];
  if (!v.members[out_port]) {
    CountDrop(&ports_[out_port], DropReason::kVlanFilter, true);
    return;
  }
  Emit(out_port, frame, in_tagged, v.tagged[out_port] ? vid : -1, pcp, tc, is_ipv4);
}

void VirtualAsic::Emit(uint16_t out_port, std::span<const uint8_t> frame, bool in_tagged,
                       int out_vlan, uint8_t pcp, int tc, bool is_ipv4) {
  Port& out = ports_[out_port];
  if (!out.admin_up || !out.oper_up) {
    CountDrop(&out, DropReason::kEgressPortDown, true);
    return;
  }
  const size_t in_off = in_tagged ? 16 : 12;
  if (frame.size() < in_off + 2) {
    CountDrop(&out, DropReason::kMalformed, true);
    return;
  }
  const size_t header = out_vlan >= 0 ? 16 : 12;
  const size_t rest = frame.size() - in_off;  // EtherType + payload
  if (header + rest > kMaxFrameSize) {
    CountDrop(&out, DropReason::kOversize, true);
    return;
  }
  if (rest - 2 > static_cast<size_t>(out.mtu) + 4) {  // allow Ethernet padding slack
    CountDrop(&out, DropReason::kMtuExceeded, true);
    return;
  }
  const uint32_t id = pool_.Alloc();
  if (id == PacketPool::kInvalid) {
    CountDrop(&out, DropReason::kNoBuffer, true);
    return;
  }
  PacketBuffer& b = pool_[id];
  uint8_t* d = b.data.data();
  std::memcpy(d, frame.data(), 12);
  if (out_vlan >= 0) {
    StoreBe16(d + 12, kEtherTypeVlan);
    StoreBe16(d + 14, static_cast<uint16_t>(((pcp & 0x7) << 13) | (out_vlan & 0x0fff)));
  }
  std::memcpy(d + header, frame.data() + in_off, rest);
  size_t len = header + rest;
  if (len < kMinFrameSize) {
    std::memset(d + len, 0, kMinFrameSize - len);
    len = kMinFrameSize;
  }
  b.len = static_cast<uint16_t>(len);
  b.l3_offset = is_ipv4 ? static_cast<uint16_t>(header + 2) : 0;
  const int queue = std::clamp(tc, 0, kNumQueues - 1);
  const EnqueueResult r = out.queues.Enqueue(queue, id, pool_, out.rng);
  if (r == EnqueueResult::kTailDrop || r == EnqueueResult::kWredDrop) {
    pool_.Free(id);
    CountDrop(&out, r == EnqueueResult::kTailDrop ? DropReason::kTailDrop : DropReason::kWredDrop,
              true);
  }
}

void VirtualAsic::Trap(sai::TrapType trap, uint16_t in_port, int rif, uint16_t vid,
                       std::span<const uint8_t> frame, bool tagged) {
  TrapState& t = traps_[static_cast<size_t>(trap)];
  if (t.policer.Meter(1, clock_->Now()) == Color::kRed) {
    ++t.counters.policed;
    ++drops_[static_cast<size_t>(DropReason::kCoppPolicer)];
    return;
  }
  ++t.counters.packets;
  if (!cpu_) return;
  std::span<const uint8_t> out = frame;
  if (tagged && frame.size() >= kEthHeaderLen + kVlanTagLen) {
    std::memcpy(cpu_scratch_.data(), frame.data(), 12);
    std::memcpy(cpu_scratch_.data() + 12, frame.data() + 16, frame.size() - 16);
    out = std::span<const uint8_t>(cpu_scratch_.data(), frame.size() - kVlanTagLen);
  }
  cpu_(CpuPacket{trap, in_port, rif, vid, out});
}

void VirtualAsic::SendFromCpu(ObjectId rif_id, std::span<const uint8_t> frame) {
  const int ri = RifIndex(rif_id);
  if (ri < 0 || frame.size() < kEthHeaderLen || frame.size() > kMaxFrameSize) return;
  const Rif& r = rifs_[static_cast<size_t>(ri)];
  const bool in_tagged = LoadBe16(frame.data() + 12) == kEtherTypeVlan;
  if (in_tagged && frame.size() < kEthHeaderLen + kVlanTagLen) return;
  const bool ipv4 = LoadBe16(frame.data() + (in_tagged ? 16 : 12)) == kEtherTypeIpv4;
  if (r.type == sai::RouterInterfaceType::kPort) {
    Emit(r.port, frame, in_tagged, -1, 0, kCpuTc, ipv4);
    return;
  }
  MacAddress dst;
  std::memcpy(dst.bytes.data(), frame.data(), 6);
  if (!dst.IsMulticast()) {
    if (const FdbEntry* e = fdb_.Lookup(r.vlan, dst)) {
      EmitToVlanMember(e->port, r.vlan, frame, in_tagged, kCpuPcp, kCpuTc, ipv4);
      return;
    }
  }
  FloodVlan(r.vlan, -1, frame, in_tagged, kCpuPcp, kCpuTc, ipv4);
}

void VirtualAsic::SendOnPort(uint16_t port, std::span<const uint8_t> frame) {
  if (port >= ports_.size() || frame.size() < kEthHeaderLen || frame.size() > kMaxFrameSize) {
    return;
  }
  Emit(port, frame, false, -1, 0, kCpuTc, false);
}

void VirtualAsic::Drain() {
  const TimeUs now = clock_->Now();
  for (uint16_t i = 0; i < ports_.size(); ++i) {
    Port& p = ports_[i];
    while (!p.queues.empty() && p.shaper.CanSend(now)) {
      const uint32_t id = p.queues.Dequeue(pool_);
      if (id == PacketPool::kInvalid) break;
      const PacketBuffer& b = pool_[id];
      p.shaper.Charge(b.len);
      ++p.counters.tx_pkts;
      p.counters.tx_bytes += b.len;
      if (tx_) tx_(i, std::span<const uint8_t>(b.data.data(), b.len));
      pool_.Free(id);
    }
  }
}

void VirtualAsic::SetPortOperStatus(uint16_t port, bool up) {
  if (port >= ports_.size()) return;
  Port& p = ports_[port];
  if (p.oper_up == up) return;
  p.oper_up = up;
  if (!up) {
    fdb_.FlushPort(port);
    p.queues.Flush(pool_);
  }
  RefreshAllGroups();
}

bool VirtualAsic::PopNeighborMiss(NeighborMiss* miss) {
  if (miss_count_ == 0) return false;
  *miss = miss_ring_[miss_head_];
  miss_head_ = (miss_head_ + 1) % miss_ring_.size();
  --miss_count_;
  return true;
}

void VirtualAsic::AgeFdb() {
  if (fdb_aging_us_ > 0) fdb_.Age(clock_->Now(), fdb_aging_us_);
}

void VirtualAsic::RaiseNeighborMiss(int rif, uint32_t ip) {
  // One event per destination per hold-down period, however much traffic
  // arrives for it, so the control plane is not flooded.
  RecentMiss& recent = recent_miss_[Mix64(ip) & (recent_miss_.size() - 1)];
  const TimeUs now = clock_->Now();
  if (recent.ip == ip && now - recent.time < kMissHoldDown) return;
  recent = RecentMiss{ip, now};
  if (miss_count_ == miss_ring_.size()) return;
  miss_ring_[(miss_head_ + miss_count_) % miss_ring_.size()] = NeighborMiss{rif, ip};
  ++miss_count_;
}

void VirtualAsic::CountDrop(Port* port, DropReason reason, bool egress) {
  ++drops_[static_cast<size_t>(reason)];
  if (port == nullptr) return;
  if (egress) {
    ++port->counters.tx_drops;
  } else {
    ++port->counters.rx_drops;
  }
}

int VirtualAsic::TrafficClass(const ParsedPacket& pkt, int tc_override) const {
  if (tc_override >= 0) return tc_override;
  if (pkt.is_ipv4()) return dscp_to_tc_[pkt.dscp];
  return pkt.vlan_tagged ? pkt.pcp : 0;
}

bool VirtualAsic::NextHopUsable(uint32_t nh) const {
  const Rif& r = rifs_[next_hops_[nh].rif];
  if (r.type != sai::RouterInterfaceType::kPort) return true;
  const Port& p = ports_[r.port];
  return p.admin_up && p.oper_up;
}

void VirtualAsic::RefreshGroup(Group& group) {
  std::vector<uint32_t> live;
  live.reserve(group.members.size());
  for (uint32_t m : group.members) {
    if (NextHopUsable(m)) live.push_back(m);
  }
  group.ecmp.SetActiveMembers(live);
}

void VirtualAsic::RefreshAllGroups() {
  for (Group& g : groups_) {
    if (g.exists) RefreshGroup(g);
  }
}

// ---------------------------------------------------------------------------
// SAI API
// ---------------------------------------------------------------------------

int VirtualAsic::PortIndex(ObjectId id) const {
  if (sai::TypeOf(id) != ObjectType::kPort || sai::IndexOf(id) >= ports_.size()) return -1;
  return static_cast<int>(sai::IndexOf(id));
}

int VirtualAsic::RifIndex(ObjectId id) const {
  if (sai::TypeOf(id) != ObjectType::kRouterInterface) return -1;
  const uint32_t i = sai::IndexOf(id);
  return i < rifs_.size() && rifs_[i].exists ? static_cast<int>(i) : -1;
}

int VirtualAsic::NextHopIndex(ObjectId id) const {
  if (sai::TypeOf(id) != ObjectType::kNextHop) return -1;
  const uint32_t i = sai::IndexOf(id);
  return i < next_hops_.size() && next_hops_[i].exists ? static_cast<int>(i) : -1;
}

int VirtualAsic::GroupIndex(ObjectId id) const {
  if (sai::TypeOf(id) != ObjectType::kNextHopGroup) return -1;
  const uint32_t i = sai::IndexOf(id);
  return i < groups_.size() && groups_[i].exists ? static_cast<int>(i) : -1;
}

Status VirtualAsic::SetSwitchMac(const MacAddress& mac) {
  if (mac.IsMulticast() || mac.IsZero()) return Status::kInvalidArgument;
  switch_mac_ = mac;
  return Status::kOk;
}

Status VirtualAsic::SetEcmpHashSeed(uint32_t seed) {
  hash_seed_ = seed;
  return Status::kOk;
}

Status VirtualAsic::SetFdbAgingTime(uint32_t seconds) {
  fdb_aging_us_ = static_cast<TimeUs>(seconds) * kUsPerSec;
  return Status::kOk;
}

ObjectId VirtualAsic::GetPortId(uint16_t index) const {
  return index < ports_.size() ? sai::MakeObjectId(ObjectType::kPort, index) : sai::kNullObjectId;
}

Status VirtualAsic::SetPortAdminState(ObjectId port, bool up) {
  const int p = PortIndex(port);
  if (p < 0) return Status::kInvalidArgument;
  Port& pt = ports_[static_cast<size_t>(p)];
  if (pt.admin_up == up) return Status::kOk;
  pt.admin_up = up;
  if (!up) {
    fdb_.FlushPort(static_cast<uint16_t>(p));
    pt.queues.Flush(pool_);
  }
  RefreshAllGroups();
  return Status::kOk;
}

Status VirtualAsic::SetPortMode(ObjectId port, sai::PortMode mode, uint16_t pvid) {
  const int p = PortIndex(port);
  if (p < 0 || pvid > 4094) return Status::kInvalidArgument;
  Port& pt = ports_[static_cast<size_t>(p)];
  if (pt.rif >= 0 && mode != sai::PortMode::kRouted) return Status::kInUse;
  if (mode != pt.mode) fdb_.FlushPort(static_cast<uint16_t>(p));
  pt.mode = mode;
  pt.pvid = pvid;
  return Status::kOk;
}

Status VirtualAsic::SetPortMtu(ObjectId port, uint16_t mtu) {
  const int p = PortIndex(port);
  if (p < 0 || mtu < 68 || mtu > kMaxFrameSize - kEthHeaderLen - kVlanTagLen) {
    return Status::kInvalidArgument;
  }
  ports_[static_cast<size_t>(p)].mtu = mtu;
  return Status::kOk;
}

Status VirtualAsic::SetPortMacLimit(ObjectId port, uint32_t max_macs) {
  const int p = PortIndex(port);
  if (p < 0) return Status::kInvalidArgument;
  fdb_.SetPortLimit(static_cast<uint16_t>(p), max_macs);
  return Status::kOk;
}

Status VirtualAsic::SetPortStormControl(ObjectId port, sai::StormType type, uint64_t pps) {
  const int p = PortIndex(port);
  if (p < 0 || type >= sai::StormType::kCount) return Status::kInvalidArgument;
  ports_[static_cast<size_t>(p)].storm[static_cast<size_t>(type)] =
      pps == 0 ? SrTcmPolicer()
               : SrTcmPolicer(pps, std::max<uint64_t>(pps / 10, 1), 0, clock_->Now());
  return Status::kOk;
}

Status VirtualAsic::SetPortScheduler(ObjectId port, const SchedulerConfig& config) {
  const int p = PortIndex(port);
  if (p < 0) return Status::kInvalidArgument;
  ports_[static_cast<size_t>(p)].queues.SetScheduler(config);
  return Status::kOk;
}

Status VirtualAsic::SetPortShaper(ObjectId port, uint64_t bits_per_second) {
  const int p = PortIndex(port);
  if (p < 0) return Status::kInvalidArgument;
  ports_[static_cast<size_t>(p)].shaper.Configure(bits_per_second, clock_->Now());
  return Status::kOk;
}

Status VirtualAsic::SetQueueWred(ObjectId port, uint8_t queue, const WredProfile& profile) {
  const int p = PortIndex(port);
  if (p < 0 || queue >= kNumQueues || (profile.enabled && profile.max_bytes < profile.min_bytes) ||
      profile.max_prob_pct > 100) {
    return Status::kInvalidArgument;
  }
  ports_[static_cast<size_t>(p)].queues.SetWred(queue, profile);
  return Status::kOk;
}

Status VirtualAsic::CreateVlan(uint16_t vid, ObjectId* vlan) {
  if (vid == 0 || vid > 4094) return Status::kInvalidArgument;
  if (vlans_[vid].exists) return Status::kAlreadyExists;
  vlans_[vid] = Vlan{};
  vlans_[vid].exists = true;
  *vlan = sai::MakeObjectId(ObjectType::kVlan, vid);
  return Status::kOk;
}

Status VirtualAsic::RemoveVlan(ObjectId vlan) {
  const uint32_t vid = sai::IndexOf(vlan);
  if (sai::TypeOf(vlan) != ObjectType::kVlan || vid == 0 || vid > 4094 || !vlans_[vid].exists) {
    return Status::kNotFound;
  }
  if (vlans_[vid].members.any() || vlans_[vid].rif >= 0) return Status::kInUse;
  vlans_[vid].exists = false;
  fdb_.FlushVlan(static_cast<uint16_t>(vid));
  return Status::kOk;
}

Status VirtualAsic::CreateVlanMember(ObjectId vlan, ObjectId port, bool tagged, ObjectId* member) {
  const uint32_t vid = sai::IndexOf(vlan);
  const int p = PortIndex(port);
  if (sai::TypeOf(vlan) != ObjectType::kVlan || vid == 0 || vid > 4094 || !vlans_[vid].exists ||
      p < 0) {
    return Status::kInvalidArgument;
  }
  Vlan& v = vlans_[vid];
  if (v.members[static_cast<size_t>(p)]) return Status::kAlreadyExists;
  v.members.set(static_cast<size_t>(p));
  v.tagged.set(static_cast<size_t>(p), tagged);
  *member = sai::MakeObjectId(ObjectType::kVlanMember, vid * kMaxPorts + static_cast<uint32_t>(p));
  return Status::kOk;
}

Status VirtualAsic::RemoveVlanMember(ObjectId member) {
  if (sai::TypeOf(member) != ObjectType::kVlanMember) return Status::kInvalidArgument;
  const uint32_t vid = sai::IndexOf(member) / kMaxPorts;
  const uint32_t p = sai::IndexOf(member) % kMaxPorts;
  if (vid == 0 || vid > 4094 || p >= ports_.size() || !vlans_[vid].members[p]) {
    return Status::kNotFound;
  }
  vlans_[vid].members.reset(p);
  vlans_[vid].tagged.reset(p);
  fdb_.FlushPortVlan(static_cast<uint16_t>(p), static_cast<uint16_t>(vid));
  return Status::kOk;
}

Status VirtualAsic::CreateStaticFdbEntry(uint16_t vid, const MacAddress& mac, ObjectId port) {
  const int p = PortIndex(port);
  if (p < 0 || vid == 0 || vid > 4094 || mac.IsMulticast()) return Status::kInvalidArgument;
  return fdb_.AddStatic(vid, mac, static_cast<uint16_t>(p));
}

Status VirtualAsic::FlushFdb(ObjectId port) {
  if (port == sai::kNullObjectId) {
    fdb_.FlushAll();
    return Status::kOk;
  }
  const int p = PortIndex(port);
  if (p < 0) return Status::kInvalidArgument;
  fdb_.FlushPort(static_cast<uint16_t>(p));
  return Status::kOk;
}

Status VirtualAsic::CreateRouterInterface(const sai::RouterInterfaceAttrs& attrs, ObjectId* rif) {
  size_t slot = rifs_.size();
  for (size_t i = 0; i < rifs_.size(); ++i) {
    if (!rifs_[i].exists) {
      slot = i;
      break;
    }
  }
  if (slot == rifs_.size()) return Status::kTableFull;
  Rif r;
  r.exists = true;
  r.type = attrs.type;
  r.mac = attrs.mac.IsZero() ? switch_mac_ : attrs.mac;
  r.mtu = attrs.mtu;
  if (attrs.type == sai::RouterInterfaceType::kPort) {
    const int p = PortIndex(attrs.port);
    if (p < 0 || ports_[static_cast<size_t>(p)].mode != sai::PortMode::kRouted) {
      return Status::kInvalidArgument;
    }
    if (ports_[static_cast<size_t>(p)].rif >= 0) return Status::kAlreadyExists;
    r.port = static_cast<uint16_t>(p);
    ports_[static_cast<size_t>(p)].rif = static_cast<int>(slot);
  } else {
    if (attrs.vlan == 0 || attrs.vlan > 4094 || !vlans_[attrs.vlan].exists) {
      return Status::kInvalidArgument;
    }
    if (vlans_[attrs.vlan].rif >= 0) return Status::kAlreadyExists;
    r.vlan = attrs.vlan;
    vlans_[attrs.vlan].rif = static_cast<int>(slot);
  }
  rifs_[slot] = r;
  *rif = sai::MakeObjectId(ObjectType::kRouterInterface, static_cast<uint32_t>(slot));
  return Status::kOk;
}

Status VirtualAsic::RemoveRouterInterface(ObjectId rif) {
  const int ri = RifIndex(rif);
  if (ri < 0) return Status::kNotFound;
  Rif& r = rifs_[static_cast<size_t>(ri)];
  if (r.refs > 0) return Status::kInUse;
  if (r.type == sai::RouterInterfaceType::kPort) {
    ports_[r.port].rif = -1;
  } else {
    vlans_[r.vlan].rif = -1;
  }
  r = Rif{};
  return Status::kOk;
}

Status VirtualAsic::CreateNeighbor(ObjectId rif, uint32_t ip, const MacAddress& mac) {
  const int ri = RifIndex(rif);
  if (ri < 0 || mac.IsMulticast() || mac.IsZero()) return Status::kInvalidArgument;
  if (Neighbor* n = neighbors_.Find(ip)) {
    if (n->rif != ri) {
      --rifs_[n->rif].refs;
      ++rifs_[static_cast<size_t>(ri)].refs;
      n->rif = static_cast<uint16_t>(ri);
    }
    n->mac = mac;
    return Status::kOk;
  }
  const Status s = neighbors_.Insert(ip, Neighbor{static_cast<uint16_t>(ri), mac});
  if (s == Status::kOk) ++rifs_[static_cast<size_t>(ri)].refs;
  return s;
}

Status VirtualAsic::RemoveNeighbor(ObjectId rif, uint32_t ip) {
  const int ri = RifIndex(rif);
  const Neighbor* n = neighbors_.Find(ip);
  if (ri < 0 || n == nullptr || n->rif != ri) return Status::kNotFound;
  --rifs_[static_cast<size_t>(ri)].refs;
  neighbors_.Erase(ip);
  return Status::kOk;
}

Status VirtualAsic::CreateNextHop(ObjectId rif, uint32_t ip, ObjectId* next_hop) {
  const int ri = RifIndex(rif);
  if (ri < 0) return Status::kInvalidArgument;
  for (size_t i = 0; i < next_hops_.size(); ++i) {
    if (!next_hops_[i].exists) {
      next_hops_[i] = NextHop{true, static_cast<uint16_t>(ri), ip, 0};
      ++rifs_[static_cast<size_t>(ri)].refs;
      *next_hop = sai::MakeObjectId(ObjectType::kNextHop, static_cast<uint32_t>(i));
      return Status::kOk;
    }
  }
  return Status::kTableFull;
}

Status VirtualAsic::RemoveNextHop(ObjectId next_hop) {
  const int i = NextHopIndex(next_hop);
  if (i < 0) return Status::kNotFound;
  NextHop& nh = next_hops_[static_cast<size_t>(i)];
  if (nh.refs > 0) return Status::kInUse;
  --rifs_[nh.rif].refs;
  nh = NextHop{};
  return Status::kOk;
}

Status VirtualAsic::CreateNextHopGroup(ObjectId* group) {
  for (size_t i = 0; i < groups_.size(); ++i) {
    if (!groups_[i].exists) {
      groups_[i] = Group{};
      groups_[i].exists = true;
      *group = sai::MakeObjectId(ObjectType::kNextHopGroup, static_cast<uint32_t>(i));
      return Status::kOk;
    }
  }
  return Status::kTableFull;
}

Status VirtualAsic::RemoveNextHopGroup(ObjectId group) {
  const int gi = GroupIndex(group);
  if (gi < 0) return Status::kNotFound;
  Group& g = groups_[static_cast<size_t>(gi)];
  if (g.refs > 0) return Status::kInUse;
  for (uint32_t m : g.members) --next_hops_[m].refs;
  g = Group{};
  return Status::kOk;
}

Status VirtualAsic::AddNextHopGroupMember(ObjectId group, ObjectId next_hop) {
  const int gi = GroupIndex(group);
  const int ni = NextHopIndex(next_hop);
  if (gi < 0 || ni < 0) return Status::kInvalidArgument;
  Group& g = groups_[static_cast<size_t>(gi)];
  const uint32_t member = static_cast<uint32_t>(ni);
  if (std::find(g.members.begin(), g.members.end(), member) != g.members.end()) {
    return Status::kAlreadyExists;
  }
  g.members.push_back(member);
  ++next_hops_[member].refs;
  RefreshGroup(g);
  return Status::kOk;
}

Status VirtualAsic::RemoveNextHopGroupMember(ObjectId group, ObjectId next_hop) {
  const int gi = GroupIndex(group);
  const int ni = NextHopIndex(next_hop);
  if (gi < 0 || ni < 0) return Status::kInvalidArgument;
  Group& g = groups_[static_cast<size_t>(gi)];
  const auto it = std::find(g.members.begin(), g.members.end(), static_cast<uint32_t>(ni));
  if (it == g.members.end()) return Status::kNotFound;
  g.members.erase(it);
  --next_hops_[static_cast<size_t>(ni)].refs;
  RefreshGroup(g);
  return Status::kOk;
}

Status VirtualAsic::ResolveTarget(const sai::RouteAttrs& attrs, uint32_t* target) {
  if (attrs.action == sai::RouteAction::kDrop) {
    *target = EncodeTarget(kTargetDrop, 0);
    return Status::kOk;
  }
  if (attrs.action != sai::RouteAction::kForward) return Status::kInvalidArgument;
  switch (sai::TypeOf(attrs.next_hop)) {
    case ObjectType::kNextHop: {
      const int i = NextHopIndex(attrs.next_hop);
      if (i < 0) return Status::kInvalidArgument;
      ++next_hops_[static_cast<size_t>(i)].refs;
      *target = EncodeTarget(kTargetNextHop, static_cast<uint32_t>(i));
      return Status::kOk;
    }
    case ObjectType::kNextHopGroup: {
      const int i = GroupIndex(attrs.next_hop);
      if (i < 0) return Status::kInvalidArgument;
      ++groups_[static_cast<size_t>(i)].refs;
      *target = EncodeTarget(kTargetGroup, static_cast<uint32_t>(i));
      return Status::kOk;
    }
    case ObjectType::kRouterInterface: {
      const int i = RifIndex(attrs.next_hop);
      if (i < 0) return Status::kInvalidArgument;
      ++rifs_[static_cast<size_t>(i)].refs;
      *target = EncodeTarget(kTargetRif, static_cast<uint32_t>(i));
      return Status::kOk;
    }
    default:
      return Status::kInvalidArgument;
  }
}

void VirtualAsic::ReleaseTarget(uint32_t target) {
  const uint32_t index = target & 0x3fffff;
  switch (target >> 22) {
    case kTargetNextHop:
      --next_hops_[index].refs;
      break;
    case kTargetGroup:
      --groups_[index].refs;
      break;
    case kTargetRif:
      --rifs_[index].refs;
      break;
    default:
      break;
  }
}

Status VirtualAsic::CreateRoute(const Ipv4Prefix& prefix, const sai::RouteAttrs& attrs) {
  if (prefix.len > 32) return Status::kInvalidArgument;
  if (attrs.action == sai::RouteAction::kTrapToCpu) {
    const int ri = RifIndex(attrs.next_hop);
    if (prefix.len != 32 || ri < 0) return Status::kInvalidArgument;
    const Status s = local_ips_.Insert(prefix.addr, static_cast<uint16_t>(ri));
    if (s == Status::kOk) ++rifs_[static_cast<size_t>(ri)].refs;
    return s;
  }
  if (lpm_.Get(prefix)) return Status::kAlreadyExists;
  uint32_t target = 0;
  Status s = ResolveTarget(attrs, &target);
  if (s != Status::kOk) return s;
  s = lpm_.Insert(prefix, target);
  if (s != Status::kOk) ReleaseTarget(target);
  return s;
}

Status VirtualAsic::SetRoute(const Ipv4Prefix& prefix, const sai::RouteAttrs& attrs) {
  if (attrs.action == sai::RouteAction::kTrapToCpu) return Status::kNotSupported;
  const auto old = lpm_.Get(prefix);
  if (!old) return Status::kNotFound;
  uint32_t target = 0;
  Status s = ResolveTarget(attrs, &target);
  if (s != Status::kOk) return s;
  s = lpm_.Insert(prefix, target);
  if (s != Status::kOk) {
    ReleaseTarget(target);
    return s;
  }
  ReleaseTarget(*old);
  return Status::kOk;
}

Status VirtualAsic::RemoveRoute(const Ipv4Prefix& prefix) {
  if (prefix.len == 32) {
    if (const uint16_t* owner = local_ips_.Find(prefix.addr)) {
      --rifs_[*owner].refs;
      local_ips_.Erase(prefix.addr);
      return Status::kOk;
    }
  }
  const auto old = lpm_.Get(prefix);
  if (!old) return Status::kNotFound;
  lpm_.Remove(prefix);
  ReleaseTarget(*old);
  return Status::kOk;
}

Status VirtualAsic::CreateAclEntry(const AclRule& rule, ObjectId* entry) {
  if (rule.action == AclAction::kSetTc && rule.set_tc >= kNumQueues) {
    return Status::kInvalidArgument;
  }
  const Status s = acl_.AddRule(rule);
  if (s == Status::kOk) *entry = sai::MakeObjectId(ObjectType::kAclEntry, rule.seq);
  return s;
}

Status VirtualAsic::RemoveAclEntry(ObjectId entry) {
  if (sai::TypeOf(entry) != ObjectType::kAclEntry) return Status::kInvalidArgument;
  return acl_.RemoveRule(sai::IndexOf(entry));
}

Status VirtualAsic::SetDscpToTc(uint8_t dscp, uint8_t tc) {
  if (dscp >= 64 || tc >= kNumQueues) return Status::kInvalidArgument;
  dscp_to_tc_[dscp] = tc;
  return Status::kOk;
}

Status VirtualAsic::SetTrapPolicer(sai::TrapType trap, uint64_t pps, uint64_t burst) {
  if (trap >= sai::TrapType::kCount) return Status::kInvalidArgument;
  traps_[static_cast<size_t>(trap)].policer =
      pps == 0 ? SrTcmPolicer() : SrTcmPolicer(pps, burst == 0 ? pps : burst, 0, clock_->Now());
  return Status::kOk;
}

bool VirtualAsic::GetPortOperStatus(ObjectId port) const {
  const int p = PortIndex(port);
  return p >= 0 && ports_[static_cast<size_t>(p)].oper_up;
}

sai::PortCounters VirtualAsic::GetPortCounters(ObjectId port) const {
  const int p = PortIndex(port);
  return p >= 0 ? ports_[static_cast<size_t>(p)].counters : sai::PortCounters{};
}

QueueCounters VirtualAsic::GetQueueCounters(ObjectId port, uint8_t queue) const {
  const int p = PortIndex(port);
  if (p < 0 || queue >= kNumQueues) return QueueCounters{};
  return ports_[static_cast<size_t>(p)].queues.counters(queue);
}

uint64_t VirtualAsic::GetDropCount(DropReason reason) const {
  return reason < DropReason::kCount ? drops_[static_cast<size_t>(reason)] : 0;
}

sai::TrapCounters VirtualAsic::GetTrapCounters(sai::TrapType trap) const {
  return trap < sai::TrapType::kCount ? traps_[static_cast<size_t>(trap)].counters
                                      : sai::TrapCounters{};
}

std::vector<sai::ResourceUsage> VirtualAsic::GetResources() const {
  const auto count = [](const auto& v) {
    return static_cast<size_t>(
        std::count_if(v.begin(), v.end(), [](const auto& x) { return x.exists; }));
  };
  return {
      {"fdb_entry", fdb_.size(), fdb_.capacity()},
      {"neighbor", neighbors_.size(), neighbors_.capacity()},
      {"ipv4_route", lpm_.size(), lpm_.max_routes()},
      {"lpm_node", lpm_.nodes_in_use(), lpm_.max_nodes()},
      {"next_hop", count(next_hops_), next_hops_.size()},
      {"next_hop_group", count(groups_), groups_.size()},
      {"router_interface", count(rifs_), rifs_.size()},
      {"acl_entry", acl_.entries_used(), acl_.capacity()},
      {"packet_buffer", pool_.capacity() - pool_.available(), pool_.capacity()},
  };
}

std::vector<sai::AclRuleStats> VirtualAsic::GetAclStats() const {
  std::vector<sai::AclRuleStats> out;
  acl_.ForEachRule([&](const AclRule& rule, uint64_t hits, size_t entries) {
    out.push_back(sai::AclRuleStats{rule.seq, hits, entries});
  });
  return out;
}

void VirtualAsic::ForEachFdbEntry(const std::function<void(const sai::FdbView&)>& fn) const {
  fdb_.ForEach([&](const FdbKey& k, const FdbEntry& e) {
    fn(sai::FdbView{k.vlan, k.mac, e.port, e.is_static});
  });
}

Status VirtualAsic::ClearCounters() {
  for (Port& p : ports_) {
    p.counters = sai::PortCounters{};
    p.queues.ClearCounters();
  }
  drops_.fill(0);
  for (TrapState& t : traps_) t.counters = sai::TrapCounters{};
  return Status::kOk;
}

}  // namespace nanonos
