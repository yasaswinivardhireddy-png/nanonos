// Deterministic simulation of a 2-leaf / 2-spine Clos fabric: four complete
// SwitchNodes (ASIC pipeline, orchagent, BGP, LLDP) connected by simulated
// wires, with BGP sessions on an in-memory transport and two hosts.
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <gtest/gtest.h>

#include "proto/memory_transport.h"
#include "test_util.h"

namespace nanonos {
namespace {

using testing::ArpFrame;
using testing::Flow;
using testing::FlowFrame;
using testing::Ip;
using testing::Mac;
using testing::Parse;
using testing::Pfx;

constexpr const char* kLeaf1 = R"(
hostname leaf1
lldp
  tx-interval 1
interface Ethernet0
  switchport access vlan 10
interface Ethernet4
  ip address 10.0.0.0/31
interface Ethernet5
  ip address 10.0.1.0/31
interface Vlan10
  ip address 10.1.1.1/24
router bgp 65001
  timers 1 3
  maximum-paths 4
  network 10.1.1.0/24
  neighbor 10.0.0.1 remote-as 65100
  neighbor 10.0.1.1 remote-as 65100
)";

constexpr const char* kLeaf2 = R"(
hostname leaf2
lldp
  tx-interval 1
interface Ethernet0
  switchport access vlan 10
interface Ethernet4
  ip address 10.0.2.0/31
interface Ethernet5
  ip address 10.0.3.0/31
interface Vlan10
  ip address 10.2.2.1/24
router bgp 65002
  timers 1 3
  maximum-paths 4
  network 10.2.2.0/24
  neighbor 10.0.2.1 remote-as 65100
  neighbor 10.0.3.1 remote-as 65100
)";

constexpr const char* kSpine1 = R"(
hostname spine1
lldp
  tx-interval 1
interface Ethernet0
  ip address 10.0.0.1/31
interface Ethernet1
  ip address 10.0.2.1/31
router bgp 65100
  timers 1 3
  neighbor 10.0.0.0 remote-as 65001
  neighbor 10.0.2.0 remote-as 65002
)";

constexpr const char* kSpine2 = R"(
hostname spine2
lldp
  tx-interval 1
interface Ethernet0
  ip address 10.0.1.1/31
interface Ethernet1
  ip address 10.0.3.1/31
router bgp 65100
  timers 1 3
  neighbor 10.0.1.0 remote-as 65001
  neighbor 10.0.3.0 remote-as 65002
)";

class Fabric {
 public:
  enum { kLeaf1Id, kLeaf2Id, kSpine1Id, kSpine2Id };
  struct Host {
    int sw;
    uint16_t port;
    MacAddress mac;
    uint32_t ip;
    uint32_t gateway;
    std::vector<std::vector<uint8_t>> inbox;
  };

  Fabric() {
    AddSwitch(kLeaf1, {Ip("10.0.0.0"), Ip("10.0.1.0")});
    AddSwitch(kLeaf2, {Ip("10.0.2.0"), Ip("10.0.3.0")});
    AddSwitch(kSpine1, {Ip("10.0.0.1"), Ip("10.0.2.1")});
    AddSwitch(kSpine2, {Ip("10.0.1.1"), Ip("10.0.3.1")});
    Cable(kLeaf1Id, 4, kSpine1Id, 0);
    Cable(kLeaf1Id, 5, kSpine2Id, 0);
    Cable(kLeaf2Id, 4, kSpine1Id, 1);
    Cable(kLeaf2Id, 5, kSpine2Id, 1);
    hosts.push_back(Host{kLeaf1Id, 0, Mac(0x0200000001aa), Ip("10.1.1.10"), Ip("10.1.1.1"), {}});
    hosts.push_back(Host{kLeaf2Id, 0, Mac(0x0200000002bb), Ip("10.2.2.20"), Ip("10.2.2.1"), {}});
  }

  SwitchNode& node(int i) { return *switches_[static_cast<size_t>(i)]; }

  void Run(TimeUs duration) {
    for (TimeUs t = 0; t < duration; t += 10 * kUsPerMs) {
      clock.Advance(10 * kUsPerMs);
      for (auto& s : switches_) s->Tick();
      bgp.Pump();
      Deliver();
    }
  }

  // Host sends one frame into its access port.
  void Send(Host& h, const std::vector<uint8_t>& frame) {
    node(h.sw).ReceiveFrame(h.port, frame);
    node(h.sw).Drain();
    Deliver();
  }

  // Hosts resolve their gateway, as a real host's first packet would.
  void ArpForGateways() {
    for (Host& h : hosts) {
      Send(h,
           ArpFrame(MacAddress::Broadcast(), kArpOpRequest, h.mac, h.ip, MacAddress{}, h.gateway));
    }
  }

  void SetLink(int a, uint16_t pa, int b, uint16_t pb, bool up) {
    link_up_[{a, pa}] = up;
    link_up_[{b, pb}] = up;
    node(a).SetPortOperStatus(pa, up);
    node(b).SetPortOperStatus(pb, up);
    const auto* ra = node(a).orch().RifByName("Ethernet" + std::to_string(pa));
    const auto* rb = node(b).orch().RifByName("Ethernet" + std::to_string(pb));
    bgp.SetLinkUp(ra->address.ip, rb->address.ip, up);
    Deliver();
  }

  // Frames of UDP traffic received by a host since the last call.
  std::vector<ParsedPacket> TakeUdp(Host& h) {
    std::vector<ParsedPacket> out;
    for (const auto& f : h.inbox) {
      ParsedPacket p;
      if (ParseFrame(f, &p) == ParseStatus::kOk && p.is_ipv4() && p.ip_proto == kIpProtoUdp) {
        out.push_back(p);
      }
    }
    h.inbox.clear();
    return out;
  }

  ManualClock clock;
  bgp::MemoryNetwork bgp;
  std::vector<Host> hosts;

 private:
  void AddSwitch(const char* config_text, std::vector<uint32_t> addresses) {
    const int id = static_cast<int>(switches_.size());
    bgp::MemoryNetwork::Endpoint* endpoint = bgp.AddEndpoint(std::move(addresses));
    SwitchNode::Platform p;
    p.clock = &clock;
    p.bgp_transport = endpoint;
    p.asic.num_ports = 8;
    p.transmit = [this, id](uint16_t port, std::span<const uint8_t> frame) {
      wire_.emplace_back(id, port, std::vector<uint8_t>(frame.begin(), frame.end()));
    };
    switches_.push_back(std::make_unique<SwitchNode>(std::move(p)));
    ConfigError error;
    const auto config = ParseConfig(config_text, &error);
    EXPECT_TRUE(config.has_value()) << error.message;
    std::vector<std::string> errors;
    EXPECT_TRUE(switches_.back()->Configure(*config, &errors));
    endpoint->SetHandler(switches_.back()->bgp());
  }

  void Cable(int a, uint16_t pa, int b, uint16_t pb) {
    peer_[{a, pa}] = {b, pb};
    peer_[{b, pb}] = {a, pa};
    link_up_[{a, pa}] = true;
    link_up_[{b, pb}] = true;
  }

  void Deliver() {
    while (!wire_.empty()) {
      auto [sw, port, frame] = std::move(wire_.front());
      wire_.pop_front();
      const auto up = link_up_.find({sw, port});
      if (up != link_up_.end() && !up->second) continue;
      const auto peer = peer_.find({sw, port});
      if (peer != peer_.end()) {
        const auto [other, other_port] = peer->second;
        node(other).ReceiveFrame(other_port, frame);
        node(other).Drain();
        continue;
      }
      for (Host& h : hosts) {
        if (h.sw == sw && h.port == port) ToHost(h, frame);
      }
    }
  }

  void ToHost(Host& h, const std::vector<uint8_t>& frame) {
    ParsedPacket p;
    if (ParseFrame(frame, &p) != ParseStatus::kOk) return;
    if (p.is_arp() && p.arp_op == kArpOpRequest && p.arp_tpa == h.ip) {
      node(h.sw).ReceiveFrame(h.port,
                              ArpFrame(p.arp_sha, kArpOpReply, h.mac, h.ip, p.arp_sha, p.arp_spa));
      node(h.sw).Drain();
      return;
    }
    h.inbox.push_back(frame);
  }

  std::vector<std::unique_ptr<SwitchNode>> switches_;
  std::map<std::pair<int, uint16_t>, std::pair<int, uint16_t>> peer_;
  std::map<std::pair<int, uint16_t>, bool> link_up_;
  std::deque<std::tuple<int, uint16_t, std::vector<uint8_t>>> wire_;
};

// Sends `count` UDP flows from one host to another and returns how many
// arrived, checking every delivered packet.
size_t SendFlows(Fabric& f, int from, int to, uint16_t count, uint16_t base_port) {
  Fabric::Host& src = f.hosts[static_cast<size_t>(from)];
  Fabric::Host& dst = f.hosts[static_cast<size_t>(to)];
  const MacAddress gateway_mac = f.node(src.sw).orch().switch_mac();
  for (uint16_t i = 0; i < count; ++i) {
    Flow flow{gateway_mac, src.mac, src.ip, dst.ip};
    flow.src_port = static_cast<uint16_t>(base_port + i);
    f.Send(src, FlowFrame(flow));
  }
  const auto received = f.TakeUdp(dst);
  for (const ParsedPacket& p : received) {
    EXPECT_EQ(p.ttl, 61);  // three routed hops: leaf, spine, leaf
    EXPECT_EQ(p.dst_mac, dst.mac);
    EXPECT_EQ(p.src_ip, src.ip);
  }
  return received.size();
}

uint64_t TxPackets(SwitchNode& n, uint16_t port) {
  return n.asic().GetPortCounters(n.asic().GetPortId(port)).tx_pkts;
}

TEST(FabricSimTest, ConvergesForwardsAcrossBothSpinesAndFailsOver) {
  Fabric f;
  f.Run(3 * kUsPerSec);

  // Every BGP session is up and leaf1 has two equal-cost paths to leaf2's subnet.
  for (int i = 0; i < 4; ++i) {
    for (const bgp::NeighborStatus& s : f.node(i).bgp()->Neighbors()) {
      EXPECT_EQ(s.state, bgp::SessionState::kEstablished) << i << " " << Ipv4ToString(s.address);
    }
  }
  bool found = false;
  for (const RouteInfo& r : f.node(Fabric::kLeaf1Id).orch().Routes()) {
    if (r.prefix == Pfx("10.2.2.0/24")) {
      found = true;
      EXPECT_EQ(r.source, RouteSource::kBgp);
      EXPECT_EQ(r.state, RouteState::kOffloaded);
      EXPECT_EQ(r.next_hops, (std::vector<uint32_t>{Ip("10.0.0.1"), Ip("10.0.1.1")}));
    }
  }
  ASSERT_TRUE(found);

  // LLDP shows the cabling.
  const auto& lldp = f.node(Fabric::kLeaf1Id).lldp().neighbors();
  ASSERT_EQ(lldp.count(4), 1u);
  EXPECT_EQ(lldp.at(4).info.system_name, "spine1");
  EXPECT_EQ(lldp.at(5).info.system_name, "spine2");
  EXPECT_EQ(lldp.at(5).info.port_id, "Ethernet0");

  f.ArpForGateways();
  // First packet to h2 makes leaf2 ARP for it (glean); afterwards traffic flows.
  SendFlows(f, 0, 1, 1, 1);
  f.Run(100 * kUsPerMs);

  const uint64_t s1_before = TxPackets(f.node(Fabric::kSpine1Id), 1);
  const uint64_t s2_before = TxPackets(f.node(Fabric::kSpine2Id), 1);
  EXPECT_EQ(SendFlows(f, 0, 1, 400, 1000), 400u);
  const uint64_t via_s1 = TxPackets(f.node(Fabric::kSpine1Id), 1) - s1_before;
  const uint64_t via_s2 = TxPackets(f.node(Fabric::kSpine2Id), 1) - s2_before;
  EXPECT_EQ(via_s1 + via_s2, 400u);
  EXPECT_GT(via_s1, 120u);  // ECMP spreads flows over both spines
  EXPECT_GT(via_s2, 120u);
  EXPECT_EQ(SendFlows(f, 1, 0, 400, 1000), 400u);  // and the reverse path works

  // Local failure (leaf1 <-> spine1): leaf1 prunes the dead next hop in the
  // data plane, so not a single packet is lost even before BGP reconverges.
  f.SetLink(Fabric::kLeaf1Id, 4, Fabric::kSpine1Id, 0, false);
  EXPECT_EQ(SendFlows(f, 0, 1, 400, 2000), 400u);
  // Remote side: leaf2 only stops using spine1 once spine1's withdrawal
  // arrives over BGP, which takes one tick of the event loop.
  f.Run(50 * kUsPerMs);
  EXPECT_EQ(SendFlows(f, 1, 0, 400, 2000), 400u);
  for (const RouteInfo& r : f.node(Fabric::kLeaf2Id).orch().Routes()) {
    if (r.prefix == Pfx("10.1.1.0/24")) {
      EXPECT_EQ(r.next_hops, (std::vector<uint32_t>{Ip("10.0.3.1")}));
    }
  }

  // Repair: sessions come back and ECMP is restored.
  f.SetLink(Fabric::kLeaf1Id, 4, Fabric::kSpine1Id, 0, true);
  f.Run(4 * kUsPerSec);
  for (const RouteInfo& r : f.node(Fabric::kLeaf1Id).orch().Routes()) {
    if (r.prefix == Pfx("10.2.2.0/24")) EXPECT_EQ(r.next_hops.size(), 2u);
  }
  EXPECT_EQ(SendFlows(f, 0, 1, 200, 3000), 200u);
  EXPECT_EQ(SendFlows(f, 1, 0, 200, 3000), 200u);
}

}  // namespace
}  // namespace nanonos
