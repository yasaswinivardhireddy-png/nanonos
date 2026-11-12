#include <algorithm>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "common/byte_order.h"
#include "proto/lldp.h"
#include "test_util.h"

namespace nanonos {
namespace {

using testing::ArpFrame;
using testing::Flow;
using testing::FlowFrame;
using testing::Ip;
using testing::Mac;
using testing::Parse;
using testing::TestSwitch;

const MacAddress kRouterMac = Mac(0x0200000000aa);
const MacAddress kH1 = Mac(0x020000000001);
const MacAddress kH2 = Mac(0x020000000002);
const MacAddress kH3 = Mac(0x020000000003);
const MacAddress kPeer4 = Mac(0x0200000000f4);
const MacAddress kPeer5 = Mac(0x0200000000f5);

constexpr const char* kL2Config = R"(
hostname sw1
switch-mac 02:00:00:00:00:aa
no lldp
vlan 10,20
interface Ethernet0
  switchport access vlan 10
interface Ethernet1
  switchport access vlan 10
interface Ethernet2
  switchport access vlan 20
interface Ethernet3
  switchport mode trunk
  switchport trunk allowed vlan 10,20
)";

TEST(PipelineTest, FloodsUnknownThenForwardsLearnedUnicast) {
  TestSwitch sw(kL2Config);
  sw.Rx(0, FlowFrame(Flow{kH2, kH1, Ip("10.1.1.1"), Ip("10.1.1.2")}));
  // Unknown unicast floods within VLAN 10: port 1 untagged, trunk port 3 tagged.
  ASSERT_EQ(sw.Take(-1).size(), 2u);
  sw.Rx(0, FlowFrame(Flow{kH2, kH1, Ip("10.1.1.1"), Ip("10.1.1.2")}));
  auto p1 = sw.Take(1);
  auto p3 = sw.Take(3);
  ASSERT_EQ(p1.size(), 1u);
  ASSERT_EQ(p3.size(), 1u);
  EXPECT_FALSE(Parse(p1[0]).vlan_tagged);
  EXPECT_TRUE(Parse(p3[0]).vlan_tagged);
  EXPECT_EQ(Parse(p3[0]).vlan_id, 10);
  EXPECT_TRUE(sw.Take(2).empty());  // VLAN 20 is isolated

  // The reply is unicast straight back to the learned port.
  sw.Rx(1, FlowFrame(Flow{kH1, kH2, Ip("10.1.1.2"), Ip("10.1.1.1")}));
  auto back = sw.Take(-1);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(sw.sent.size(), 0u);
  EXPECT_EQ(Parse(back[0]).dst_mac, kH1);
}

TEST(PipelineTest, TrunkTagsAndFiltersVlans) {
  TestSwitch sw(kL2Config);
  Flow f{kH3, kH2, Ip("10.2.0.1"), Ip("10.2.0.2")};
  f.vlan = 20;
  sw.Rx(3, FlowFrame(f));
  auto to_access = sw.Take(2);
  ASSERT_EQ(to_access.size(), 1u);
  EXPECT_FALSE(Parse(to_access[0]).vlan_tagged);  // tag removed toward the access port
  EXPECT_EQ(Parse(to_access[0]).src_ip, Ip("10.2.0.1"));

  f.vlan = 30;  // not allowed on the trunk
  sw.Rx(3, FlowFrame(f));
  EXPECT_TRUE(sw.Take(-1).empty());
  EXPECT_EQ(sw.Drops(sai::DropReason::kVlanFilter), 1u);

  f.vlan = 20;  // tagged frames on an access port are dropped
  sw.Rx(0, FlowFrame(f));
  EXPECT_EQ(sw.Drops(sai::DropReason::kVlanFilter), 2u);
}

TEST(PipelineTest, PortSecurityAndStormControl) {
  TestSwitch sw(R"(
switch-mac 02:00:00:00:00:aa
no lldp
interface Ethernet0
  switchport access vlan 10
  port-security max-mac 2
  storm-control broadcast pps 100
interface Ethernet1
  switchport access vlan 10
)");
  for (uint64_t m = 1; m <= 3; ++m) {
    sw.Rx(0, FlowFrame(Flow{kH3, Mac(0x020000000100 + m), Ip("1.1.1.1"), Ip("1.1.1.2")}));
  }
  EXPECT_EQ(sw.Drops(sai::DropReason::kPortSecurity), 1u);
  EXPECT_EQ(sw.Take(1).size(), 2u);

  // 1000 broadcasts in one second against a 100 pps limit (burst 10).
  for (int i = 0; i < 1000; ++i) {
    sw.clock.Advance(kUsPerMs);
    sw.Rx(0, FlowFrame(Flow{MacAddress::Broadcast(), Mac(0x020000000101), Ip("1.1.1.1"),
                            Ip("1.1.1.255")}));
  }
  const size_t forwarded = sw.Take(1).size();
  EXPECT_NEAR(static_cast<double>(forwarded), 110.0, 5.0);
  EXPECT_EQ(sw.Drops(sai::DropReason::kStormControl), 1000u - forwarded);
}

constexpr const char* kRouterConfig = R"(
hostname r1
switch-mac 02:00:00:00:00:aa
no lldp
interface Ethernet0
  switchport access vlan 10
interface Ethernet1
  switchport access vlan 10
interface Ethernet4
  ip address 10.0.0.1/31
interface Ethernet5
  ip address 10.0.1.1/31
interface Vlan10
  ip address 10.1.1.1/24
qos dscp 10 tc 6
ip route 10.9.0.0/16 10.0.0.0 10.0.1.0
ip route 10.8.0.0/16 blackhole
copp arp pps 100 burst 20
access-list
  rule 10 deny tcp dst 10.9.0.0/16 dport 23
)";

// Answers the switch's ARP requests on the routed ports so next hops resolve.
void ResolveNextHops(TestSwitch& sw) {
  sw.Advance(20 * kUsPerMs);
  for (auto& [port, frame] : sw.sent) {
    const ParsedPacket p = Parse(frame);
    if (!p.is_arp() || p.arp_op != kArpOpRequest) continue;
    const MacAddress peer = port == 4 ? kPeer4 : kPeer5;
    sw.node->ReceiveFrame(
        port, ArpFrame(kRouterMac, kArpOpReply, peer, p.arp_tpa, kRouterMac, p.arp_spa));
  }
  sw.sent.clear();
  sw.node->Drain();
}

TEST(PipelineTest, AnswersArpAndPingForTheGatewayAddress) {
  TestSwitch sw(kRouterConfig);
  sw.Rx(0, ArpFrame(MacAddress::Broadcast(), kArpOpRequest, kH1, Ip("10.1.1.10"), MacAddress{},
                    Ip("10.1.1.1")));
  auto replies = sw.Take(0);
  ASSERT_EQ(replies.size(), 1u);
  const ParsedPacket reply = Parse(replies[0]);
  EXPECT_EQ(reply.arp_op, kArpOpReply);
  EXPECT_EQ(reply.arp_sha, kRouterMac);
  EXPECT_EQ(reply.arp_spa, Ip("10.1.1.1"));
  EXPECT_EQ(sw.Take(1).size(), 1u);  // the request is still flooded in the VLAN

  Flow ping{kRouterMac, kH1, Ip("10.1.1.10"), Ip("10.1.1.1")};
  ping.proto = kIpProtoIcmp;
  sw.Rx(0, FlowFrame(ping));
  auto echo = sw.Take(0);
  ASSERT_EQ(echo.size(), 1u);
  const ParsedPacket e = Parse(echo[0]);
  EXPECT_EQ(e.icmp_type, 0);
  EXPECT_EQ(e.dst_ip, Ip("10.1.1.10"));
  EXPECT_EQ(e.src_ip, Ip("10.1.1.1"));
  EXPECT_EQ(sw.node->asic().GetTrapCounters(sai::TrapType::kIcmpToMe).packets, 1u);
}

TEST(PipelineTest, RoutesWithRewriteGleansAndBalancesAcrossEcmp) {
  TestSwitch sw(kRouterConfig);
  ResolveNextHops(sw);
  EXPECT_EQ(sw.node->orch().Neighbors().size(), 2u);

  // 2000 flows from h1 to 10.9.0.0/16 split across Ethernet4 and Ethernet5.
  size_t on4 = 0;
  size_t on5 = 0;
  for (uint16_t i = 0; i < 2000; ++i) {
    Flow f{kRouterMac, kH1, Ip("10.1.1.10"), Ip("10.9.1.1")};
    f.src_port = static_cast<uint16_t>(10000 + i);
    sw.Rx(0, FlowFrame(f));
  }
  for (auto& [port, frame] : sw.sent) {
    const ParsedPacket p = Parse(frame);  // checksum verified by the parser
    EXPECT_EQ(p.ttl, 63);
    EXPECT_EQ(p.src_mac, kRouterMac);
    EXPECT_EQ(p.dst_mac, port == 4 ? kPeer4 : kPeer5);
    (port == 4 ? on4 : on5) += 1;
  }
  sw.sent.clear();
  EXPECT_EQ(on4 + on5, 2000u);
  EXPECT_NEAR(static_cast<double>(on4) / 2000.0, 0.5, 0.06);

  // Link down: the data plane prunes the dead member at once, and the
  // control plane then rewrites the route to the surviving next hop.
  sw.node->SetPortOperStatus(4, false);
  for (uint16_t i = 0; i < 500; ++i) {
    Flow f{kRouterMac, kH1, Ip("10.1.1.10"), Ip("10.9.1.1")};
    f.src_port = static_cast<uint16_t>(10000 + i);
    sw.Rx(0, FlowFrame(f));
  }
  EXPECT_EQ(sw.Take(5).size(), 500u);
  EXPECT_TRUE(sw.sent.empty());

  // Unresolved host in a connected subnet: drop, then ARP for it (glean).
  sw.Rx(5, FlowFrame(Flow{kRouterMac, kPeer5, Ip("10.9.9.9"), Ip("10.1.1.77")}));
  EXPECT_EQ(sw.Drops(sai::DropReason::kNeighborMiss), 1u);
  sw.Advance(10 * kUsPerMs);
  bool asked = false;
  for (auto& [port, frame] : sw.sent) {
    const ParsedPacket p = Parse(frame);
    asked |= port <= 1 && p.is_arp() && p.arp_op == kArpOpRequest && p.arp_tpa == Ip("10.1.1.77");
  }
  EXPECT_TRUE(asked);
}

TEST(PipelineTest, DropReasonsAreCounted) {
  TestSwitch sw(kRouterConfig);
  ResolveNextHops(sw);
  Flow f{kRouterMac, kH1, Ip("10.1.1.10"), Ip("10.9.1.1")};
  f.ttl = 1;
  sw.Rx(0, FlowFrame(f));
  EXPECT_EQ(sw.Drops(sai::DropReason::kTtlExpired), 1u);
  f.ttl = 64;
  f.dst_ip = Ip("172.16.0.1");
  sw.Rx(0, FlowFrame(f));
  EXPECT_EQ(sw.Drops(sai::DropReason::kNoRoute), 1u);
  f.dst_ip = Ip("10.8.0.1");
  sw.Rx(0, FlowFrame(f));
  EXPECT_EQ(sw.Drops(sai::DropReason::kBlackhole), 1u);
  f.dst_ip = Ip("10.9.0.1");
  f.proto = kIpProtoTcp;
  f.dst_port = 23;
  sw.Rx(0, FlowFrame(f));
  EXPECT_EQ(sw.Drops(sai::DropReason::kAclDeny), 1u);
  EXPECT_TRUE(sw.Take(-1).empty());
  const std::string drops = sw.node->Execute("show drops");
  EXPECT_NE(drops.find("acl_deny"), std::string::npos);
  EXPECT_NE(drops.find("ttl_expired"), std::string::npos);
}

TEST(PipelineTest, CoppPolicesArpFloods) {
  TestSwitch sw(kRouterConfig);
  // 1000 ARP requests for the gateway in one second; ARP is policed to 100 pps, burst 20.
  for (int i = 0; i < 1000; ++i) {
    sw.clock.Advance(kUsPerMs);
    sw.Rx(0, ArpFrame(MacAddress::Broadcast(), kArpOpRequest, kH1, Ip("10.1.1.10"), MacAddress{},
                      Ip("10.1.1.1")));
  }
  const sai::TrapCounters c = sw.node->asic().GetTrapCounters(sai::TrapType::kArp);
  EXPECT_NEAR(static_cast<double>(c.packets), 120.0, 5.0);
  EXPECT_EQ(c.packets + c.policed, 1000u);
}

TEST(PipelineTest, DscpSelectsTheQueueAndWredMarksEcn) {
  TestSwitch sw(R"(
switch-mac 02:00:00:00:00:aa
no lldp
interface Ethernet0
  switchport access vlan 10
interface Ethernet4
  ip address 10.0.0.1/31
  qos shaper 10m
  qos wred queue 0 min 3000 max 6000 probability 100 ecn
interface Vlan10
  ip address 10.1.1.1/24
qos dscp 10 tc 6
ip route 10.9.0.0/16 10.0.0.0
)");
  ResolveNextHops(sw);
  Flow f{kRouterMac, kH1, Ip("10.1.1.10"), Ip("10.9.1.1")};
  f.dscp = 10;
  sw.Rx(0, FlowFrame(f));
  const sai::ObjectId port4 = sw.node->asic().GetPortId(4);
  EXPECT_EQ(sw.node->asic().GetQueueCounters(port4, 6).enq_pkts, 1u);

  // A burst of ECN-capable traffic into a 10 Mb/s port builds a queue.
  f.dscp = 0;
  f.ecn = 2;
  f.payload = 900;
  for (int i = 0; i < 60; ++i) sw.Rx(0, FlowFrame(f));
  sw.Advance(200 * kUsPerMs);
  size_t marked = 0;
  for (auto& frame : sw.Take(4)) marked += Parse(frame).ecn == kEcnCe ? 1 : 0;
  EXPECT_GT(marked, 40u);
  EXPECT_EQ(sw.node->asic().GetQueueCounters(port4, 0).ecn_marked, marked);
  EXPECT_EQ(sw.node->asic().GetQueueCounters(port4, 0).wred_drops, 0u);
}

TEST(PipelineTest, LldpIsTrappedNotForwarded) {
  TestSwitch sw(R"(
hostname leaf9
interface Ethernet0
  switchport access vlan 10
interface Ethernet1
  switchport access vlan 10
)");
  lldp::Info info;
  info.system_name = "spine7";
  info.port_id = "Ethernet12";
  uint8_t frame[512];
  const size_t len = lldp::BuildFrame(frame, Mac(0x0200000000c7), Mac(0x0200000000c7), info);
  sw.Rx(0, std::vector<uint8_t>(frame, frame + len));
  EXPECT_TRUE(sw.Take(1).empty());
  ASSERT_EQ(sw.node->lldp().neighbors().count(0), 1u);
  EXPECT_NE(sw.node->Execute("show lldp neighbors").find("spine7"), std::string::npos);
  // The switch announces itself on its own ports.
  sw.Advance(20 * kUsPerMs);
  bool announced = false;
  for (auto& f : sw.Take(1)) {
    lldp::Info out;
    announced |= lldp::ParseFrame(f, &out) && out.system_name == "leaf9";
  }
  EXPECT_TRUE(announced);
}

TEST(PipelineTest, RoutesRejectedWithTableFullAreRetried) {
  VirtualAsic::Options small;
  small.lpm_routes = 4;  // two connected subnets + two more routes fit
  TestSwitch sw(R"(
switch-mac 02:00:00:00:00:aa
no lldp
interface Ethernet0
  switchport access vlan 10
interface Ethernet4
  ip address 10.0.0.1/31
interface Vlan10
  ip address 10.1.1.1/24
ip route 10.7.0.0/16 10.0.0.0
ip route 10.8.0.0/16 10.0.0.0
ip route 10.9.0.0/16 10.0.0.0
)",
                8, nullptr, small);
  std::string routes = sw.node->Execute("show ip route");
  EXPECT_NE(routes.find("S! 10.9.0.0/16"), std::string::npos) << routes;
  EXPECT_NE(sw.node->Execute("show ip route json").find("\"state\":\"failed\""), std::string::npos);
  EXPECT_EQ(sw.node->Execute("no ip route 10.7.0.0/16"), "ok\n");
  sw.Advance(1100 * kUsPerMs);  // the orchagent retries failed routes every second
  routes = sw.node->Execute("show ip route");
  EXPECT_NE(routes.find("S* 10.9.0.0/16"), std::string::npos) << routes;
  EXPECT_EQ(routes.find("10.7.0.0/16"), std::string::npos);
}

TEST(PipelineTest, CliAndSaiRecording) {
  TestSwitch sw(kRouterConfig);
  EXPECT_NE(sw.node->Execute("help").find("show"), std::string::npos);
  EXPECT_EQ(sw.node->Execute("show nonsense").rfind("% Error", 0), 0u);
  const std::string json = sw.node->Execute("show interfaces json");
  EXPECT_EQ(json.front(), '[');
  EXPECT_NE(json.find("\"name\":\"Ethernet4\""), std::string::npos);
  EXPECT_NE(sw.node->Execute("show resources").find("ipv4_route"), std::string::npos);
  EXPECT_NE(sw.node->Execute("show acl").find("10"), std::string::npos);
  EXPECT_EQ(sw.node->Execute("interface Ethernet4 shutdown"), "ok\n");
  EXPECT_FALSE(sw.node->orch().PortAdminUp(4));
  // Every SAI programming call is recorded, sairedis-style.
  const auto has = [&](const std::string& needle) {
    return std::any_of(sw.sai_log.begin(), sw.sai_log.end(),
                       [&](const std::string& l) { return l.find(needle) != std::string::npos; });
  };
  EXPECT_TRUE(has("c|VLAN|vid=10|OK"));
  EXPECT_TRUE(has("c|ROUTER_INTERFACE|type=vlan vid=10"));
  EXPECT_TRUE(has("c|NEXT_HOP_GROUP|"));
  EXPECT_TRUE(has("c|ROUTE|10.9.0.0/16 action=forward"));
  EXPECT_TRUE(has("s|PORT|oid:0x1000000000004 admin=down|OK"));
}

}  // namespace
}  // namespace nanonos
