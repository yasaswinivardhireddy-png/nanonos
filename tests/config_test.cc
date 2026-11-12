#include <gtest/gtest.h>

#include "orch/config.h"
#include "test_util.h"

namespace nanonos {
namespace {

using testing::Ip;

constexpr const char* kLeafConfig = R"(! leaf switch
hostname leaf1
ecmp-hash-seed 7
vlan 10,20
interface Ethernet0
  port veth-h1
  description server h1
  switchport access vlan 10
  storm-control broadcast pps 500
  port-security max-mac 4
interface Ethernet1
  switchport mode trunk
  switchport trunk allowed vlan 10,20
  switchport trunk native vlan 10
interface Ethernet4
  ip address 10.0.0.1/31
  mtu 1500
  qos scheduler strict 7
  qos scheduler weights 1 1 1 4 1 1 1 1
  qos shaper 100m
  qos wred queue 3 min 20000 max 80000 probability 10 ecn
interface Vlan10
  ip address 10.1.1.1/24
ip route 0.0.0.0/0 10.0.0.0
ip route 192.0.2.0/24 blackhole
qos dscp 26 tc 3
copp arp pps 100 burst 20
access-list
  rule 10 deny tcp src any dst 10.1.1.0/24 dport 23
  rule 20 set-tc 3 udp dport 4791
lldp
  tx-interval 5
router bgp 4200000001
  timers 1 3
  maximum-paths 8
  network 10.1.1.0/24
  neighbor 10.0.0.0 remote-as 4200000100
  neighbor 10.0.0.0 description spine1
  neighbor 10.0.0.0 password s3cret
  neighbor 10.0.0.0 ttl-security hops 1
)";

TEST(ConfigTest, ParsesAFullConfiguration) {
  ConfigError error;
  const auto c = ParseConfig(kLeafConfig, &error);
  ASSERT_TRUE(c.has_value()) << error.line << ": " << error.message;
  EXPECT_EQ(c->hostname, "leaf1");
  EXPECT_EQ(c->ecmp_hash_seed, 7u);
  EXPECT_EQ(c->vlans, (std::vector<uint16_t>{10, 20}));
  ASSERT_EQ(c->interfaces.size(), 3u);
  const InterfaceConfig& e0 = c->interfaces[0];
  EXPECT_EQ(e0.netdev, "veth-h1");
  EXPECT_EQ(e0.description, "server h1");
  EXPECT_EQ(e0.access_vlan, 10);
  EXPECT_EQ(e0.storm_pps[static_cast<size_t>(sai::StormType::kBroadcast)], 500u);
  EXPECT_EQ(e0.max_macs, 4u);
  EXPECT_EQ(c->interfaces[1].mode, sai::PortMode::kTrunk);
  EXPECT_EQ(c->interfaces[1].native_vlan, 10);
  const InterfaceConfig& e4 = c->interfaces[2];
  EXPECT_EQ(e4.mode, sai::PortMode::kRouted);
  EXPECT_EQ(e4.address->ip, Ip("10.0.0.1"));
  EXPECT_EQ(e4.scheduler.strict_mask, 0x80);
  EXPECT_EQ(e4.scheduler.weights[3], 4);
  EXPECT_EQ(e4.shaper_bps, 100'000'000u);
  ASSERT_EQ(e4.wred.size(), 1u);
  EXPECT_EQ(e4.wred[0].second.max_bytes, 80000u);
  ASSERT_EQ(c->svis.size(), 1u);
  EXPECT_EQ(c->svis[0].address->ToString(), "10.1.1.1/24");
  ASSERT_EQ(c->static_routes.size(), 2u);
  EXPECT_TRUE(c->static_routes[1].blackhole);
  ASSERT_EQ(c->acl_rules.size(), 2u);
  EXPECT_EQ(c->acl_rules[0].dst_ports.lo, 23);
  EXPECT_EQ(c->acl_rules[1].action, AclAction::kSetTc);
  EXPECT_EQ(c->copp.pps[static_cast<size_t>(sai::TrapType::kArp)], 100u);
  EXPECT_EQ(c->lldp.tx_interval_s, 5);
  EXPECT_EQ(c->bgp.asn, 4200000001u);
  EXPECT_EQ(c->bgp.router_id, Ip("10.0.0.1"));  // defaults to the first interface address
  EXPECT_EQ(c->bgp.hold_s, 3);
  EXPECT_EQ(c->bgp.max_paths, 8);
  ASSERT_EQ(c->bgp.neighbors.size(), 1u);
  EXPECT_EQ(c->bgp.neighbors[0].remote_as, 4200000100u);
  EXPECT_EQ(c->bgp.neighbors[0].password, "s3cret");
  EXPECT_EQ(c->bgp.neighbors[0].ttl_security_hops, 1);
}

TEST(ConfigTest, ReportsErrorsWithLineNumbers) {
  const struct {
    const char* text;
    int line;
  } cases[] = {
      {"hostname a\nbogus command\n", 2},
      {"interface Ethernet0\n  switchport access vlan 5000\n", 2},
      {"  indented first line\n", 1},
      {"interface Ethernet0\n  ip address 10.0.0.1\n", 2},
      {"access-list\n  rule 5 deny dport 80\n", 2},  // ports need tcp or udp
      {"router bgp 65001\n  router-id 1.1.1.1\n  timers 3 2\n", 3},
      {"interface Port7\n", 1},
  };
  for (const auto& c : cases) {
    ConfigError error;
    EXPECT_FALSE(ParseConfig(c.text, &error).has_value()) << c.text;
    EXPECT_EQ(error.line, c.line) << c.text << " -> " << error.message;
  }
  ConfigError error;
  EXPECT_FALSE(
      ParseConfig("router bgp 65001\n  router-id 1.1.1.1\n  neighbor 1.1.1.2 description x\n",
                  &error)
          .has_value());
  EXPECT_NE(error.message.find("remote-as"), std::string::npos);
}

}  // namespace
}  // namespace nanonos
