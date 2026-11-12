#include <gtest/gtest.h>

#include "asic/acl.h"
#include "common/hash.h"
#include "test_util.h"

namespace nanonos {
namespace {

using testing::Ip;
using testing::Pfx;

TEST(AclTest, RangeExpansionCoversExactlyTheRange) {
  Xorshift rng(5);
  for (int i = 0; i < 300; ++i) {
    const uint16_t a = static_cast<uint16_t>(rng.Next());
    const uint16_t b = static_cast<uint16_t>(rng.Next());
    const PortRange r{std::min(a, b), std::max(a, b)};
    const auto prefixes = AclTable::ExpandRange(r);
    ASSERT_LE(prefixes.size(), 30u);  // at most 2w-2 entries for w = 16 bits
    for (uint32_t v = 0; v <= 65535; v += 97) {
      bool hit = false;
      for (const auto& [value, mask] : prefixes) hit |= (v & mask) == value;
      ASSERT_EQ(hit, v >= r.lo && v <= r.hi) << v << " in [" << r.lo << "," << r.hi << "]";
    }
  }
  EXPECT_EQ(AclTable::ExpandRange({0, 65535}).size(), 1u);
  EXPECT_EQ(AclTable::ExpandRange({1024, 65535}).size(), 6u);
  EXPECT_EQ(AclTable::ExpandRange({1, 65534}).size(), 30u);  // worst case
}

TEST(AclTest, FirstMatchBySequenceAndCountsHits) {
  AclTable acl(64);
  AclRule deny_telnet;
  deny_telnet.seq = 10;
  deny_telnet.action = AclAction::kDeny;
  deny_telnet.ip_proto = kIpProtoTcp;
  deny_telnet.dst = Pfx("10.1.0.0/16");
  deny_telnet.dst_ports = {23, 23};
  AclRule roce;
  roce.seq = 20;
  roce.action = AclAction::kSetTc;
  roce.set_tc = 3;
  roce.ip_proto = kIpProtoUdp;
  roce.dst_ports = {kRoceV2Port, kRoceV2Port};
  AclRule permit;
  permit.seq = 30;
  ASSERT_EQ(acl.AddRule(permit), Status::kOk);
  ASSERT_EQ(acl.AddRule(roce), Status::kOk);
  ASSERT_EQ(acl.AddRule(deny_telnet), Status::kOk);
  EXPECT_EQ(acl.AddRule(permit), Status::kAlreadyExists);

  AclLookupKey telnet{Ip("1.1.1.1"), Ip("10.1.2.3"), 5555, 23, kIpProtoTcp, 0, 1};
  ASSERT_NE(acl.Lookup(telnet), nullptr);
  EXPECT_EQ(acl.Lookup(telnet)->action, AclAction::kDeny);
  AclLookupKey rocev2{Ip("1.1.1.1"), Ip("10.9.9.9"), 5555, kRoceV2Port, kIpProtoUdp, 26, 1};
  EXPECT_EQ(acl.Lookup(rocev2)->set_tc, 3);
  AclLookupKey other{Ip("1.1.1.1"), Ip("10.1.2.3"), 5555, 80, kIpProtoTcp, 0, 1};
  EXPECT_EQ(acl.Lookup(other)->seq, 30u);
  EXPECT_EQ(acl.hits(10), 2u);
  ASSERT_EQ(acl.RemoveRule(10), Status::kOk);
  EXPECT_EQ(acl.Lookup(telnet)->seq, 30u);
}

TEST(AclTest, RangesConsumeTcamEntriesAndRespectCapacity) {
  AclTable acl(10);
  AclRule r;
  r.seq = 1;
  r.ip_proto = kIpProtoTcp;
  r.dst_ports = {1024, 65535};  // 6 entries
  ASSERT_EQ(acl.AddRule(r), Status::kOk);
  EXPECT_EQ(acl.entries_used(), 6u);
  r.seq = 2;
  EXPECT_EQ(acl.AddRule(r), Status::kTableFull);
  EXPECT_EQ(acl.rule_count(), 1u);
}

}  // namespace
}  // namespace nanonos
