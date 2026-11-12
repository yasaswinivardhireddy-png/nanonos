#include <cstring>
#include <vector>

#include <gtest/gtest.h>

#include "common/byte_order.h"
#include "common/hash.h"
#include "test_util.h"

namespace nanonos {
namespace {

using testing::FlowFrame;
using testing::Ip;
using testing::Mac;

TEST(TypesTest, ParsesAndFormatsAddresses) {
  EXPECT_EQ(ParseIpv4("10.1.2.3"), 0x0a010203u);
  EXPECT_FALSE(ParseIpv4("10.1.2").has_value());
  EXPECT_FALSE(ParseIpv4("10.1.2.256").has_value());
  EXPECT_FALSE(ParseIpv4("10.1.2.3.4").has_value());
  EXPECT_FALSE(ParseIpv4("10.1..3").has_value());
  EXPECT_FALSE(ParseIpv4("+1.1.1.1").has_value());
  EXPECT_EQ(Ipv4ToString(0xc0a80001), "192.168.0.1");

  const auto p = Ipv4Prefix::Parse("10.1.2.3/16");
  ASSERT_TRUE(p.has_value());
  EXPECT_EQ(p->addr, 0x0a010000u);  // host bits cleared
  EXPECT_EQ(p->ToString(), "10.1.0.0/16");
  EXPECT_TRUE(p->Contains(0x0a01ffffu));
  EXPECT_FALSE(p->Contains(0x0a020000u));
  EXPECT_FALSE(Ipv4Prefix::Parse("10.0.0.0/33").has_value());

  const auto a = InterfaceAddress::Parse("10.0.0.1/31");
  ASSERT_TRUE(a.has_value());
  EXPECT_EQ(a->ip, 0x0a000001u);  // host bits kept
  EXPECT_EQ(a->Subnet().ToString(), "10.0.0.0/31");

  const auto mac = MacAddress::Parse("02:00:5e:10:aa:ff");
  ASSERT_TRUE(mac.has_value());
  EXPECT_EQ(mac->ToU64(), 0x02005e10aaffULL);
  EXPECT_EQ(mac->ToString(), "02:00:5e:10:aa:ff");
  EXPECT_FALSE(MacAddress::Parse("02:00:5e:10:aa").has_value());
  EXPECT_TRUE(MacAddress::Broadcast().IsBroadcast());
  EXPECT_TRUE(Mac(0x01005e000001).IsMulticast());
  EXPECT_FALSE(Mac(0x020000000001).IsMulticast());
}

TEST(PacketTest, ParsesTaggedUdpFrame) {
  testing::Flow f{Mac(0x020000000002), Mac(0x020000000001), Ip("10.0.0.1"), Ip("10.0.0.2")};
  f.vlan = 42;
  f.dscp = 46;
  f.ecn = 2;
  f.src_port = 4000;
  f.dst_port = 4791;
  const auto frame = FlowFrame(f);
  ParsedPacket p;
  ASSERT_EQ(ParseFrame(frame, &p), ParseStatus::kOk);
  EXPECT_TRUE(p.vlan_tagged);
  EXPECT_EQ(p.vlan_id, 42);
  EXPECT_TRUE(p.is_ipv4());
  EXPECT_EQ(p.l3_offset, 18);
  EXPECT_EQ(p.dscp, 46);
  EXPECT_EQ(p.ecn, 2);
  EXPECT_EQ(p.src_ip, Ip("10.0.0.1"));
  EXPECT_EQ(p.dst_port, kRoceV2Port);
  EXPECT_TRUE(p.has_l4);
}

TEST(PacketTest, ParsesArp) {
  const auto frame = testing::ArpFrame(MacAddress::Broadcast(), kArpOpRequest, Mac(0x020000000001),
                                       Ip("10.0.0.1"), MacAddress{}, Ip("10.0.0.2"));
  EXPECT_EQ(frame.size(), kMinFrameSize);
  ParsedPacket p;
  ASSERT_EQ(ParseFrame(frame, &p), ParseStatus::kOk);
  EXPECT_TRUE(p.is_arp());
  EXPECT_EQ(p.arp_op, kArpOpRequest);
  EXPECT_EQ(p.arp_spa, Ip("10.0.0.1"));
  EXPECT_EQ(p.arp_tpa, Ip("10.0.0.2"));
}

TEST(PacketTest, RejectsMalformedHeaders) {
  testing::Flow f{Mac(2), Mac(1), Ip("1.1.1.1"), Ip("2.2.2.2")};
  auto frame = FlowFrame(f);
  ParsedPacket p;

  EXPECT_EQ(ParseFrame(std::span(frame.data(), 13), &p), ParseStatus::kTruncated);
  EXPECT_EQ(ParseFrame(std::span(frame.data(), 30), &p), ParseStatus::kTruncated);

  auto bad = frame;
  bad[14] = 0x65;  // version 6
  EXPECT_EQ(ParseFrame(bad, &p), ParseStatus::kBadIpVersion);
  bad = frame;
  bad[14] = 0x44;  // IHL 16 bytes
  EXPECT_EQ(ParseFrame(bad, &p), ParseStatus::kBadIpHeaderLength);
  bad = frame;
  StoreBe16(bad.data() + 16, 2000);  // total length beyond the frame
  EXPECT_EQ(ParseFrame(bad, &p), ParseStatus::kBadIpTotalLength);
  bad = frame;
  bad[22] ^= 0x01;  // corrupt TTL without fixing the checksum
  EXPECT_EQ(ParseFrame(bad, &p), ParseStatus::kBadIpChecksum);
}

TEST(PacketTest, IncrementalChecksumMatchesFullRecompute) {
  Xorshift rng(7);
  for (int i = 0; i < 5000; ++i) {
    uint8_t ip[20];
    for (uint8_t& b : ip) b = static_cast<uint8_t>(rng.Next());
    ip[0] = 0x45;
    ip[8] = static_cast<uint8_t>(2 + rng.Below(254));
    StoreBe16(ip + 10, 0);
    StoreBe16(ip + 10, InternetChecksum(ip, 20));
    if (i % 2 == 0) {
      DecrementTtl(ip);
    } else {
      MarkEcnCe(ip);
    }
    ASSERT_EQ(InternetChecksum(ip, 20), 0) << "iteration " << i;
  }
}

TEST(PacketTest, FlowHashDependsOnFiveTupleAndSeed) {
  testing::Flow f{Mac(2), Mac(1), Ip("10.0.0.1"), Ip("10.0.0.2")};
  const ParsedPacket a = testing::Parse(FlowFrame(f));
  f.src_port = 1001;
  const ParsedPacket b = testing::Parse(FlowFrame(f));
  EXPECT_EQ(FlowHash(a, 1), FlowHash(a, 1));
  EXPECT_NE(FlowHash(a, 1), FlowHash(b, 1));
  EXPECT_NE(FlowHash(a, 1), FlowHash(a, 2));
  // A known CRC-32 value ("123456789" -> 0xCBF43926) pins the implementation.
  const char* check = "123456789";
  EXPECT_EQ(Crc32(reinterpret_cast<const uint8_t*>(check), 9), 0xcbf43926u);
}

}  // namespace
}  // namespace nanonos
