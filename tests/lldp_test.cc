#include <vector>

#include <gtest/gtest.h>

#include "common/byte_order.h"
#include "proto/lldp.h"
#include "test_util.h"

namespace nanonos {
namespace {

using testing::Mac;

TEST(LldpTest, RoundTripsAllTlvs) {
  lldp::Info info;
  info.port_id = "Ethernet4";
  info.port_description = "to spine1";
  info.system_name = "leaf1";
  info.system_description = "NanoNOS 0.1.0";
  info.ttl = 120;
  info.mgmt_ip = 0x0a000001;
  uint8_t frame[512];
  const size_t len = lldp::BuildFrame(frame, Mac(0x020000000001), Mac(0x020000000001), info);
  ASSERT_GT(len, 0u);
  ParsedPacket p;
  ASSERT_EQ(ParseFrame(std::span<const uint8_t>(frame, len), &p), ParseStatus::kOk);
  EXPECT_TRUE(IsLinkLocalMulticast(p.dst_mac));
  EXPECT_EQ(p.ethertype, kEtherTypeLldp);

  lldp::Info out;
  ASSERT_TRUE(lldp::ParseFrame(std::span<const uint8_t>(frame, len), &out));
  EXPECT_EQ(out.chassis_id, "02:00:00:00:00:01");
  EXPECT_EQ(out.port_id, "Ethernet4");
  EXPECT_EQ(out.port_description, "to spine1");
  EXPECT_EQ(out.system_name, "leaf1");
  EXPECT_EQ(out.ttl, 120);
  EXPECT_EQ(out.mgmt_ip, 0x0a000001u);
}

TEST(LldpTest, RejectsMissingMandatoryTlvsAndOverruns) {
  lldp::Info info;
  info.port_id = "Ethernet0";
  uint8_t frame[512];
  const size_t len = lldp::BuildFrame(frame, Mac(1), Mac(1), info);
  lldp::Info out;
  std::vector<uint8_t> bad(frame, frame + len);
  // Port ID TLV changed to type 4: mandatory order violated.
  bad[14 + 9] = static_cast<uint8_t>((4 << 1) | (bad[14 + 9] & 1));
  EXPECT_FALSE(lldp::ParseFrame(bad, &out));
  // TLV length running past the end of the frame.
  bad.assign(frame, frame + len);
  StoreBe16(bad.data() + 14, static_cast<uint16_t>((1 << 9) | 500));
  EXPECT_FALSE(lldp::ParseFrame(bad, &out));
  // Non-printable bytes in strings are sanitized.
  info.system_name = std::string("ab\x01\x7f", 4);
  const size_t len2 = lldp::BuildFrame(frame, Mac(1), Mac(1), info);
  ASSERT_TRUE(lldp::ParseFrame(std::span<const uint8_t>(frame, len2), &out));
  EXPECT_EQ(out.system_name, "ab..");
}

TEST(LldpTest, AgentsDiscoverEachOtherAndExpire) {
  ManualClock clock;
  lldp::Agent a(&clock);
  lldp::Agent b(&clock);
  a.Configure("leaf1", "NanoNOS", Mac(0xa), 5, 4);
  b.Configure("spine1", "NanoNOS", Mac(0xb), 5, 4);
  a.AddPort(4, "Ethernet4", "uplink", 0);
  b.AddPort(0, "Ethernet0", "downlink", 0);
  // Wire: a's port 4 <-> b's port 0.
  a.Tick([&](uint16_t, std::span<const uint8_t> f) { b.OnFrame(0, f); });
  b.Tick([&](uint16_t, std::span<const uint8_t> f) { a.OnFrame(4, f); });
  ASSERT_EQ(a.neighbors().count(4), 1u);
  EXPECT_EQ(a.neighbors().at(4).info.system_name, "spine1");
  EXPECT_EQ(a.neighbors().at(4).info.port_id, "Ethernet0");
  EXPECT_EQ(b.neighbors().at(0).info.system_name, "leaf1");
  // The TTL is tx-interval x hold-multiplier = 20 s.
  clock.Advance(19 * kUsPerSec);
  a.Tick([](uint16_t, std::span<const uint8_t>) {});
  EXPECT_EQ(a.neighbors().size(), 1u);
  clock.Advance(2 * kUsPerSec);
  a.Tick([](uint16_t, std::span<const uint8_t>) {});
  EXPECT_TRUE(a.neighbors().empty());
}

}  // namespace
}  // namespace nanonos
