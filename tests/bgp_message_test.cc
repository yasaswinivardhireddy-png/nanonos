#include <vector>

#include <gtest/gtest.h>

#include "common/byte_order.h"
#include "proto/bgp_message.h"
#include "test_util.h"

namespace nanonos::bgp {
namespace {

using testing::Ip;
using testing::Pfx;

// Runs one encoded message through the stream reader and returns its body.
std::vector<uint8_t> Body(const std::vector<uint8_t>& message, MessageType expected) {
  MessageReader reader;
  reader.Append(message);
  MessageType type{};
  std::vector<uint8_t> body;
  Error error;
  EXPECT_TRUE(reader.Next(&type, &body, &error));
  EXPECT_TRUE(error.ok());
  EXPECT_EQ(type, expected);
  return body;
}

std::vector<uint8_t> UpdateBody(const std::vector<uint8_t>& withdrawn,
                                const std::vector<uint8_t>& attrs,
                                const std::vector<uint8_t>& nlri) {
  std::vector<uint8_t> b;
  b.push_back(static_cast<uint8_t>(withdrawn.size() >> 8));
  b.push_back(static_cast<uint8_t>(withdrawn.size()));
  b.insert(b.end(), withdrawn.begin(), withdrawn.end());
  b.push_back(static_cast<uint8_t>(attrs.size() >> 8));
  b.push_back(static_cast<uint8_t>(attrs.size()));
  b.insert(b.end(), attrs.begin(), attrs.end());
  b.insert(b.end(), nlri.begin(), nlri.end());
  return b;
}

// ORIGIN IGP, AS_PATH [65001] (4-octet), NEXT_HOP 10.0.0.1
const std::vector<uint8_t> kGoodAttrs = {0x40, 1,    1,    0,    0x40, 2, 6,  2, 1, 0,
                                         0,    0xfd, 0xe9, 0x40, 3,    4, 10, 0, 0, 1};
const std::vector<uint8_t> kNlri = {24, 10, 2, 3};  // 10.2.3.0/24

TEST(BgpMessageTest, OpenRoundTripWithFourOctetAs) {
  OpenMessage open;
  open.my_as = 4200000001;
  open.hold_time = 9;
  open.bgp_id = Ip("10.0.0.1");
  open.cap_as4 = true;
  open.cap_mp_ipv4_unicast = true;
  const std::vector<uint8_t> msg = EncodeOpen(open);
  const std::vector<uint8_t> body = Body(msg, MessageType::kOpen);
  EXPECT_EQ(LoadBe16(body.data() + 1), kAsTrans);  // 2-octet field carries AS_TRANS
  OpenMessage out;
  ASSERT_TRUE(DecodeOpen(body, &out).ok());
  EXPECT_EQ(out.my_as, 4200000001u);
  EXPECT_EQ(out.hold_time, 9);
  EXPECT_EQ(out.bgp_id, Ip("10.0.0.1"));
  EXPECT_TRUE(out.cap_as4);
  EXPECT_TRUE(out.cap_mp_ipv4_unicast);
}

TEST(BgpMessageTest, OpenErrorsMapToNotificationCodes) {
  OpenMessage open;
  open.my_as = 65001;
  open.bgp_id = Ip("1.1.1.1");
  std::vector<uint8_t> body = Body(EncodeOpen(open), MessageType::kOpen);
  OpenMessage out;

  auto bad = body;
  bad[0] = 3;
  Error e = DecodeOpen(bad, &out);
  EXPECT_EQ(e.code, err::kOpen);
  EXPECT_EQ(e.subcode, err::kUnsupportedVersion);

  bad = body;
  StoreBe16(bad.data() + 3, 2);
  EXPECT_EQ(DecodeOpen(bad, &out).subcode, err::kUnacceptableHoldTime);

  bad = body;
  StoreBe32(bad.data() + 5, 0);
  EXPECT_EQ(DecodeOpen(bad, &out).subcode, err::kBadBgpId);

  bad = body;
  bad.insert(bad.end(), {1, 0});  // optional parameter type 1 (deprecated authentication)
  bad[9] = static_cast<uint8_t>(bad[9] + 2);
  EXPECT_EQ(DecodeOpen(bad, &out).subcode, err::kUnsupportedOptParam);
}

TEST(BgpMessageTest, DecodesExtendedOptionalParameters) {
  // RFC 9072: Non-Ext OP Len 255, Non-Ext OP Type 255, 2-octet lengths.
  std::vector<uint8_t> body = {4, 0xfd, 0xe9, 0, 90, 1,  1, 1, 1, 255,  255,
                               0, 9,    2,    0, 6,  65, 4, 0, 0, 0xfd, 0xe9};
  OpenMessage out;
  const Error e = DecodeOpen(body, &out);
  ASSERT_TRUE(e.ok()) << ErrorString(e.code, e.subcode);
  EXPECT_TRUE(out.cap_as4);
  EXPECT_EQ(out.my_as, 65001u);
}

TEST(BgpMessageTest, UpdateRoundTrip) {
  PathAttributes a;
  a.origin = Origin::kIncomplete;
  a.as_path = {AsPathSegment{2, {4200000100u, 65002}}};
  a.next_hop = Ip("10.0.0.1");
  a.med = 50;
  a.communities = {0xfde80064};
  const std::vector<Ipv4Prefix> prefixes = {Pfx("10.1.0.0/16"), Pfx("10.2.3.0/24"),
                                            Pfx("0.0.0.0/0"), Pfx("10.9.9.9/32")};
  const auto messages = EncodeAnnouncements(a, prefixes, true);
  ASSERT_EQ(messages.size(), 1u);
  UpdateMessage u;
  ASSERT_TRUE(DecodeUpdate(Body(messages[0], MessageType::kUpdate), true, &u).ok());
  EXPECT_EQ(u.attrs, a);
  EXPECT_EQ(u.nlri, prefixes);
  EXPECT_EQ(u.attrs.AsPathLength(), 2u);
  EXPECT_EQ(u.attrs.FirstAs(), 4200000100u);

  // Without 4-octet AS support the large AS is replaced by AS_TRANS.
  const auto two_octet = EncodeAnnouncements(a, prefixes, false);
  ASSERT_TRUE(DecodeUpdate(Body(two_octet[0], MessageType::kUpdate), false, &u).ok());
  EXPECT_EQ(u.attrs.as_path[0].asns, (std::vector<uint32_t>{kAsTrans, 65002}));

  const auto withdrawals = EncodeWithdrawals(prefixes);
  ASSERT_EQ(withdrawals.size(), 1u);
  ASSERT_TRUE(DecodeUpdate(Body(withdrawals[0], MessageType::kUpdate), true, &u).ok());
  EXPECT_EQ(u.withdrawn, prefixes);
  EXPECT_FALSE(u.has_attributes);
}

TEST(BgpMessageTest, LargeUpdatesSplitUnderTheMaximumMessageSize) {
  std::vector<Ipv4Prefix> prefixes;
  for (uint32_t i = 0; i < 3000; ++i)
    prefixes.push_back(Ipv4Prefix::Make((10u << 24) | (i << 8), 24));
  PathAttributes a;
  a.as_path = {AsPathSegment{2, {65001}}};
  a.next_hop = Ip("10.0.0.1");
  const auto messages = EncodeAnnouncements(a, prefixes, true);
  EXPECT_GT(messages.size(), 1u);
  size_t total = 0;
  for (const auto& m : messages) {
    EXPECT_LE(m.size(), kMaxMessageLen);
    UpdateMessage u;
    ASSERT_TRUE(DecodeUpdate(Body(m, MessageType::kUpdate), true, &u).ok());
    total += u.nlri.size();
  }
  EXPECT_EQ(total, prefixes.size());
}

TEST(BgpMessageTest, UpdateErrorsMapToNotificationCodes) {
  UpdateMessage u;
  // Missing NEXT_HOP with NLRI present.
  std::vector<uint8_t> attrs(kGoodAttrs.begin(), kGoodAttrs.begin() + 13);
  Error e = DecodeUpdate(UpdateBody({}, attrs, kNlri), true, &u);
  EXPECT_EQ(e.code, err::kUpdate);
  EXPECT_EQ(e.subcode, err::kMissingWellKnown);
  EXPECT_EQ(e.data, std::vector<uint8_t>{3});

  attrs = kGoodAttrs;
  attrs[3] = 5;  // invalid ORIGIN
  EXPECT_EQ(DecodeUpdate(UpdateBody({}, attrs, kNlri), true, &u).subcode, err::kInvalidOrigin);

  attrs = kGoodAttrs;
  attrs[16] = 224;  // multicast NEXT_HOP 224.0.0.1
  EXPECT_EQ(DecodeUpdate(UpdateBody({}, attrs, kNlri), true, &u).subcode, err::kInvalidNextHop);

  attrs = kGoodAttrs;
  attrs[0] = 0xc0;  // ORIGIN marked optional
  EXPECT_EQ(DecodeUpdate(UpdateBody({}, attrs, kNlri), true, &u).subcode, err::kAttrFlags);

  attrs = kGoodAttrs;
  attrs[6] = 60;  // AS_PATH length runs past the attribute list
  EXPECT_EQ(DecodeUpdate(UpdateBody({}, attrs, kNlri), true, &u).subcode, err::kMalformedAttrList);

  attrs = kGoodAttrs;
  attrs.insert(attrs.end(), {0x40, 1, 1, 0});  // duplicate ORIGIN
  EXPECT_EQ(DecodeUpdate(UpdateBody({}, attrs, kNlri), true, &u).subcode, err::kMalformedAttrList);

  attrs = kGoodAttrs;
  attrs.insert(attrs.end(), {0x40, 99, 0});  // unknown well-known attribute
  EXPECT_EQ(DecodeUpdate(UpdateBody({}, attrs, kNlri), true, &u).subcode,
            err::kUnrecognizedWellKnown);

  attrs = kGoodAttrs;
  attrs.insert(attrs.end(), {0xc0, 99, 1, 7});  // unknown optional transitive: ignored
  EXPECT_TRUE(DecodeUpdate(UpdateBody({}, attrs, kNlri), true, &u).ok());

  EXPECT_EQ(DecodeUpdate(UpdateBody({}, kGoodAttrs, {33, 10, 0, 0, 0, 0}), true, &u).subcode,
            err::kInvalidNetwork);
  EXPECT_EQ(DecodeUpdate(UpdateBody({24, 10}, {}, {}), true, &u).subcode, err::kInvalidNetwork);

  // An empty UPDATE is an End-of-RIB marker, not an error.
  EXPECT_TRUE(DecodeUpdate(UpdateBody({}, {}, {}), true, &u).ok());
}

TEST(BgpMessageTest, ReaderReassemblesByteByByte) {
  OpenMessage open;
  open.my_as = 65001;
  open.bgp_id = 1;
  std::vector<uint8_t> stream = EncodeOpen(open);
  const auto ka = EncodeKeepalive();
  stream.insert(stream.end(), ka.begin(), ka.end());
  const auto notification = EncodeNotification(err::kCease, err::kAdminReset);
  stream.insert(stream.end(), notification.begin(), notification.end());

  MessageReader reader;
  std::vector<MessageType> seen;
  MessageType type{};
  std::vector<uint8_t> body;
  Error error;
  for (uint8_t byte : stream) {
    reader.Append(std::span<const uint8_t>(&byte, 1));
    while (reader.Next(&type, &body, &error)) seen.push_back(type);
    ASSERT_TRUE(error.ok());
  }
  EXPECT_EQ(seen, (std::vector<MessageType>{MessageType::kOpen, MessageType::kKeepalive,
                                            MessageType::kNotification}));
  EXPECT_EQ(reader.buffered(), 0u);
}

TEST(BgpMessageTest, ReaderRejectsBadHeaders) {
  const auto check = [](std::vector<uint8_t> m, uint8_t subcode) {
    MessageReader reader;
    reader.Append(m);
    MessageType type{};
    std::vector<uint8_t> body;
    Error error;
    EXPECT_FALSE(reader.Next(&type, &body, &error));
    EXPECT_EQ(error.code, err::kHeader);
    EXPECT_EQ(error.subcode, subcode);
  };
  auto m = EncodeKeepalive();
  m[3] = 0;
  check(m, err::kNotSynchronized);
  m = EncodeKeepalive();
  StoreBe16(m.data() + 16, 20);
  m.push_back(0);
  check(m, err::kBadLength);
  m = EncodeKeepalive();
  m[18] = 9;
  check(m, err::kBadType);
  m = EncodeKeepalive();
  StoreBe16(m.data() + 16, 5000);
  check(m, err::kBadLength);
}

}  // namespace
}  // namespace nanonos::bgp
