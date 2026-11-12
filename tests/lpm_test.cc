#include <map>
#include <vector>

#include <gtest/gtest.h>

#include "asic/lpm.h"
#include "common/hash.h"
#include "test_util.h"

namespace nanonos {
namespace {

using testing::Ip;
using testing::Pfx;

TEST(LpmTest, LongestPrefixWins) {
  LpmTable lpm(100, 64);
  ASSERT_EQ(lpm.Insert(Pfx("0.0.0.0/0"), 1), Status::kOk);
  ASSERT_EQ(lpm.Insert(Pfx("10.0.0.0/8"), 2), Status::kOk);
  ASSERT_EQ(lpm.Insert(Pfx("10.1.0.0/16"), 3), Status::kOk);
  ASSERT_EQ(lpm.Insert(Pfx("10.1.2.0/24"), 4), Status::kOk);
  ASSERT_EQ(lpm.Insert(Pfx("10.1.2.3/32"), 5), Status::kOk);
  ASSERT_EQ(lpm.Insert(Pfx("10.1.2.128/25"), 6), Status::kOk);
  EXPECT_EQ(lpm.Lookup(Ip("192.168.0.1")), 1u);
  EXPECT_EQ(lpm.Lookup(Ip("10.9.9.9")), 2u);
  EXPECT_EQ(lpm.Lookup(Ip("10.1.9.9")), 3u);
  EXPECT_EQ(lpm.Lookup(Ip("10.1.2.4")), 4u);
  EXPECT_EQ(lpm.Lookup(Ip("10.1.2.3")), 5u);
  EXPECT_EQ(lpm.Lookup(Ip("10.1.2.200")), 6u);
}

TEST(LpmTest, ShorterPrefixInsertedLaterDoesNotOverrideLonger) {
  LpmTable lpm(100, 64);
  ASSERT_EQ(lpm.Insert(Pfx("10.1.2.0/24"), 4), Status::kOk);
  ASSERT_EQ(lpm.Insert(Pfx("10.0.0.0/8"), 2), Status::kOk);
  EXPECT_EQ(lpm.Lookup(Ip("10.1.2.9")), 4u);
  EXPECT_EQ(lpm.Lookup(Ip("10.1.3.9")), 2u);
}

TEST(LpmTest, RemoveRestoresCoveringPrefixAndReclaimsNodes) {
  LpmTable lpm(100, 64);
  ASSERT_EQ(lpm.Insert(Pfx("10.0.0.0/8"), 2), Status::kOk);
  ASSERT_EQ(lpm.Insert(Pfx("10.1.2.0/24"), 4), Status::kOk);
  EXPECT_EQ(lpm.nodes_in_use(), 3u);  // root, 10/8 level, 10.1/16 level
  ASSERT_EQ(lpm.Remove(Pfx("10.1.2.0/24")), Status::kOk);
  EXPECT_EQ(lpm.Lookup(Ip("10.1.2.9")), 2u);
  EXPECT_EQ(lpm.nodes_in_use(), 1u);
  ASSERT_EQ(lpm.Remove(Pfx("10.0.0.0/8")), Status::kOk);
  EXPECT_FALSE(lpm.Lookup(Ip("10.1.2.9")).has_value());
  EXPECT_EQ(lpm.Remove(Pfx("10.0.0.0/8")), Status::kNotFound);
}

TEST(LpmTest, UpdatesValueInPlace) {
  LpmTable lpm(100, 64);
  ASSERT_EQ(lpm.Insert(Pfx("10.1.0.0/16"), 3), Status::kOk);
  ASSERT_EQ(lpm.Insert(Pfx("10.1.5.0/24"), 7), Status::kOk);
  ASSERT_EQ(lpm.Insert(Pfx("10.1.0.0/16"), 9), Status::kOk);
  EXPECT_EQ(lpm.Lookup(Ip("10.1.0.1")), 9u);
  EXPECT_EQ(lpm.Lookup(Ip("10.1.5.1")), 7u);
  EXPECT_EQ(lpm.size(), 2u);
}

TEST(LpmTest, TableFullIsAllOrNothing) {
  LpmTable lpm(100, 3);  // root + 2 nodes: one /24 costs 3 levels
  ASSERT_EQ(lpm.Insert(Pfx("10.1.2.0/24"), 1), Status::kOk);
  EXPECT_EQ(lpm.Insert(Pfx("20.1.2.0/24"), 2), Status::kTableFull);
  EXPECT_FALSE(lpm.Lookup(Ip("20.1.2.1")).has_value());
  EXPECT_FALSE(lpm.Get(Pfx("20.1.2.0/24")).has_value());
  EXPECT_EQ(lpm.Insert(Pfx("20.0.0.0/8"), 3), Status::kOk);  // needs no new node
  LpmTable small(1, 64);
  ASSERT_EQ(small.Insert(Pfx("1.0.0.0/8"), 1), Status::kOk);
  EXPECT_EQ(small.Insert(Pfx("2.0.0.0/8"), 1), Status::kTableFull);
}

// Reference: a linear scan for the longest matching prefix.
std::optional<uint32_t> ReferenceLookup(const std::map<Ipv4Prefix, uint32_t>& rules, uint32_t ip) {
  int best_len = -1;
  std::optional<uint32_t> best;
  for (const auto& [p, v] : rules) {
    if (p.Contains(ip) && p.len > best_len) {
      best_len = p.len;
      best = v;
    }
  }
  return best;
}

TEST(LpmTest, RandomizedAgainstReference) {
  Xorshift rng(1234);
  LpmTable lpm(4096, 4096);
  std::map<Ipv4Prefix, uint32_t> rules;
  // Addresses cluster in a few /8s so prefixes overlap heavily.
  const auto random_addr = [&] {
    return (static_cast<uint32_t>(rng.Below(4)) << 24) |
           static_cast<uint32_t>(rng.Next() & 0xffffff);
  };
  for (int step = 0; step < 20000; ++step) {
    const uint64_t op = rng.Below(10);
    if (op < 5 || rules.empty()) {
      const int len = static_cast<int>(rng.Below(33));
      const Ipv4Prefix p = Ipv4Prefix::Make(random_addr(), len);
      const uint32_t value = static_cast<uint32_t>(rng.Below(LpmTable::kMaxValue));
      ASSERT_EQ(lpm.Insert(p, value), Status::kOk);
      rules[p] = value;
    } else if (op < 8) {
      auto it = rules.begin();
      std::advance(it, static_cast<long>(rng.Below(rules.size())));
      ASSERT_EQ(lpm.Remove(it->first), Status::kOk);
      rules.erase(it);
    } else {
      const uint32_t ip = random_addr();
      ASSERT_EQ(lpm.Lookup(ip), ReferenceLookup(rules, ip)) << Ipv4ToString(ip);
    }
  }
  for (int i = 0; i < 20000; ++i) {
    const uint32_t ip = random_addr();
    ASSERT_EQ(lpm.Lookup(ip), ReferenceLookup(rules, ip)) << Ipv4ToString(ip);
  }
  for (const auto& [p, v] : rules) ASSERT_EQ(lpm.Remove(p), Status::kOk);
  EXPECT_EQ(lpm.size(), 0u);
  EXPECT_EQ(lpm.nodes_in_use(), 1u);  // every node returned to the pool
}

}  // namespace
}  // namespace nanonos
