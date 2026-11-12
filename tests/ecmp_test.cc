#include <vector>

#include <gtest/gtest.h>

#include "asic/ecmp.h"
#include "common/hash.h"

namespace nanonos {
namespace {

std::vector<uint32_t> FlowHashes(size_t n) {
  std::vector<uint32_t> hashes;
  Xorshift rng(99);
  for (size_t i = 0; i < n; ++i) hashes.push_back(static_cast<uint32_t>(rng.Next()));
  return hashes;
}

// Fraction of flows whose member changes when member `removed` fails.
double Disruption(EcmpGroup::Mode mode, const std::vector<uint32_t>& members, uint32_t removed,
                  double* moved_from_survivors) {
  EcmpGroup g(mode);
  g.SetActiveMembers(members);
  const std::vector<uint32_t> hashes = FlowHashes(20000);
  std::vector<uint32_t> before;
  for (uint32_t h : hashes) before.push_back(g.Select(h));
  std::vector<uint32_t> rest;
  for (uint32_t m : members) {
    if (m != removed) rest.push_back(m);
  }
  g.SetActiveMembers(rest);
  size_t moved = 0;
  size_t moved_survivor = 0;
  for (size_t i = 0; i < hashes.size(); ++i) {
    const uint32_t after = g.Select(hashes[i]);
    EXPECT_NE(after, removed);
    if (after != before[i]) {
      ++moved;
      if (before[i] != removed) ++moved_survivor;
    }
  }
  *moved_from_survivors = static_cast<double>(moved_survivor) / static_cast<double>(hashes.size());
  return static_cast<double>(moved) / static_cast<double>(hashes.size());
}

TEST(EcmpTest, BucketsAreBalanced) {
  EcmpGroup g;
  g.SetActiveMembers(std::vector<uint32_t>{10, 11, 12});
  EXPECT_EQ(g.BucketsOwnedBy(10) + g.BucketsOwnedBy(11) + g.BucketsOwnedBy(12),
            EcmpGroup::kBuckets);
  for (uint32_t m : {10u, 11u, 12u}) {
    EXPECT_GE(g.BucketsOwnedBy(m), 85u);
    EXPECT_LE(g.BucketsOwnedBy(m), 86u);
  }
}

TEST(EcmpTest, ResilientHashingOnlyMovesFlowsOfTheFailedMember) {
  const std::vector<uint32_t> members{1, 2, 3, 4};
  double survivors_resilient = 0;
  double survivors_modulo = 0;
  const double resilient =
      Disruption(EcmpGroup::Mode::kResilient, members, 3, &survivors_resilient);
  const double modulo = Disruption(EcmpGroup::Mode::kModulo, members, 3, &survivors_modulo);
  EXPECT_EQ(survivors_resilient, 0.0);  // flows on healthy paths never move
  EXPECT_NEAR(resilient, 0.25, 0.03);   // only the failed member's quarter moves
  EXPECT_GT(modulo, 0.6);               // modulo reshuffles most flows
  std::printf("flows moved when 1 of 4 members fails: resilient %.1f%%, modulo %.1f%%\n",
              resilient * 100, modulo * 100);
}

TEST(EcmpTest, AddingAMemberTakesOnlyItsShare) {
  EcmpGroup g;
  g.SetActiveMembers(std::vector<uint32_t>{1, 2, 3});
  const std::vector<uint32_t> hashes = FlowHashes(20000);
  std::vector<uint32_t> before;
  for (uint32_t h : hashes) before.push_back(g.Select(h));
  g.SetActiveMembers(std::vector<uint32_t>{1, 2, 3, 4});
  size_t moved = 0;
  for (size_t i = 0; i < hashes.size(); ++i) {
    const uint32_t after = g.Select(hashes[i]);
    if (after != before[i]) {
      ++moved;
      EXPECT_EQ(after, 4u);  // flows only move onto the new member
    }
  }
  EXPECT_NEAR(static_cast<double>(moved) / static_cast<double>(hashes.size()), 0.25, 0.03);
  EXPECT_EQ(g.BucketsOwnedBy(4), 64u);
}

TEST(EcmpTest, EmptyAndRefill) {
  EcmpGroup g;
  g.SetActiveMembers(std::vector<uint32_t>{7});
  EXPECT_EQ(g.Select(12345), 7u);
  g.SetActiveMembers(std::vector<uint32_t>{});
  EXPECT_TRUE(g.empty());
  g.SetActiveMembers(std::vector<uint32_t>{8, 9});
  EXPECT_EQ(g.BucketsOwnedBy(8), 128u);
}

}  // namespace
}  // namespace nanonos
