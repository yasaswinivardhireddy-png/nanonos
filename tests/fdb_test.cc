#include <gtest/gtest.h>

#include "asic/bucket_hash.h"
#include "asic/fdb.h"
#include "common/hash.h"
#include "test_util.h"

namespace nanonos {
namespace {

using testing::Mac;

TEST(FdbTest, LearnsRefreshesAndMoves) {
  Fdb fdb(256, 4, 2, 8);
  EXPECT_EQ(fdb.Learn(10, Mac(0xa), 1, 100), LearnResult::kLearned);
  EXPECT_EQ(fdb.Learn(10, Mac(0xa), 1, 200), LearnResult::kRefreshed);
  EXPECT_EQ(fdb.Lookup(10, Mac(0xa))->port, 1);
  EXPECT_EQ(fdb.Lookup(20, Mac(0xa)), nullptr);  // per-VLAN
  EXPECT_EQ(fdb.Learn(10, Mac(0xa), 3, 300), LearnResult::kMoved);
  EXPECT_EQ(fdb.Lookup(10, Mac(0xa))->port, 3);
  EXPECT_EQ(fdb.PortCount(1), 0u);
  EXPECT_EQ(fdb.PortCount(3), 1u);
}

TEST(FdbTest, AgesOutDynamicEntriesButNotStatic) {
  Fdb fdb(256, 4, 2, 8);
  fdb.Learn(1, Mac(0xa), 1, 0);
  fdb.Learn(1, Mac(0xb), 1, 5 * kUsPerSec);
  ASSERT_EQ(fdb.AddStatic(1, Mac(0xc), 2), Status::kOk);
  EXPECT_EQ(fdb.Age(8 * kUsPerSec, 6 * kUsPerSec), 1u);
  EXPECT_EQ(fdb.Lookup(1, Mac(0xa)), nullptr);
  EXPECT_NE(fdb.Lookup(1, Mac(0xb)), nullptr);
  EXPECT_EQ(fdb.FlushAll(), 1u);
  EXPECT_NE(fdb.Lookup(1, Mac(0xc)), nullptr);  // static entries survive flushes
}

TEST(FdbTest, PortSecurityLimitsMacsPerPort) {
  Fdb fdb(256, 4, 2, 8);
  fdb.SetPortLimit(2, 2);
  EXPECT_EQ(fdb.Learn(1, Mac(1), 2, 0), LearnResult::kLearned);
  EXPECT_EQ(fdb.Learn(1, Mac(2), 2, 0), LearnResult::kLearned);
  EXPECT_EQ(fdb.Learn(1, Mac(3), 2, 0), LearnResult::kPortLimit);
  EXPECT_EQ(fdb.Learn(1, Mac(1), 2, 1), LearnResult::kRefreshed);  // known MACs still pass
  ASSERT_EQ(fdb.AddStatic(1, Mac(9), 4), Status::kOk);
  EXPECT_EQ(fdb.Learn(1, Mac(9), 5, 0), LearnResult::kStaticConflict);
}

struct U64Hash {
  uint64_t operator()(uint64_t k) const { return Mix64(k); }
};

// Fills a table with random keys until the first hash-collision failure and
// returns the load reached, the way an ASIC FDB fills up.
double LoadAtFirstCollision(int choices) {
  BucketHashTable<uint64_t, int, U64Hash> table(4096, 4, choices);
  Xorshift rng(42);
  while (true) {
    if (table.Insert(rng.Next(), 0) == Status::kTableFull) {
      return static_cast<double>(table.size()) / static_cast<double>(table.capacity());
    }
  }
}

TEST(BucketHashTest, TwoChoiceCuckooHashingDefersCollisions) {
  const double one = LoadAtFirstCollision(1);
  const double two = LoadAtFirstCollision(2);
  // With 4-way buckets, a single hash overflows one bucket early; two choices
  // with cuckoo displacement keep inserting until the table is nearly full.
  EXPECT_LT(one, 0.6);
  EXPECT_GT(two, 0.9);
  std::printf(
      "4-way buckets, load at first collision: 1 choice %.1f%%, 2 choices + cuckoo %.1f%%\n",
      one * 100, two * 100);
}

TEST(BucketHashTest, EraseAndReinsert) {
  BucketHashTable<uint64_t, int, U64Hash> table(64, 2, 2);
  for (uint64_t k = 0; k < 64; ++k) ASSERT_EQ(table.Insert(k, static_cast<int>(k)), Status::kOk);
  EXPECT_EQ(table.Insert(5, 0), Status::kAlreadyExists);
  EXPECT_TRUE(table.Erase(5));
  EXPECT_FALSE(table.Erase(5));
  EXPECT_EQ(table.Find(5), nullptr);
  EXPECT_EQ(*table.Find(6), 6);
  EXPECT_EQ(table.EraseIf([](uint64_t k, int) { return k % 2 == 0; }), 32u);
  EXPECT_EQ(table.size(), 31u);
}

}  // namespace
}  // namespace nanonos
