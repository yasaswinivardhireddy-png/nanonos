#include <array>
#include <vector>

#include <gtest/gtest.h>

#include "asic/policer.h"
#include "asic/qos.h"
#include "common/byte_order.h"
#include "test_util.h"

namespace nanonos {
namespace {

using testing::Ip;
using testing::Mac;

class QueueFixture : public ::testing::Test {
 protected:
  QueueFixture() : pool_(4096), queues_(1024, 1 << 30) {}

  uint32_t Packet(uint16_t len, uint8_t ecn = 0) {
    const uint32_t id = pool_.Alloc();
    testing::Flow f{Mac(2), Mac(1), Ip("10.0.0.1"), Ip("10.0.0.2")};
    f.ecn = ecn;
    f.payload = static_cast<uint16_t>(len - 42);  // 14 Ethernet + 20 IPv4 + 8 UDP
    const auto frame = testing::FlowFrame(f);
    PacketBuffer& b = pool_[id];
    std::copy(frame.begin(), frame.end(), b.data.begin());
    b.len = static_cast<uint16_t>(frame.size());
    b.l3_offset = kEthHeaderLen;
    return id;
  }

  PacketPool pool_;
  EgressQueues queues_;
  Xorshift rng_;
};

TEST_F(QueueFixture, StrictPriorityServesHighestQueueFirst) {
  SchedulerConfig s;
  s.strict_mask = (1 << 7) | (1 << 5);
  queues_.SetScheduler(s);
  const uint32_t low = Packet(100);
  const uint32_t mid = Packet(100);
  const uint32_t high = Packet(100);
  queues_.Enqueue(0, low, pool_, rng_);
  queues_.Enqueue(5, mid, pool_, rng_);
  queues_.Enqueue(7, high, pool_, rng_);
  EXPECT_EQ(queues_.Dequeue(pool_), high);
  EXPECT_EQ(queues_.Dequeue(pool_), mid);
  EXPECT_EQ(queues_.Dequeue(pool_), low);
  EXPECT_EQ(queues_.Dequeue(pool_), PacketPool::kInvalid);
}

TEST_F(QueueFixture, DwrrSharesBandwidthByWeight) {
  SchedulerConfig s;
  s.weights = {1, 2, 4, 1, 1, 1, 1, 1};
  queues_.SetScheduler(s);
  // Keep three queues backlogged with mixed packet sizes and count bytes served.
  std::array<uint64_t, kNumQueues> served{};
  const uint16_t sizes[] = {64, 300, 1500, 900};
  for (int q = 0; q < 3; ++q) {
    for (int i = 0; i < 300; ++i) queues_.Enqueue(q, Packet(sizes[i % 4]), pool_, rng_);
  }
  for (int i = 0; i < 400; ++i) {
    const uint32_t id = queues_.Dequeue(pool_);
    ASSERT_NE(id, PacketPool::kInvalid);
    pool_.Free(id);
  }
  for (int q = 0; q < 3; ++q) served[static_cast<size_t>(q)] = queues_.counters(q).deq_bytes;
  const double total = static_cast<double>(served[0] + served[1] + served[2]);
  EXPECT_NEAR(served[0] / total, 1.0 / 7, 0.02);
  EXPECT_NEAR(served[1] / total, 2.0 / 7, 0.02);
  EXPECT_NEAR(served[2] / total, 4.0 / 7, 0.02);
}

TEST_F(QueueFixture, WredMarksEcnCapableTrafficAndDropsTheRest) {
  WredProfile w;
  w.enabled = true;
  w.ecn = true;
  w.min_bytes = 10'000;
  w.max_bytes = 50'000;
  w.max_prob_pct = 20;
  queues_.SetWred(3, w);
  // Fill to the midpoint between min and max with ECN-capable traffic.
  while (queues_.counters(3).depth_bytes < 30'000) queues_.Enqueue(3, Packet(1000, 2), pool_, rng_);
  const uint64_t marked_before = queues_.counters(3).ecn_marked;
  int marked = 0;
  int dropped = 0;
  for (int i = 0; i < 4000; ++i) {
    const uint32_t ect = Packet(1000, 2);
    const EnqueueResult r = queues_.Enqueue(3, ect, pool_, rng_);
    if (r == EnqueueResult::kMarked) {
      ++marked;
      PacketBuffer& b = pool_[ect];
      EXPECT_EQ(b.data[kEthHeaderLen + 1] & 3, kEcnCe);
      EXPECT_EQ(InternetChecksum(b.data.data() + kEthHeaderLen, 20), 0);
    }
    // Keep the depth constant: remove one packet per packet added.
    pool_.Free(queues_.Dequeue(pool_));
    const uint32_t legacy = Packet(1000, 0);
    const EnqueueResult r2 = queues_.Enqueue(3, legacy, pool_, rng_);
    if (r2 == EnqueueResult::kWredDrop) {
      ++dropped;
      pool_.Free(legacy);
    } else {
      pool_.Free(queues_.Dequeue(pool_));
    }
  }
  EXPECT_GT(queues_.counters(3).ecn_marked, marked_before);
  // At the midpoint the probability is about half of max_prob (10%).
  EXPECT_NEAR(marked / 4000.0, 0.10, 0.03);
  EXPECT_NEAR(dropped / 4000.0, 0.10, 0.03);
}

TEST_F(QueueFixture, TailDropAtByteLimit) {
  EgressQueues small(1024, 5000);
  int accepted = 0;
  for (int i = 0; i < 10; ++i) {
    const uint32_t id = Packet(1000);
    if (small.Enqueue(0, id, pool_, rng_) == EnqueueResult::kEnqueued) {
      ++accepted;
    } else {
      pool_.Free(id);
    }
  }
  EXPECT_EQ(accepted, 5);  // 5 x 1000-byte frames fill the 5000-byte limit exactly
  EXPECT_EQ(small.counters(0).tail_drops, 5u);
}

TEST(PolicerTest, SrTcmEnforcesCommittedRate) {
  // 1000 packets per second, burst 100.
  SrTcmPolicer p(1000, 100, 0, 0);
  int green = 0;
  // Offer 5000 packets over one second (5x the rate).
  for (int i = 0; i < 5000; ++i) {
    if (p.Meter(1, static_cast<TimeUs>(i) * 200) == Color::kGreen) ++green;
  }
  EXPECT_NEAR(green, 1100, 20);  // one second of rate plus the initial burst
}

TEST(PolicerTest, ExcessBurstGivesYellow) {
  SrTcmPolicer p(1000, 10, 10, 0);
  int green = 0;
  int yellow = 0;
  for (int i = 0; i < 30; ++i) {
    const Color c = p.Meter(1, 0);
    green += c == Color::kGreen;
    yellow += c == Color::kYellow;
  }
  EXPECT_EQ(green, 10);
  EXPECT_EQ(yellow, 10);
}

TEST(ShaperTest, LimitsPortRate) {
  Shaper s;
  s.Configure(8'000'000, 0);  // 1 MB/s
  uint64_t sent = 0;
  for (TimeUs t = 0; t < kUsPerSec; t += 100) {
    while (s.CanSend(t)) {
      s.Charge(1000);
      sent += 1000;
    }
  }
  EXPECT_NEAR(static_cast<double>(sent), 1'000'000.0, 20'000.0);
}

}  // namespace
}  // namespace nanonos
