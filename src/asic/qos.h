// Packet buffers and egress queueing: 8 queues per port, WRED with ECN
// marking, and a strict-priority + deficit-weighted-round-robin scheduler.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "common/hash.h"
#include "packet/packet.h"

namespace nanonos {

inline constexpr int kNumQueues = 8;

struct PacketBuffer {
  uint16_t len = 0;
  uint16_t l3_offset = 0;  // offset of the IPv4 header, 0 if not IPv4
  std::array<uint8_t, kMaxFrameSize> data;
};

// Preallocated buffer pool: the data path never calls malloc.
class PacketPool {
 public:
  static constexpr uint32_t kInvalid = 0xffffffff;

  explicit PacketPool(size_t count) : buffers_(count) {
    free_.reserve(count);
    for (size_t i = count; i > 0; --i) free_.push_back(static_cast<uint32_t>(i - 1));
  }
  uint32_t Alloc() {
    if (free_.empty()) return kInvalid;
    const uint32_t id = free_.back();
    free_.pop_back();
    return id;
  }
  void Free(uint32_t id) { free_.push_back(id); }
  PacketBuffer& operator[](uint32_t id) { return buffers_[id]; }
  size_t available() const { return free_.size(); }
  size_t capacity() const { return buffers_.size(); }

 private:
  std::vector<PacketBuffer> buffers_;
  std::vector<uint32_t> free_;
};

// Weighted random early detection on instantaneous queue depth. Between
// min_bytes and max_bytes the mark/drop probability rises linearly to
// max_prob_pct; above max_bytes every packet is marked (ECN-capable) or dropped.
struct WredProfile {
  bool enabled = false;
  bool ecn = true;  // mark ECN-capable packets instead of dropping them
  uint32_t min_bytes = 0;
  uint32_t max_bytes = 0;
  uint32_t max_prob_pct = 0;
};

struct SchedulerConfig {
  uint8_t strict_mask = 0;  // bit q set: queue q is strict priority (higher q first)
  std::array<uint16_t, kNumQueues> weights{1, 1, 1, 1, 1, 1, 1, 1};  // DWRR weights
};

struct QueueCounters {
  uint64_t enq_pkts = 0;
  uint64_t enq_bytes = 0;
  uint64_t deq_pkts = 0;
  uint64_t deq_bytes = 0;
  uint64_t tail_drops = 0;
  uint64_t wred_drops = 0;
  uint64_t ecn_marked = 0;
  uint32_t depth_bytes = 0;
  uint32_t watermark_bytes = 0;
};

enum class EnqueueResult : uint8_t { kEnqueued, kMarked, kTailDrop, kWredDrop };

class EgressQueues {
 public:
  EgressQueues(uint32_t capacity_pkts, uint32_t limit_bytes);

  // On a drop the caller still owns (and must free) the buffer.
  EnqueueResult Enqueue(int queue, uint32_t id, PacketPool& pool, Xorshift& rng);
  uint32_t Dequeue(PacketPool& pool);  // PacketPool::kInvalid when empty
  bool empty() const { return total_pkts_ == 0; }
  uint32_t total_pkts() const { return total_pkts_; }
  void Flush(PacketPool& pool);

  void SetScheduler(const SchedulerConfig& config) { sched_ = config; }
  const SchedulerConfig& scheduler() const { return sched_; }
  void SetWred(int queue, const WredProfile& profile) {
    wred_[static_cast<size_t>(queue)] = profile;
  }
  const WredProfile& wred(int queue) const { return wred_[static_cast<size_t>(queue)]; }
  const QueueCounters& counters(int queue) const { return counters_[static_cast<size_t>(queue)]; }
  void ClearCounters();

 private:
  struct Ring {
    std::vector<uint32_t> slots;
    uint32_t head = 0;
    uint32_t count = 0;
  };
  bool QueueEmpty(int q) const { return rings_[static_cast<size_t>(q)].count == 0; }
  uint32_t Pop(int q, PacketPool& pool);

  uint32_t limit_bytes_;
  std::array<Ring, kNumQueues> rings_;
  std::array<WredProfile, kNumQueues> wred_{};
  std::array<QueueCounters, kNumQueues> counters_{};
  std::array<int64_t, kNumQueues> deficit_{};
  std::array<bool, kNumQueues> quantum_added_{};
  SchedulerConfig sched_;
  int dwrr_current_ = 0;
  uint32_t total_pkts_ = 0;
};

}  // namespace nanonos
