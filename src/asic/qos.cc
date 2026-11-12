#include "asic/qos.h"

namespace nanonos {
namespace {

// One DWRR quantum per unit of weight; at least one maximum-size frame so a
// queue always makes progress in a single round.
constexpr int64_t kQuantumBytes = static_cast<int64_t>(kMaxFrameSize);

uint32_t RoundUpPow2(uint32_t n) {
  uint32_t p = 1;
  while (p < n) p <<= 1;
  return p;
}

}  // namespace

EgressQueues::EgressQueues(uint32_t capacity_pkts, uint32_t limit_bytes)
    : limit_bytes_(limit_bytes) {
  for (Ring& r : rings_) r.slots.assign(RoundUpPow2(capacity_pkts == 0 ? 1 : capacity_pkts), 0);
}

EnqueueResult EgressQueues::Enqueue(int queue, uint32_t id, PacketPool& pool, Xorshift& rng) {
  const size_t q = static_cast<size_t>(queue);
  Ring& ring = rings_[q];
  QueueCounters& c = counters_[q];
  PacketBuffer& buf = pool[id];
  const uint32_t depth = c.depth_bytes;
  if (ring.count == ring.slots.size() || depth + buf.len > limit_bytes_) {
    ++c.tail_drops;
    return EnqueueResult::kTailDrop;
  }

  EnqueueResult result = EnqueueResult::kEnqueued;
  const WredProfile& w = wred_[q];
  if (w.enabled && depth >= w.min_bytes) {
    bool hit = depth >= w.max_bytes;
    if (!hit && w.max_bytes > w.min_bytes) {
      const uint64_t span = uint64_t{w.max_bytes - w.min_bytes};
      hit = rng.Below(100 * span) < uint64_t{w.max_prob_pct} * (depth - w.min_bytes);
    }
    if (hit) {
      uint8_t* ip = buf.l3_offset != 0 ? buf.data.data() + buf.l3_offset : nullptr;
      const bool ect = ip != nullptr && (ip[1] & 0x03) != kEcnNotEct;
      if (w.ecn && ect) {
        if ((ip[1] & 0x03) != kEcnCe) MarkEcnCe(ip);
        ++c.ecn_marked;
        result = EnqueueResult::kMarked;
      } else {
        ++c.wred_drops;
        return EnqueueResult::kWredDrop;
      }
    }
  }

  ring.slots[(ring.head + ring.count) & (ring.slots.size() - 1)] = id;
  ++ring.count;
  ++total_pkts_;
  ++c.enq_pkts;
  c.enq_bytes += buf.len;
  c.depth_bytes += buf.len;
  if (c.depth_bytes > c.watermark_bytes) c.watermark_bytes = c.depth_bytes;
  return result;
}

uint32_t EgressQueues::Pop(int q, PacketPool& pool) {
  Ring& ring = rings_[static_cast<size_t>(q)];
  const uint32_t id = ring.slots[ring.head];
  ring.head = (ring.head + 1) & static_cast<uint32_t>(ring.slots.size() - 1);
  --ring.count;
  --total_pkts_;
  QueueCounters& c = counters_[static_cast<size_t>(q)];
  const uint16_t len = pool[id].len;
  ++c.deq_pkts;
  c.deq_bytes += len;
  c.depth_bytes -= len;
  return id;
}

uint32_t EgressQueues::Dequeue(PacketPool& pool) {
  if (total_pkts_ == 0) return PacketPool::kInvalid;
  // Strict-priority queues first, highest queue index wins.
  for (int q = kNumQueues - 1; q >= 0; --q) {
    if ((sched_.strict_mask & (1u << q)) && !QueueEmpty(q)) return Pop(q, pool);
  }
  // Deficit weighted round robin over the remaining queues. Bounded: every
  // visit to a non-empty queue adds at least one maximum-size frame of credit.
  for (int visits = 0; visits < 4 * kNumQueues; ++visits) {
    const int q = dwrr_current_;
    const size_t qi = static_cast<size_t>(q);
    const bool strict = (sched_.strict_mask & (1u << q)) != 0;
    if (strict || QueueEmpty(q)) {
      deficit_[qi] = 0;
      quantum_added_[qi] = false;
      dwrr_current_ = (q + 1) % kNumQueues;
      continue;
    }
    if (!quantum_added_[qi]) {
      const uint16_t weight = sched_.weights[qi] == 0 ? 1 : sched_.weights[qi];
      deficit_[qi] += kQuantumBytes * weight;
      quantum_added_[qi] = true;
    }
    const Ring& ring = rings_[qi];
    const uint16_t head_len = pool[ring.slots[ring.head]].len;
    if (head_len <= deficit_[qi]) {
      deficit_[qi] -= head_len;
      const uint32_t id = Pop(q, pool);
      if (QueueEmpty(q)) {
        deficit_[qi] = 0;
        quantum_added_[qi] = false;
        dwrr_current_ = (q + 1) % kNumQueues;
      }
      return id;
    }
    quantum_added_[qi] = false;  // credit carries over to the next round
    dwrr_current_ = (q + 1) % kNumQueues;
  }
  return PacketPool::kInvalid;  // unreachable with a non-empty queue
}

void EgressQueues::Flush(PacketPool& pool) {
  for (int q = 0; q < kNumQueues; ++q) {
    while (!QueueEmpty(q)) {
      const uint32_t id = Pop(q, pool);
      ++counters_[static_cast<size_t>(q)].tail_drops;
      pool.Free(id);
    }
    deficit_[static_cast<size_t>(q)] = 0;
    quantum_added_[static_cast<size_t>(q)] = false;
  }
}

void EgressQueues::ClearCounters() {
  for (QueueCounters& c : counters_) {
    const uint32_t depth = c.depth_bytes;
    c = QueueCounters{};
    c.depth_bytes = depth;
    c.watermark_bytes = depth;
  }
}

}  // namespace nanonos
