// ECMP next-hop group with resilient (consistent) hashing.
//
// Flows hash into kBuckets buckets and each bucket is owned by one member.
// When a member leaves, only its buckets are reassigned, so flows on the
// surviving members keep their path (no TCP reordering, no RoCE retransmits).
// Plain modulo hashing is kept as a mode to measure the difference: with
// modulo, removing 1 of N members moves about (N-1)/N of all flows.
#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace nanonos {

class EcmpGroup {
 public:
  static constexpr uint32_t kBuckets = 256;
  enum class Mode : uint8_t { kResilient, kModulo };

  EcmpGroup() = default;
  explicit EcmpGroup(Mode mode) : mode_(mode) {}

  // Replaces the set of usable members (next-hop ids; order does not matter).
  void SetActiveMembers(std::span<const uint32_t> members);

  bool empty() const { return active_.empty(); }
  size_t size() const { return active_.size(); }
  std::span<const uint32_t> active() const { return active_; }

  // Precondition: !empty().
  uint32_t Select(uint32_t hash) const {
    if (mode_ == Mode::kModulo) return active_[hash % active_.size()];
    return buckets_[(hash ^ (hash >> 8) ^ (hash >> 16) ^ (hash >> 24)) & (kBuckets - 1)];
  }

  uint32_t BucketsOwnedBy(uint32_t member) const;

 private:
  Mode mode_ = Mode::kResilient;
  std::vector<uint32_t> active_;  // sorted
  std::array<uint32_t, kBuckets> buckets_{};
};

}  // namespace nanonos
