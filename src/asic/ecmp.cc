#include "asic/ecmp.h"

#include <algorithm>

namespace nanonos {

void EcmpGroup::SetActiveMembers(std::span<const uint32_t> members) {
  std::vector<uint32_t> next(members.begin(), members.end());
  std::sort(next.begin(), next.end());
  next.erase(std::unique(next.begin(), next.end()), next.end());
  const bool was_empty = active_.empty();
  active_ = std::move(next);
  if (active_.empty() || mode_ == Mode::kModulo) return;

  const size_t n = active_.size();
  if (was_empty) {
    for (uint32_t b = 0; b < kBuckets; ++b) buckets_[b] = active_[b % n];
    return;
  }

  // Each member's fair share: kBuckets / n, with the remainder spread over the
  // first members.
  const auto index_of = [&](uint32_t member) -> int {
    const auto it = std::lower_bound(active_.begin(), active_.end(), member);
    return (it != active_.end() && *it == member) ? static_cast<int>(it - active_.begin()) : -1;
  };
  const auto target = [&](size_t i) {
    return static_cast<uint32_t>(kBuckets / n + (i < kBuckets % n ? 1 : 0));
  };

  std::vector<uint32_t> counts(n, 0);
  std::vector<uint32_t> unassigned;
  // 1. Buckets whose owner left become free; everything else stays put.
  for (uint32_t b = 0; b < kBuckets; ++b) {
    const int i = index_of(buckets_[b]);
    if (i < 0) {
      unassigned.push_back(b);
    } else {
      ++counts[static_cast<size_t>(i)];
    }
  }
  // 2. Members above their share (only after members were added) give up buckets.
  for (uint32_t b = 0; b < kBuckets; ++b) {
    const int i = index_of(buckets_[b]);
    if (i >= 0 && counts[static_cast<size_t>(i)] > target(static_cast<size_t>(i))) {
      --counts[static_cast<size_t>(i)];
      unassigned.push_back(b);
    }
  }
  // 3. Free buckets go to members below their share.
  size_t next_member = 0;
  for (uint32_t b : unassigned) {
    while (counts[next_member] >= target(next_member)) next_member = (next_member + 1) % n;
    buckets_[b] = active_[next_member];
    ++counts[next_member];
  }
}

uint32_t EcmpGroup::BucketsOwnedBy(uint32_t member) const {
  if (mode_ == Mode::kModulo) return 0;
  uint32_t owned = 0;
  for (uint32_t b : buckets_) owned += (b == member && !active_.empty()) ? 1 : 0;
  return owned;
}

}  // namespace nanonos
