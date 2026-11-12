// Fixed-capacity bucketized hash table modelled on switch ASIC exact-match
// tables (L2 FDB, neighbor/host table).
//
// Memory is allocated once at construction and inserts never allocate. A key
// hashes to `choices` (1 or 2) candidate buckets of `ways` slots each. An
// insert goes to the least-loaded candidate; when both are full it displaces
// residents to their alternate buckets (bounded cuckoo kicks), and only fails
// with kTableFull if no path to a free slot is found. A single hash function
// overflows a bucket early (a "hash collision" while the table still has free
// entries); two choices plus displacement fill the table almost completely.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include "common/hash.h"
#include "common/status.h"

namespace nanonos {

template <typename Key, typename Value, typename Hash>
class BucketHashTable {
 public:
  BucketHashTable(size_t buckets, size_t ways, int choices)
      : bucket_mask_(RoundUpPow2(buckets) - 1),
        ways_(ways == 0 ? 1 : ways),
        choices_(choices >= 2 ? 2 : 1),
        slots_((bucket_mask_ + 1) * ways_) {}

  size_t capacity() const { return slots_.size(); }
  size_t size() const { return size_; }
  uint64_t collision_failures() const { return collision_failures_; }

  Value* Find(const Key& key) {
    const uint64_t h = Hash{}(key);
    for (int c = 0; c < choices_; ++c) {
      Slot* bucket = &slots_[BucketIndex(h, c) * ways_];
      for (size_t w = 0; w < ways_; ++w) {
        if (bucket[w].used && bucket[w].key == key) return &bucket[w].value;
      }
    }
    return nullptr;
  }
  const Value* Find(const Key& key) const { return const_cast<BucketHashTable*>(this)->Find(key); }

  Status Insert(const Key& key, const Value& value) {
    if (Find(key) != nullptr) return Status::kAlreadyExists;
    return InsertNew(key, value);
  }

  // Inserts, or overwrites the value of an existing key.
  Status Upsert(const Key& key, const Value& value) {
    if (Value* existing = Find(key)) {
      *existing = value;
      return Status::kOk;
    }
    return InsertNew(key, value);
  }

  bool Erase(const Key& key) {
    const uint64_t h = Hash{}(key);
    for (int c = 0; c < choices_; ++c) {
      Slot* bucket = &slots_[BucketIndex(h, c) * ways_];
      for (size_t w = 0; w < ways_; ++w) {
        if (bucket[w].used && bucket[w].key == key) {
          bucket[w] = Slot{};
          --size_;
          return true;
        }
      }
    }
    return false;
  }

  template <typename F>
  void ForEach(F&& f) const {
    for (const Slot& s : slots_) {
      if (s.used) f(s.key, s.value);
    }
  }

  template <typename F>
  void ForEachMutable(F&& f) {
    for (Slot& s : slots_) {
      if (s.used) f(s.key, s.value);
    }
  }

  // Removes every entry for which pred(key, value) is true.
  template <typename Pred>
  size_t EraseIf(Pred&& pred) {
    size_t removed = 0;
    for (Slot& s : slots_) {
      if (s.used && pred(s.key, s.value)) {
        s = Slot{};
        ++removed;
      }
    }
    size_ -= removed;
    return removed;
  }

 private:
  struct Slot {
    Key key{};
    Value value{};
    bool used = false;
  };
  static constexpr size_t kMaxKicks = 64;

  static size_t RoundUpPow2(size_t n) {
    size_t p = 1;
    while (p < n) p <<= 1;
    return p;
  }

  // The second bucket comes from an independent remix of the hash.
  size_t BucketIndex(uint64_t h, int choice) const {
    const uint64_t index = choice == 0 ? h : Mix64(h ^ 0x9e3779b97f4a7c15ULL);
    return static_cast<size_t>(index & bucket_mask_);
  }

  Slot* FreeSlot(size_t bucket, size_t* load) {
    Slot* first = &slots_[bucket * ways_];
    Slot* free_slot = nullptr;
    *load = 0;
    for (size_t w = 0; w < ways_; ++w) {
      if (first[w].used) {
        ++*load;
      } else if (free_slot == nullptr) {
        free_slot = &first[w];
      }
    }
    return free_slot;
  }

  Status InsertNew(const Key& key, const Value& value) {
    const uint64_t h = Hash{}(key);
    Slot* best = nullptr;
    size_t best_load = ways_ + 1;
    for (int c = 0; c < choices_; ++c) {
      size_t load = 0;
      Slot* free_slot = FreeSlot(BucketIndex(h, c), &load);
      if (free_slot != nullptr && load < best_load) {
        best = free_slot;
        best_load = load;
      }
    }
    if (best != nullptr) {
      *best = Slot{key, value, true};
      ++size_;
      return Status::kOk;
    }
    if (choices_ < 2) {
      ++collision_failures_;
      return Status::kTableFull;
    }
    // Cuckoo displacement: evict a resident into its alternate bucket, repeat.
    Slot carry{key, value, true};
    size_t bucket = BucketIndex(h, 0);
    std::array<size_t, kMaxKicks> path{};
    size_t steps = 0;
    for (; steps < kMaxKicks; ++steps) {
      // A pseudo-random victim keeps the walk from cycling between two buckets.
      const size_t victim = bucket * ways_ + static_cast<size_t>(Mix64(++kick_counter_) % ways_);
      std::swap(carry, slots_[victim]);
      path[steps] = victim;
      const uint64_t ch = Hash{}(carry.key);
      const size_t b0 = BucketIndex(ch, 0);
      const size_t alt = b0 == bucket ? BucketIndex(ch, 1) : b0;
      size_t load = 0;
      if (Slot* free_slot = FreeSlot(alt, &load)) {
        *free_slot = carry;
        ++size_;
        return Status::kOk;
      }
      bucket = alt;
    }
    // No free slot within reach: undo every move so the table is unchanged.
    for (size_t i = steps; i-- > 0;) std::swap(carry, slots_[path[i]]);
    ++collision_failures_;
    return Status::kTableFull;
  }

  size_t bucket_mask_;
  size_t ways_;
  int choices_;
  std::vector<Slot> slots_;
  size_t size_ = 0;
  uint64_t collision_failures_ = 0;
  uint64_t kick_counter_ = 0;
};

}  // namespace nanonos
