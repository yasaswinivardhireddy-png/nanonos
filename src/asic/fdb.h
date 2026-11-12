// L2 forwarding database: MAC learning, moves, aging and per-port MAC limits
// (port security) on top of a hardware-style bucketized hash table.
#pragma once

#include <cstdint>
#include <vector>

#include "asic/bucket_hash.h"
#include "common/clock.h"
#include "common/hash.h"
#include "common/types.h"

namespace nanonos {

struct FdbKey {
  uint16_t vlan = 0;
  MacAddress mac;
  friend bool operator==(const FdbKey&, const FdbKey&) = default;
};

struct FdbKeyHash {
  uint64_t operator()(const FdbKey& k) const {
    return Mix64(k.mac.ToU64() | (uint64_t{k.vlan} << 48));
  }
};

struct FdbEntry {
  uint16_t port = 0;
  bool is_static = false;
  TimeUs last_seen = 0;
};

enum class LearnResult : uint8_t {
  kLearned,
  kRefreshed,
  kMoved,
  kTableFull,
  kPortLimit,       // port security: the port already has its maximum number of MACs
  kStaticConflict,  // a static entry pins this MAC to another port
};

class Fdb {
 public:
  Fdb(size_t buckets, size_t ways, int choices, size_t max_ports)
      : table_(buckets, ways, choices), port_count_(max_ports, 0), port_limit_(max_ports, 0) {}

  LearnResult Learn(uint16_t vlan, const MacAddress& mac, uint16_t port, TimeUs now) {
    const FdbKey key{vlan, mac};
    if (FdbEntry* e = table_.Find(key)) {
      if (e->port == port) {
        e->last_seen = now;
        return LearnResult::kRefreshed;
      }
      if (e->is_static) return LearnResult::kStaticConflict;
      if (AtLimit(port)) return LearnResult::kPortLimit;
      --port_count_[e->port];
      ++port_count_[port];
      e->port = port;
      e->last_seen = now;
      return LearnResult::kMoved;
    }
    if (AtLimit(port)) return LearnResult::kPortLimit;
    if (table_.Insert(key, FdbEntry{port, false, now}) != Status::kOk) {
      return LearnResult::kTableFull;
    }
    ++port_count_[port];
    return LearnResult::kLearned;
  }

  Status AddStatic(uint16_t vlan, const MacAddress& mac, uint16_t port) {
    const FdbKey key{vlan, mac};
    if (const FdbEntry* e = table_.Find(key); e != nullptr && !e->is_static) {
      --port_count_[e->port];
    }
    return table_.Upsert(key, FdbEntry{port, true, 0});
  }

  const FdbEntry* Lookup(uint16_t vlan, const MacAddress& mac) const {
    return table_.Find(FdbKey{vlan, mac});
  }

  // Removes dynamic entries not seen for `max_age`.
  size_t Age(TimeUs now, TimeUs max_age) {
    return EraseDynamic(
        [&](const FdbKey&, const FdbEntry& e) { return now - e.last_seen > max_age; });
  }
  size_t FlushPort(uint16_t port) {
    return EraseDynamic([&](const FdbKey&, const FdbEntry& e) { return e.port == port; });
  }
  size_t FlushVlan(uint16_t vlan) {
    return EraseDynamic([&](const FdbKey& k, const FdbEntry&) { return k.vlan == vlan; });
  }
  size_t FlushPortVlan(uint16_t port, uint16_t vlan) {
    return EraseDynamic(
        [&](const FdbKey& k, const FdbEntry& e) { return k.vlan == vlan && e.port == port; });
  }
  size_t FlushAll() {
    return EraseDynamic([](const FdbKey&, const FdbEntry&) { return true; });
  }

  void SetPortLimit(uint16_t port, uint32_t max_macs) { port_limit_[port] = max_macs; }
  uint32_t PortCount(uint16_t port) const { return port_count_[port]; }

  size_t size() const { return table_.size(); }
  size_t capacity() const { return table_.capacity(); }
  uint64_t collision_failures() const { return table_.collision_failures(); }

  template <typename F>
  void ForEach(F&& f) const {
    table_.ForEach(f);
  }

 private:
  bool AtLimit(uint16_t port) const {
    return port_limit_[port] != 0 && port_count_[port] >= port_limit_[port];
  }

  template <typename Pred>
  size_t EraseDynamic(Pred&& pred) {
    return table_.EraseIf([&](const FdbKey& k, const FdbEntry& e) {
      if (e.is_static || !pred(k, e)) return false;
      --port_count_[e.port];
      return true;
    });
  }

  BucketHashTable<FdbKey, FdbEntry, FdbKeyHash> table_;
  std::vector<uint32_t> port_count_;  // dynamic entries per port
  std::vector<uint32_t> port_limit_;  // 0 = unlimited
};

}  // namespace nanonos
