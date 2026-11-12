// Ingress ACL modelled on a TCAM: every rule becomes one or more
// value/mask entries over a packed lookup key, matched in priority order.
// L4 port ranges are expanded into prefixes (range-to-prefix expansion), so a
// rule like "dport 1024-65535" costs several TCAM entries -- the same trade-off
// hardware ACLs make.
#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include "common/status.h"
#include "common/types.h"

namespace nanonos {

struct PortRange {
  uint16_t lo = 0;
  uint16_t hi = 65535;
  bool any() const { return lo == 0 && hi == 65535; }
};

enum class AclAction : uint8_t { kPermit, kDeny, kSetTc };

struct AclRule {
  uint32_t seq = 0;  // lower sequence numbers are evaluated first
  AclAction action = AclAction::kPermit;
  uint8_t set_tc = 0;
  Ipv4Prefix src{};  // /0 matches any address
  Ipv4Prefix dst{};
  int ip_proto = -1;  // -1 = any
  PortRange src_ports;
  PortRange dst_ports;
  int dscp = -1;
  int in_port = -1;
};

struct AclLookupKey {
  uint32_t src_ip = 0;
  uint32_t dst_ip = 0;
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint8_t ip_proto = 0;
  uint8_t dscp = 0;
  uint16_t in_port = 0;
};

struct AclResult {
  AclAction action;
  uint8_t set_tc;
  uint32_t seq;
};

class AclTable {
 public:
  explicit AclTable(size_t tcam_entries) : capacity_(tcam_entries) {}

  Status AddRule(const AclRule& rule);
  Status RemoveRule(uint32_t seq);
  // First matching rule, or nullptr. Counts a hit on the matched rule.
  const AclResult* Lookup(const AclLookupKey& key);

  size_t entries_used() const { return entries_.size(); }
  size_t capacity() const { return capacity_; }
  size_t rule_count() const { return rules_.size(); }
  uint64_t hits(uint32_t seq) const;
  // TCAM entries a rule would need (product of its port-range expansions).
  static size_t EntriesNeeded(const AclRule& rule);
  // Minimal set of (value, mask) prefixes covering [lo, hi].
  static std::vector<std::pair<uint16_t, uint16_t>> ExpandRange(PortRange range);

  template <typename F>
  void ForEachRule(F&& f) const {
    for (const Rule& r : rules_) f(r.rule, r.hits, r.entry_count);
  }

 private:
  struct Rule {
    AclRule rule;
    AclResult result;
    uint64_t hits = 0;
    size_t entry_count = 0;
  };
  struct Entry {
    uint64_t value[2];
    uint64_t mask[2];
    size_t rule_index;
  };

  void Rebuild();

  size_t capacity_;
  std::vector<Rule> rules_;  // sorted by seq
  std::vector<Entry> entries_;
};

}  // namespace nanonos
