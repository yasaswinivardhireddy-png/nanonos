// IPv4 longest-prefix-match table: a stride-8 multibit trie with controlled
// prefix expansion, the classic algorithmic-LPM layout used by routers.
//
// A lookup is at most 4 dependent memory reads (one per address byte). Nodes
// come from a pool sized at construction, so programming a route never
// allocates trie memory, and running out of nodes is reported as kTableFull,
// just like an ASIC running out of LPM memory.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

#include "common/status.h"
#include "common/types.h"

namespace nanonos {

class LpmTable {
 public:
  static constexpr uint32_t kMaxValue = (1u << 24) - 1;

  LpmTable(size_t max_routes, size_t max_nodes);

  // Adds a route or replaces the value of an existing one. All-or-nothing: on
  // kTableFull the table is unchanged.
  Status Insert(const Ipv4Prefix& prefix, uint32_t value);
  Status Remove(const Ipv4Prefix& prefix);
  std::optional<uint32_t> Get(const Ipv4Prefix& prefix) const;

  std::optional<uint32_t> Lookup(uint32_t addr) const {
    uint32_t e = nodes_[0][addr >> 24];
    if (e & kChild) {
      e = nodes_[e & kIndexMask][(addr >> 16) & 0xff];
      if (e & kChild) {
        e = nodes_[e & kIndexMask][(addr >> 8) & 0xff];
        if (e & kChild) e = nodes_[e & kIndexMask][addr & 0xff];
      }
    }
    if (e & kValid) return e & kIndexMask;
    return std::nullopt;
  }

  size_t size() const { return rules_.size(); }
  size_t max_routes() const { return max_routes_; }
  size_t nodes_in_use() const { return nodes_.size() - free_nodes_.size(); }
  size_t max_nodes() const { return nodes_.size(); }
  size_t memory_bytes() const { return nodes_.size() * sizeof(Node); }

  template <typename F>
  void ForEach(F&& f) const {
    for (const auto& [key, value] : rules_) {
      f(Ipv4Prefix{static_cast<uint32_t>(key >> 8), static_cast<uint8_t>(key & 0xff)}, value);
    }
  }

 private:
  using Node = std::array<uint32_t, 256>;
  // Entry encoding: a leaf holds valid | depth (prefix length) | value; a child
  // pointer holds the child flag and the node index.
  static constexpr uint32_t kValid = 1u << 31;
  static constexpr uint32_t kChild = 1u << 30;
  static constexpr int kDepthShift = 24;
  static constexpr uint32_t kIndexMask = 0x00ffffff;

  static uint32_t Leaf(int depth, uint32_t value) {
    return kValid | (static_cast<uint32_t>(depth) << kDepthShift) | value;
  }
  static int Depth(uint32_t entry) { return static_cast<int>((entry >> kDepthShift) & 0x3f); }
  static int LevelOf(int len) { return len == 0 ? 0 : (len - 1) / 8; }
  static uint32_t ByteAt(uint32_t addr, int level) { return (addr >> (24 - 8 * level)) & 0xff; }
  static uint64_t Key(const Ipv4Prefix& p) { return (uint64_t{p.addr} << 8) | p.len; }

  uint32_t AllocNode(uint32_t fill);
  void WriteEntry(uint32_t node, uint32_t slot, int depth, uint32_t value);
  void ReplaceEntry(uint32_t node, uint32_t slot, int level, int depth, uint32_t replacement);
  void MaybeCollapse(uint32_t parent, uint32_t slot, int child_level);

  std::vector<Node> nodes_;
  std::vector<uint32_t> free_nodes_;
  std::unordered_map<uint64_t, uint32_t> rules_;  // control-plane copy: (addr << 8 | len) -> value
  size_t max_routes_;
};

}  // namespace nanonos
