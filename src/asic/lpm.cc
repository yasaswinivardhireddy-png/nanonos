#include "asic/lpm.h"

namespace nanonos {

LpmTable::LpmTable(size_t max_routes, size_t max_nodes)
    : nodes_(max_nodes < 1 ? 1 : max_nodes), max_routes_(max_routes) {
  nodes_[0].fill(0);
  free_nodes_.reserve(nodes_.size());
  for (size_t i = nodes_.size(); i > 1; --i) free_nodes_.push_back(static_cast<uint32_t>(i - 1));
}

uint32_t LpmTable::AllocNode(uint32_t fill) {
  const uint32_t index = free_nodes_.back();
  free_nodes_.pop_back();
  nodes_[index].fill(fill);
  return index;
}

Status LpmTable::Insert(const Ipv4Prefix& raw, uint32_t value) {
  if (raw.len > 32 || value > kMaxValue) return Status::kInvalidArgument;
  const Ipv4Prefix p = Ipv4Prefix::Make(raw.addr, raw.len);
  const auto it = rules_.find(Key(p));
  if (it == rules_.end() && rules_.size() >= max_routes_) return Status::kTableFull;

  // Count the trie nodes this prefix needs before changing anything.
  const int level = LevelOf(p.len);
  uint32_t node = 0;
  size_t needed = 0;
  for (int l = 0; l < level; ++l) {
    const uint32_t e = nodes_[node][ByteAt(p.addr, l)];
    if (!(e & kChild)) {
      needed = static_cast<size_t>(level - l);
      break;
    }
    node = e & kIndexMask;
  }
  if (needed > free_nodes_.size()) return Status::kTableFull;

  if (it == rules_.end()) {
    rules_.emplace(Key(p), value);
  } else {
    it->second = value;
  }

  node = 0;
  for (int l = 0; l < level; ++l) {
    const uint32_t slot = ByteAt(p.addr, l);
    const uint32_t e = nodes_[node][slot];
    if (!(e & kChild)) {
      // The new child inherits the shorter prefix that covered this slot.
      nodes_[node][slot] = kChild | AllocNode(e);
    }
    node = nodes_[node][slot] & kIndexMask;
  }
  const uint32_t first = ByteAt(p.addr, level);
  const uint32_t count = 1u << (8 * (level + 1) - p.len);
  for (uint32_t i = first; i < first + count; ++i) WriteEntry(node, i, p.len, value);
  return Status::kOk;
}

// Writes a leaf unless a longer prefix already owns the slot; recurses into
// children so the new prefix also fills their slots that only shorter
// prefixes covered.
void LpmTable::WriteEntry(uint32_t node, uint32_t slot, int depth, uint32_t value) {
  uint32_t& e = nodes_[node][slot];
  if (e & kChild) {
    const uint32_t child = e & kIndexMask;
    for (uint32_t i = 0; i < 256; ++i) WriteEntry(child, i, depth, value);
  } else if (!(e & kValid) || Depth(e) <= depth) {
    e = Leaf(depth, value);
  }
}

Status LpmTable::Remove(const Ipv4Prefix& raw) {
  if (raw.len > 32) return Status::kInvalidArgument;
  const Ipv4Prefix p = Ipv4Prefix::Make(raw.addr, raw.len);
  const auto it = rules_.find(Key(p));
  if (it == rules_.end()) return Status::kNotFound;
  rules_.erase(it);

  // The longest remaining prefix that covers the removed one takes over its slots.
  uint32_t replacement = 0;
  for (int l = p.len - 1; l >= 0; --l) {
    const auto parent = rules_.find(Key(Ipv4Prefix::Make(p.addr, l)));
    if (parent != rules_.end()) {
      replacement = Leaf(l, parent->second);
      break;
    }
  }

  const int level = LevelOf(p.len);
  uint32_t path[4] = {0, 0, 0, 0};
  uint32_t node = 0;
  for (int l = 0; l < level; ++l) {
    // The path exists: inserting the prefix created it, and a node is only
    // collapsed once it holds no prefix longer than its parent's level.
    node = nodes_[node][ByteAt(p.addr, l)] & kIndexMask;
    path[l + 1] = node;
  }
  const uint32_t first = ByteAt(p.addr, level);
  const uint32_t count = 1u << (8 * (level + 1) - p.len);
  for (uint32_t i = first; i < first + count; ++i) {
    ReplaceEntry(node, i, level, p.len, replacement);
  }
  for (int l = level; l >= 1; --l) MaybeCollapse(path[l - 1], ByteAt(p.addr, l - 1), l);
  return Status::kOk;
}

void LpmTable::ReplaceEntry(uint32_t node, uint32_t slot, int level, int depth,
                            uint32_t replacement) {
  uint32_t& e = nodes_[node][slot];
  if (e & kChild) {
    const uint32_t child = e & kIndexMask;
    for (uint32_t i = 0; i < 256; ++i) ReplaceEntry(child, i, level + 1, depth, replacement);
    MaybeCollapse(node, slot, level + 1);
  } else if ((e & kValid) && Depth(e) == depth) {
    e = replacement;
  }
}

// Folds a child back into its parent slot once all 256 entries are the same
// leaf inherited from a prefix no longer than the parent level, returning the
// node to the pool.
void LpmTable::MaybeCollapse(uint32_t parent, uint32_t slot, int child_level) {
  uint32_t& pe = nodes_[parent][slot];
  if (!(pe & kChild)) return;
  const uint32_t child = pe & kIndexMask;
  const Node& c = nodes_[child];
  const uint32_t first = c[0];
  if (first & kChild) return;
  if ((first & kValid) && Depth(first) > 8 * child_level) return;
  for (uint32_t i = 1; i < 256; ++i) {
    if (c[i] != first) return;
  }
  pe = first;
  free_nodes_.push_back(child);
}

std::optional<uint32_t> LpmTable::Get(const Ipv4Prefix& prefix) const {
  const auto it = rules_.find(Key(Ipv4Prefix::Make(prefix.addr, prefix.len)));
  if (it == rules_.end()) return std::nullopt;
  return it->second;
}

}  // namespace nanonos
