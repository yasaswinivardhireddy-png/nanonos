#include "asic/acl.h"

#include <algorithm>

namespace nanonos {
namespace {

// Packed key layout, the "TCAM word":
//   word 0: src_ip(32) | dst_ip(32)
//   word 1: src_port(16) | dst_port(16) | proto(8) | dscp(8) | in_port(16)
void PackKey(const AclLookupKey& k, uint64_t out[2]) {
  out[0] = (uint64_t{k.src_ip} << 32) | k.dst_ip;
  out[1] = (uint64_t{k.src_port} << 48) | (uint64_t{k.dst_port} << 32) |
           (uint64_t{k.ip_proto} << 24) | (uint64_t{k.dscp} << 16) | k.in_port;
}

}  // namespace

std::vector<std::pair<uint16_t, uint16_t>> AclTable::ExpandRange(PortRange range) {
  std::vector<std::pair<uint16_t, uint16_t>> out;
  uint32_t lo = range.lo;
  const uint32_t hi = range.hi;
  while (lo <= hi) {
    // Largest power-of-two block that starts at lo and ends at or before hi.
    uint32_t size = lo == 0 ? 0x10000 : (lo & (~lo + 1));
    while (lo + size - 1 > hi) size >>= 1;
    out.emplace_back(static_cast<uint16_t>(lo), static_cast<uint16_t>(~(size - 1) & 0xffff));
    lo += size;
  }
  return out;
}

size_t AclTable::EntriesNeeded(const AclRule& rule) {
  return ExpandRange(rule.src_ports).size() * ExpandRange(rule.dst_ports).size();
}

Status AclTable::AddRule(const AclRule& rule) {
  if (rule.src_ports.lo > rule.src_ports.hi || rule.dst_ports.lo > rule.dst_ports.hi) {
    return Status::kInvalidArgument;
  }
  for (const Rule& r : rules_) {
    if (r.rule.seq == rule.seq) return Status::kAlreadyExists;
  }
  const size_t needed = EntriesNeeded(rule);
  if (entries_.size() + needed > capacity_) return Status::kTableFull;
  Rule r;
  r.rule = rule;
  r.result = AclResult{rule.action, rule.set_tc, rule.seq};
  const auto pos = std::lower_bound(rules_.begin(), rules_.end(), rule.seq,
                                    [](const Rule& a, uint32_t seq) { return a.rule.seq < seq; });
  rules_.insert(pos, r);
  Rebuild();
  return Status::kOk;
}

Status AclTable::RemoveRule(uint32_t seq) {
  const auto it =
      std::find_if(rules_.begin(), rules_.end(), [&](const Rule& r) { return r.rule.seq == seq; });
  if (it == rules_.end()) return Status::kNotFound;
  rules_.erase(it);
  Rebuild();
  return Status::kOk;
}

// Re-derives the TCAM image from the rule list. Rules are few and change
// rarely, so a full rebuild keeps priority order trivially correct.
void AclTable::Rebuild() {
  entries_.clear();
  for (size_t ri = 0; ri < rules_.size(); ++ri) {
    Rule& r = rules_[ri];
    const AclRule& a = r.rule;
    const uint64_t src_mask = PrefixMask(a.src.len);
    const uint64_t dst_mask = PrefixMask(a.dst.len);
    const uint64_t proto_mask = a.ip_proto >= 0 ? 0xff : 0;
    const uint64_t dscp_mask = a.dscp >= 0 ? 0xff : 0;
    const uint64_t port_mask = a.in_port >= 0 ? 0xffff : 0;
    const auto sports = ExpandRange(a.src_ports);
    const auto dports = ExpandRange(a.dst_ports);
    r.entry_count = sports.size() * dports.size();
    for (const auto& [sv, sm] : sports) {
      for (const auto& [dv, dm] : dports) {
        Entry e;
        e.value[0] = (uint64_t{a.src.addr} << 32) | a.dst.addr;
        e.mask[0] = (src_mask << 32) | dst_mask;
        e.value[1] = (uint64_t{sv} << 48) | (uint64_t{dv} << 32) |
                     (uint64_t{static_cast<uint8_t>(a.ip_proto >= 0 ? a.ip_proto : 0)} << 24) |
                     (uint64_t{static_cast<uint8_t>(a.dscp >= 0 ? a.dscp : 0)} << 16) |
                     static_cast<uint16_t>(a.in_port >= 0 ? a.in_port : 0);
        e.mask[1] = (uint64_t{sm} << 48) | (uint64_t{dm} << 32) | (proto_mask << 24) |
                    (dscp_mask << 16) | port_mask;
        e.value[0] &= e.mask[0];
        e.value[1] &= e.mask[1];
        e.rule_index = ri;
        entries_.push_back(e);
      }
    }
  }
}

const AclResult* AclTable::Lookup(const AclLookupKey& key) {
  uint64_t k[2];
  PackKey(key, k);
  for (const Entry& e : entries_) {
    if (((k[0] & e.mask[0]) == e.value[0]) && ((k[1] & e.mask[1]) == e.value[1])) {
      Rule& r = rules_[e.rule_index];
      ++r.hits;
      return &r.result;
    }
  }
  return nullptr;
}

uint64_t AclTable::hits(uint32_t seq) const {
  for (const Rule& r : rules_) {
    if (r.rule.seq == seq) return r.hits;
  }
  return 0;
}

}  // namespace nanonos
