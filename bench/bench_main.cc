// Benchmarks for the data-plane structures and the full forwarding pipeline.
// Prints a Markdown table (CI appends it to the job summary).
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "asic/acl.h"
#include "asic/bucket_hash.h"
#include "asic/ecmp.h"
#include "asic/lpm.h"
#include "common/clock.h"
#include "common/hash.h"
#include "packet/builder.h"
#include "sw/switch_node.h"

namespace nanonos {
namespace {

volatile uint64_t g_sink = 0;

double Seconds(std::chrono::steady_clock::time_point start) {
  return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
}

void Row(const std::string& name, const std::string& value) {
  std::printf("| %s | %s |\n", name.c_str(), value.c_str());
}

std::string Fmt(const char* fmt, double v) {
  char buf[64];
  std::snprintf(buf, sizeof(buf), fmt, v);
  return buf;
}

// Prefix lengths roughly follow the Internet routing table: mostly /24s, then
// /22-/23, then shorter aggregates and a few longer prefixes.
int RandomLength(Xorshift& rng) {
  const uint64_t r = rng.Below(100);
  if (r < 55) return 24;
  if (r < 70) return 22 + static_cast<int>(rng.Below(2));
  if (r < 92) return 16 + static_cast<int>(rng.Below(6));
  if (r < 97) return 8 + static_cast<int>(rng.Below(8));
  return 25 + static_cast<int>(rng.Below(8));
}

void BenchLpm(size_t routes) {
  Xorshift rng(routes);
  LpmTable lpm(routes, 160000);
  size_t inserted = 0;
  const auto t0 = std::chrono::steady_clock::now();
  while (inserted < routes) {
    if (lpm.Insert(Ipv4Prefix::Make(static_cast<uint32_t>(rng.Next()), RandomLength(rng)),
                   static_cast<uint32_t>(rng.Below(4096))) == Status::kTableFull) {
      break;
    }
    inserted = lpm.size();
  }
  const double insert_s = Seconds(t0);
  std::vector<uint32_t> addrs(1 << 20);
  for (uint32_t& a : addrs) a = static_cast<uint32_t>(rng.Next());
  const int rounds = 20;
  uint64_t hits = 0;
  const auto t1 = std::chrono::steady_clock::now();
  for (int r = 0; r < rounds; ++r) {
    for (uint32_t a : addrs) hits += lpm.Lookup(a).value_or(0);
  }
  const double lookup_s = Seconds(t1);
  g_sink += hits;
  const double mlps = static_cast<double>(addrs.size()) * rounds / lookup_s / 1e6;
  const std::string label = std::to_string(lpm.size() / 1000) + "K routes";
  Row("LPM lookups, " + label, Fmt("%.0f M lookups/s", mlps));
  Row("LPM insert rate, " + label,
      Fmt("%.2f M routes/s", static_cast<double>(lpm.size()) / insert_s / 1e6));
  Row("LPM trie memory, " + label,
      Fmt("%.1f MB", static_cast<double>(lpm.nodes_in_use()) * 1024.0 / 1048576.0));
}

struct U64Hash {
  uint64_t operator()(uint64_t k) const { return Mix64(k); }
};

void BenchHashTable() {
  for (int choices : {1, 2}) {
    BucketHashTable<uint64_t, uint32_t, U64Hash> table(8192, 4, choices);
    Xorshift rng(7);
    while (table.Insert(rng.Next(), 0) == Status::kOk) {
    }
    Row(choices == 1 ? "FDB fill at first hash collision, 1 hash"
                     : "FDB fill at first hash collision, 2-choice cuckoo",
        Fmt("%.1f%%",
            100.0 * static_cast<double>(table.size()) / static_cast<double>(table.capacity())));
  }
}

void BenchEcmpChurn() {
  for (auto mode : {EcmpGroup::Mode::kModulo, EcmpGroup::Mode::kResilient}) {
    EcmpGroup g(mode);
    g.SetActiveMembers(std::vector<uint32_t>{1, 2, 3, 4, 5, 6, 7, 8});
    Xorshift rng(3);
    std::vector<uint32_t> hashes(100000);
    for (uint32_t& h : hashes) h = static_cast<uint32_t>(rng.Next());
    std::vector<uint32_t> before;
    for (uint32_t h : hashes) before.push_back(g.Select(h));
    g.SetActiveMembers(std::vector<uint32_t>{1, 2, 3, 4, 5, 6, 7});
    size_t moved = 0;
    for (size_t i = 0; i < hashes.size(); ++i) moved += g.Select(hashes[i]) != before[i];
    Row(mode == EcmpGroup::Mode::kModulo ? "Flows remapped when 1 of 8 ECMP paths fails, modulo"
                                         : "Flows remapped when 1 of 8 ECMP paths fails, resilient",
        Fmt("%.1f%%", 100.0 * static_cast<double>(moved) / static_cast<double>(hashes.size())));
  }
}

void BenchAcl() {
  AclTable acl(4096);
  Xorshift rng(11);
  for (uint32_t i = 0; i < 128; ++i) {
    AclRule r;
    r.seq = i + 1;
    r.action = AclAction::kDeny;
    r.ip_proto = kIpProtoTcp;
    r.src = Ipv4Prefix::Make(static_cast<uint32_t>(rng.Next()), 24);
    r.dst_ports = {static_cast<uint16_t>(1000 + i), static_cast<uint16_t>(1000 + i)};
    acl.AddRule(r);
  }
  std::vector<AclLookupKey> keys(1 << 16);
  for (AclLookupKey& k : keys) {
    k.src_ip = static_cast<uint32_t>(rng.Next());
    k.dst_ip = static_cast<uint32_t>(rng.Next());
    k.ip_proto = kIpProtoTcp;
    k.dst_port = static_cast<uint16_t>(rng.Below(65536));
  }
  const auto t0 = std::chrono::steady_clock::now();
  uint64_t matched = 0;
  for (int r = 0; r < 20; ++r) {
    for (const AclLookupKey& k : keys) matched += acl.Lookup(k) != nullptr;
  }
  g_sink += matched;
  Row("ACL lookups, 128 rules (software TCAM, worst case: no match)",
      Fmt("%.1f M lookups/s", static_cast<double>(keys.size()) * 20 / Seconds(t0) / 1e6));
}

void BenchPipeline() {
  ManualClock clock;
  uint64_t transmitted = 0;
  SwitchNode::Platform p;
  p.clock = &clock;
  p.asic.num_ports = 8;
  p.transmit = [&](uint16_t, std::span<const uint8_t>) { ++transmitted; };
  SwitchNode node(std::move(p));
  const auto config = ParseConfig(R"(
switch-mac 02:00:00:00:00:aa
no lldp
interface Ethernet0
  switchport access vlan 10
interface Ethernet1
  switchport access vlan 10
interface Ethernet4
  ip address 10.0.0.1/31
interface Ethernet5
  ip address 10.0.1.1/31
interface Vlan10
  ip address 10.1.1.1/24
ip route 10.9.0.0/16 10.0.0.0 10.0.1.0
access-list
  rule 10 deny tcp dport 23
  rule 20 set-tc 3 udp dport 4791
)",
                                  nullptr);
  node.Configure(*config, nullptr);
  const MacAddress router = MacAddress::FromU64(0x0200000000aa);
  const MacAddress h1 = MacAddress::FromU64(0x020000000001);
  const MacAddress h2 = MacAddress::FromU64(0x020000000002);
  uint8_t buf[128];
  const auto arp = [&](uint16_t port, uint64_t mac, uint32_t ip) {
    const size_t n = BuildArpFrame(buf, router, kArpOpReply, MacAddress::FromU64(mac), ip, router,
                                   port == 4 ? 0x0a000001 : 0x0a000101);
    node.ReceiveFrame(port, std::span<const uint8_t>(buf, n));
  };
  arp(4, 0x0200000000f4, 0x0a000000);
  arp(5, 0x0200000000f5, 0x0a000100);

  for (bool routed : {true, false}) {
    std::vector<std::vector<uint8_t>> frames;
    for (uint16_t i = 0; i < 256; ++i) {
      FlowFrameSpec s;
      s.dst_mac = routed ? router : h2;
      s.src_mac = h1;
      s.src_ip = 0x0a01010a;
      s.dst_ip = routed ? 0x0a090101 : 0x0a010114;
      s.src_port = static_cast<uint16_t>(1000 + i);
      s.dst_port = 2000;
      s.payload_len = 18;  // 64-byte frames
      std::vector<uint8_t> f(128);
      f.resize(BuildFlowFrame(f, s));
      frames.push_back(std::move(f));
    }
    if (!routed) {
      FlowFrameSpec back;
      back.dst_mac = h1;
      back.src_mac = h2;
      back.src_ip = 0x0a010114;
      back.dst_ip = 0x0a01010a;
      std::vector<uint8_t> f(128);
      f.resize(BuildFlowFrame(f, back));
      node.ReceiveFrame(1, f);  // learn h2 on port 1
    }
    node.Drain();
    transmitted = 0;
    const int packets = 4'000'000;
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < packets; ++i) {
      node.ReceiveFrame(0, frames[static_cast<size_t>(i) & 255]);
      if ((i & 31) == 31) node.Drain();
    }
    node.Drain();
    const double s = Seconds(t0);
    Row(routed ? "Pipeline, routed + ECMP + ACL, 64-byte frames, 1 core"
               : "Pipeline, bridged + ACL, 64-byte frames, 1 core",
        Fmt("%.2f Mpps", static_cast<double>(transmitted) / s / 1e6));
  }
}

}  // namespace
}  // namespace nanonos

int main() {
  std::printf("| Benchmark | Result |\n|---|---|\n");
  nanonos::BenchPipeline();
  nanonos::BenchLpm(100000);
  nanonos::BenchLpm(500000);
  nanonos::BenchAcl();
  nanonos::BenchHashTable();
  nanonos::BenchEcmpChurn();
  return nanonos::g_sink == 42 ? 1 : 0;
}
