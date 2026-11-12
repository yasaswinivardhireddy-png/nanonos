// Proves the forwarding path is allocation-free: global operator new is
// replaced with a counting version, and 100,000 bridged, routed and ECMP
// packets (with ACLs, storm control and QoS enabled) must not allocate once.
#include <atomic>
#include <cstdlib>
#include <new>
#include <vector>

#include <gtest/gtest.h>

#include "test_util.h"

namespace {
std::atomic<bool> g_counting{false};
std::atomic<uint64_t> g_allocations{0};
}  // namespace

void* operator new(std::size_t size) {
  if (g_counting.load(std::memory_order_relaxed)) g_allocations.fetch_add(1);
  void* p = std::malloc(size == 0 ? 1 : size);
  if (p == nullptr) std::abort();
  return p;
}
void* operator new[](std::size_t size) { return operator new(size); }
// The nothrow forms must be replaced too (libstdc++ uses them for temporary
// buffers), or sanitizers see memory from their allocator freed by ours.
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
  if (g_counting.load(std::memory_order_relaxed)) g_allocations.fetch_add(1);
  return std::malloc(size == 0 ? 1 : size);
}
void* operator new[](std::size_t size, const std::nothrow_t& tag) noexcept {
  return operator new(size, tag);
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { std::free(p); }

namespace nanonos {
namespace {

using testing::ArpFrame;
using testing::Flow;
using testing::FlowFrame;
using testing::Ip;
using testing::Mac;

TEST(AllocationTest, ForwardingPathNeverAllocates) {
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
  storm-control broadcast pps 1000
interface Ethernet1
  switchport access vlan 10
interface Ethernet4
  ip address 10.0.0.1/31
  qos wred queue 0 min 100000 max 200000 probability 10 ecn
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
  ASSERT_TRUE(config.has_value());
  ASSERT_TRUE(node.Configure(*config, nullptr));

  const MacAddress router = Mac(0x0200000000aa);
  const MacAddress h1 = Mac(0x020000000001);
  const MacAddress h2 = Mac(0x020000000002);
  // Warm up: resolve both next hops and teach the FDB both hosts.
  node.ReceiveFrame(4, ArpFrame(router, kArpOpReply, Mac(0x0200000000f4), Ip("10.0.0.0"), router,
                                Ip("10.0.0.1")));
  node.ReceiveFrame(5, ArpFrame(router, kArpOpReply, Mac(0x0200000000f5), Ip("10.0.1.0"), router,
                                Ip("10.0.1.1")));
  node.ReceiveFrame(0, FlowFrame(Flow{h2, h1, Ip("10.1.1.10"), Ip("10.1.1.20")}));
  node.ReceiveFrame(1, FlowFrame(Flow{h1, h2, Ip("10.1.1.20"), Ip("10.1.1.10")}));
  node.Drain();

  std::vector<std::vector<uint8_t>> frames;
  for (uint16_t i = 0; i < 64; ++i) {
    Flow routed{router, h1, Ip("10.1.1.10"), Ip("10.9.1.1")};
    routed.src_port = static_cast<uint16_t>(1000 + i);
    routed.dst_port = i % 2 ? kRoceV2Port : 2000;
    frames.push_back(FlowFrame(routed));
    frames.push_back(FlowFrame(Flow{h2, h1, Ip("10.1.1.10"), Ip("10.1.1.20")}));
  }
  transmitted = 0;
  g_allocations = 0;
  g_counting = true;
  for (int i = 0; i < 100000; ++i) {
    node.ReceiveFrame(0, frames[static_cast<size_t>(i) % frames.size()]);
    if (i % 16 == 0) node.Drain();
  }
  node.Drain();
  g_counting = false;
  EXPECT_EQ(g_allocations.load(), 0u);
  EXPECT_EQ(transmitted, 100000u);
}

}  // namespace
}  // namespace nanonos
