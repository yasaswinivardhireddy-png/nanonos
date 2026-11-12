// Fuzzes the whole switch: arbitrary frames on arbitrary ports of a switch
// configured with VLANs, a trunk, SVIs, routed ports, ECMP, ACLs, QoS, storm
// control and CoPP. The first input byte picks the ingress port and whether to
// run the control-plane tick (ARP glean, LLDP, aging).
#include <cstddef>
#include <cstdint>
#include <memory>

#include "common/clock.h"
#include "sw/switch_node.h"

namespace {

nanonos::ManualClock g_clock;

nanonos::SwitchNode* Switch() {
  static std::unique_ptr<nanonos::SwitchNode> node = [] {
    nanonos::SwitchNode::Platform p;
    p.clock = &g_clock;
    p.asic.num_ports = 8;
    p.asic.packet_buffers = 512;
    p.transmit = [](uint16_t, std::span<const uint8_t>) {};
    auto n = std::make_unique<nanonos::SwitchNode>(std::move(p));
    const auto config = nanonos::ParseConfig(R"(
switch-mac 02:00:00:00:00:aa
interface Ethernet0
  switchport access vlan 10
  storm-control broadcast pps 100
  port-security max-mac 64
interface Ethernet1
  switchport mode trunk
  switchport trunk allowed vlan 10,20
  switchport trunk native vlan 20
interface Ethernet2
  switchport access vlan 20
interface Ethernet4
  ip address 10.0.0.1/31
  qos shaper 100m
  qos wred queue 0 min 2000 max 8000 probability 50 ecn
interface Ethernet5
  ip address 10.0.1.1/31
interface Vlan10
  ip address 10.1.1.1/24
interface Vlan20
  ip address 10.2.1.1/24
ip route 0.0.0.0/0 10.0.0.0 10.0.1.0
ip route 10.8.0.0/16 blackhole
access-list
  rule 10 deny tcp dport 23
  rule 20 set-tc 3 udp dport 4791
  rule 30 deny src 10.66.0.0/16
)",
                                             nullptr);
    n->Configure(*config, nullptr);
    return n;
  }();
  return node.get();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return 0;
  nanonos::SwitchNode* node = Switch();
  const uint16_t port = data[0] % 8;
  node->ReceiveFrame(port, std::span<const uint8_t>(data + 1, size - 1));
  if (data[0] & 0x80) {
    g_clock.Advance(3 * nanonos::kUsPerMs);
    node->Tick();
  }
  node->Drain();
  return 0;
}
