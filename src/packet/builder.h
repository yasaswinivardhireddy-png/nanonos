// Frame builders for control-plane packets (ARP, LLDP) and for tests.
// All builders write into caller-provided buffers and never allocate.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "common/types.h"
#include "packet/packet.h"

namespace nanonos {

struct EthernetSpec {
  MacAddress dst;
  MacAddress src;
  uint16_t ethertype = 0;
  int vlan = -1;  // -1 = untagged
  uint8_t pcp = 0;
};

struct Ipv4Spec {
  uint32_t src = 0;
  uint32_t dst = 0;
  uint8_t proto = kIpProtoUdp;
  uint8_t ttl = 64;
  uint8_t dscp = 0;
  uint8_t ecn = 0;
  uint16_t payload_len = 0;  // bytes after the IPv4 header
  uint16_t id = 0;
};

size_t WriteEthernet(uint8_t* out, const EthernetSpec& spec);  // 14 or 18 bytes
size_t WriteArp(uint8_t* out, uint16_t op, const MacAddress& sha, uint32_t spa,
                const MacAddress& tha, uint32_t tpa);  // 28 bytes
size_t WriteIpv4(uint8_t* out, const Ipv4Spec& spec);  // 20 bytes, checksum filled in

// Pads to the 60-byte Ethernet minimum. Returns the frame length, or 0 if `out`
// is too small.
size_t BuildArpFrame(std::span<uint8_t> out, const MacAddress& eth_dst, uint16_t op,
                     const MacAddress& sha, uint32_t spa, const MacAddress& tha, uint32_t tpa,
                     int vlan = -1);

struct FlowFrameSpec {
  MacAddress dst_mac;
  MacAddress src_mac;
  int vlan = -1;
  uint8_t pcp = 0;
  uint32_t src_ip = 0;
  uint32_t dst_ip = 0;
  uint8_t proto = kIpProtoUdp;  // UDP, TCP or ICMP
  uint16_t src_port = 0;        // ICMP: echo identifier
  uint16_t dst_port = 0;        // ICMP: echo sequence number
  uint8_t tcp_flags = 0x10;     // ACK
  uint8_t icmp_type = 8;        // echo request
  uint8_t ttl = 64;
  uint8_t dscp = 0;
  uint8_t ecn = 0;
  uint16_t payload_len = 18;
};

// UDP, TCP or ICMP echo frame. Returns the frame length or 0 if it does not fit.
size_t BuildFlowFrame(std::span<uint8_t> out, const FlowFrameSpec& spec);

}  // namespace nanonos
