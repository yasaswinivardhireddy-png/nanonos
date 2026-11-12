#include "packet/builder.h"

#include <cstring>

#include "common/byte_order.h"

namespace nanonos {

size_t WriteEthernet(uint8_t* out, const EthernetSpec& spec) {
  std::memcpy(out, spec.dst.bytes.data(), 6);
  std::memcpy(out + 6, spec.src.bytes.data(), 6);
  if (spec.vlan >= 0) {
    StoreBe16(out + 12, kEtherTypeVlan);
    StoreBe16(out + 14, static_cast<uint16_t>((spec.pcp << 13) | (spec.vlan & 0x0fff)));
    StoreBe16(out + 16, spec.ethertype);
    return kEthHeaderLen + kVlanTagLen;
  }
  StoreBe16(out + 12, spec.ethertype);
  return kEthHeaderLen;
}

size_t WriteArp(uint8_t* out, uint16_t op, const MacAddress& sha, uint32_t spa,
                const MacAddress& tha, uint32_t tpa) {
  StoreBe16(out, 1);  // Ethernet
  StoreBe16(out + 2, kEtherTypeIpv4);
  out[4] = 6;
  out[5] = 4;
  StoreBe16(out + 6, op);
  std::memcpy(out + 8, sha.bytes.data(), 6);
  StoreBe32(out + 14, spa);
  std::memcpy(out + 18, tha.bytes.data(), 6);
  StoreBe32(out + 24, tpa);
  return kArpLen;
}

size_t WriteIpv4(uint8_t* out, const Ipv4Spec& spec) {
  out[0] = 0x45;
  out[1] = static_cast<uint8_t>((spec.dscp << 2) | (spec.ecn & 0x03));
  StoreBe16(out + 2, static_cast<uint16_t>(kIpv4HeaderLen + spec.payload_len));
  StoreBe16(out + 4, spec.id);
  StoreBe16(out + 6, 0x4000);  // don't fragment
  out[8] = spec.ttl;
  out[9] = spec.proto;
  StoreBe16(out + 10, 0);
  StoreBe32(out + 12, spec.src);
  StoreBe32(out + 16, spec.dst);
  StoreBe16(out + 10, InternetChecksum(out, kIpv4HeaderLen));
  return kIpv4HeaderLen;
}

namespace {

size_t PadToMinimum(std::span<uint8_t> out, size_t len) {
  if (len < kMinFrameSize) {
    std::memset(out.data() + len, 0, kMinFrameSize - len);
    len = kMinFrameSize;
  }
  return len;
}

}  // namespace

size_t BuildArpFrame(std::span<uint8_t> out, const MacAddress& eth_dst, uint16_t op,
                     const MacAddress& sha, uint32_t spa, const MacAddress& tha, uint32_t tpa,
                     int vlan) {
  if (out.size() < kMinFrameSize + kVlanTagLen) return 0;
  size_t len = WriteEthernet(out.data(), {eth_dst, sha, kEtherTypeArp, vlan, 0});
  len += WriteArp(out.data() + len, op, sha, spa, tha, tpa);
  return PadToMinimum(out, len);
}

size_t BuildFlowFrame(std::span<uint8_t> out, const FlowFrameSpec& spec) {
  size_t l4_header = 8;
  if (spec.proto == kIpProtoTcp) l4_header = 20;
  const size_t eth_len = spec.vlan >= 0 ? kEthHeaderLen + kVlanTagLen : kEthHeaderLen;
  const size_t total = eth_len + kIpv4HeaderLen + l4_header + spec.payload_len;
  if (total > out.size() || out.size() < kMinFrameSize + kVlanTagLen) return 0;

  uint8_t* p = out.data();
  size_t off = WriteEthernet(p, {spec.dst_mac, spec.src_mac, kEtherTypeIpv4, spec.vlan, spec.pcp});
  Ipv4Spec ip;
  ip.src = spec.src_ip;
  ip.dst = spec.dst_ip;
  ip.proto = spec.proto;
  ip.ttl = spec.ttl;
  ip.dscp = spec.dscp;
  ip.ecn = spec.ecn;
  ip.payload_len = static_cast<uint16_t>(l4_header + spec.payload_len);
  off += WriteIpv4(p + off, ip);
  uint8_t* l4 = p + off;
  std::memset(l4, 0, l4_header + spec.payload_len);
  if (spec.proto == kIpProtoTcp) {
    StoreBe16(l4, spec.src_port);
    StoreBe16(l4 + 2, spec.dst_port);
    l4[12] = 0x50;  // data offset: 5 words
    l4[13] = spec.tcp_flags;
    StoreBe16(l4 + 14, 65535);
  } else if (spec.proto == kIpProtoIcmp) {
    l4[0] = spec.icmp_type;
    l4[1] = 0;
    StoreBe16(l4 + 4, spec.src_port);
    StoreBe16(l4 + 6, spec.dst_port);
    StoreBe16(l4 + 2, InternetChecksum(l4, l4_header + spec.payload_len));
  } else {
    StoreBe16(l4, spec.src_port);
    StoreBe16(l4 + 2, spec.dst_port);
    StoreBe16(l4 + 4, static_cast<uint16_t>(l4_header + spec.payload_len));
  }
  return PadToMinimum(out, off + l4_header + spec.payload_len);
}

}  // namespace nanonos
