#include "packet/packet.h"

#include <cstring>

#include "common/byte_order.h"
#include "common/hash.h"

namespace nanonos {

const char* ParseStatusName(ParseStatus status) {
  switch (status) {
    case ParseStatus::kOk:
      return "ok";
    case ParseStatus::kTruncated:
      return "truncated";
    case ParseStatus::kBadArp:
      return "bad-arp";
    case ParseStatus::kBadIpVersion:
      return "bad-ip-version";
    case ParseStatus::kBadIpHeaderLength:
      return "bad-ip-header-length";
    case ParseStatus::kBadIpTotalLength:
      return "bad-ip-total-length";
    case ParseStatus::kBadIpChecksum:
      return "bad-ip-checksum";
  }
  return "?";
}

ParseStatus ParseFrame(std::span<const uint8_t> frame, ParsedPacket* out) {
  ParsedPacket& p = *out;
  p = ParsedPacket{};
  const uint8_t* d = frame.data();
  const size_t n = frame.size();
  if (n < kEthHeaderLen) return ParseStatus::kTruncated;

  std::memcpy(p.dst_mac.bytes.data(), d, 6);
  std::memcpy(p.src_mac.bytes.data(), d + 6, 6);
  size_t off = 12;
  uint16_t type = LoadBe16(d + off);
  off += 2;
  if (type == kEtherTypeVlan) {
    if (n < off + kVlanTagLen) return ParseStatus::kTruncated;
    const uint16_t tci = LoadBe16(d + off);
    p.vlan_tagged = true;
    p.pcp = static_cast<uint8_t>(tci >> 13);
    p.vlan_id = tci & 0x0fff;
    type = LoadBe16(d + off + 2);
    off += kVlanTagLen;
  }
  p.ethertype = type;
  p.l3_offset = static_cast<uint16_t>(off);
  const uint8_t* l3 = d + off;
  const size_t l3_len = n - off;

  if (type == kEtherTypeArp) {
    if (l3_len < kArpLen) return ParseStatus::kTruncated;
    if (LoadBe16(l3) != 1 || LoadBe16(l3 + 2) != kEtherTypeIpv4 || l3[4] != 6 || l3[5] != 4) {
      return ParseStatus::kBadArp;
    }
    p.arp_op = LoadBe16(l3 + 6);
    std::memcpy(p.arp_sha.bytes.data(), l3 + 8, 6);
    p.arp_spa = LoadBe32(l3 + 14);
    std::memcpy(p.arp_tha.bytes.data(), l3 + 18, 6);
    p.arp_tpa = LoadBe32(l3 + 24);
    return ParseStatus::kOk;
  }
  if (type != kEtherTypeIpv4) return ParseStatus::kOk;

  if (l3_len < kIpv4HeaderLen) return ParseStatus::kTruncated;
  if ((l3[0] >> 4) != 4) return ParseStatus::kBadIpVersion;
  const size_t ihl = static_cast<size_t>(l3[0] & 0x0f) * 4;
  if (ihl < kIpv4HeaderLen) return ParseStatus::kBadIpHeaderLength;
  if (ihl > l3_len) return ParseStatus::kTruncated;
  const uint16_t total = LoadBe16(l3 + 2);
  // Ethernet padding may follow the datagram, so the frame can be longer than total.
  if (total < ihl || total > l3_len) return ParseStatus::kBadIpTotalLength;
  if (InternetChecksum(l3, ihl) != 0) return ParseStatus::kBadIpChecksum;

  p.ip_header_len = static_cast<uint8_t>(ihl);
  p.dscp = static_cast<uint8_t>(l3[1] >> 2);
  p.ecn = static_cast<uint8_t>(l3[1] & 0x03);
  p.ip_total_len = total;
  const uint16_t frag = LoadBe16(l3 + 6);
  const uint16_t frag_offset = frag & 0x1fff;
  p.ip_fragment = frag_offset != 0 || (frag & 0x2000) != 0;
  p.ttl = l3[8];
  p.ip_proto = l3[9];
  p.src_ip = LoadBe32(l3 + 12);
  p.dst_ip = LoadBe32(l3 + 16);

  if (frag_offset == 0) {
    const uint8_t* l4 = l3 + ihl;
    const size_t l4_len = total - ihl;
    switch (p.ip_proto) {
      case kIpProtoTcp:
        if (l4_len >= 14) {
          p.src_port = LoadBe16(l4);
          p.dst_port = LoadBe16(l4 + 2);
          p.tcp_flags = l4[13];
          p.has_l4 = true;
        }
        break;
      case kIpProtoUdp:
        if (l4_len >= 8) {
          p.src_port = LoadBe16(l4);
          p.dst_port = LoadBe16(l4 + 2);
          p.has_l4 = true;
        }
        break;
      case kIpProtoIcmp:
        if (l4_len >= 2) {
          p.icmp_type = l4[0];
          p.icmp_code = l4[1];
          p.has_l4 = true;
        }
        break;
      default:
        break;
    }
  }
  return ParseStatus::kOk;
}

uint16_t InternetChecksum(const uint8_t* data, size_t len) {
  uint32_t sum = 0;
  size_t i = 0;
  for (; i + 1 < len; i += 2) sum += LoadBe16(data + i);
  if (i < len) sum += static_cast<uint32_t>(data[i]) << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

uint16_t ChecksumUpdate16(uint16_t checksum, uint16_t old_word, uint16_t new_word) {
  uint32_t sum = static_cast<uint16_t>(~checksum);
  sum += static_cast<uint16_t>(~old_word);
  sum += new_word;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

void DecrementTtl(uint8_t* ip_header) {
  const uint16_t old_word = LoadBe16(ip_header + 8);
  ip_header[8] = static_cast<uint8_t>(ip_header[8] - 1);
  const uint16_t new_word = LoadBe16(ip_header + 8);
  StoreBe16(ip_header + 10, ChecksumUpdate16(LoadBe16(ip_header + 10), old_word, new_word));
}

void MarkEcnCe(uint8_t* ip_header) {
  const uint16_t old_word = LoadBe16(ip_header);
  ip_header[1] = static_cast<uint8_t>(ip_header[1] | kEcnCe);
  const uint16_t new_word = LoadBe16(ip_header);
  StoreBe16(ip_header + 10, ChecksumUpdate16(LoadBe16(ip_header + 10), old_word, new_word));
}

uint32_t FlowHash(const ParsedPacket& packet, uint32_t seed) {
  uint8_t tuple[13];
  StoreBe32(tuple, packet.src_ip);
  StoreBe32(tuple + 4, packet.dst_ip);
  tuple[8] = packet.ip_proto;
  const bool ports = packet.has_l4 && !packet.ip_fragment &&
                     (packet.ip_proto == kIpProtoTcp || packet.ip_proto == kIpProtoUdp);
  StoreBe16(tuple + 9, ports ? packet.src_port : 0);
  StoreBe16(tuple + 11, ports ? packet.dst_port : 0);
  return Crc32(tuple, sizeof(tuple), seed);
}

}  // namespace nanonos
