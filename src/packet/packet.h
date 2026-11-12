// Bounds-checked parsing of Ethernet, 802.1Q, ARP, IPv4, TCP, UDP and ICMP
// headers, plus the in-place header rewrites a router performs.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "common/types.h"

namespace nanonos {

inline constexpr size_t kMaxFrameSize = 2048;  // 1500-byte MTU plus headers; no jumbo frames
inline constexpr size_t kMinFrameSize = 60;    // Ethernet minimum without FCS
inline constexpr size_t kEthHeaderLen = 14;
inline constexpr size_t kVlanTagLen = 4;
inline constexpr size_t kArpLen = 28;
inline constexpr size_t kIpv4HeaderLen = 20;

inline constexpr uint16_t kEtherTypeIpv4 = 0x0800;
inline constexpr uint16_t kEtherTypeArp = 0x0806;
inline constexpr uint16_t kEtherTypeVlan = 0x8100;
inline constexpr uint16_t kEtherTypeIpv6 = 0x86dd;
inline constexpr uint16_t kEtherTypeMacControl = 0x8808;  // PAUSE and PFC
inline constexpr uint16_t kEtherTypeLldp = 0x88cc;

inline constexpr uint8_t kIpProtoIcmp = 1;
inline constexpr uint8_t kIpProtoTcp = 6;
inline constexpr uint8_t kIpProtoUdp = 17;

inline constexpr uint16_t kArpOpRequest = 1;
inline constexpr uint16_t kArpOpReply = 2;
inline constexpr uint16_t kBgpPort = 179;
inline constexpr uint16_t kRoceV2Port = 4791;

inline constexpr uint8_t kEcnNotEct = 0;
inline constexpr uint8_t kEcnCe = 3;

enum class ParseStatus : uint8_t {
  kOk,
  kTruncated,
  kBadArp,
  kBadIpVersion,
  kBadIpHeaderLength,
  kBadIpTotalLength,
  kBadIpChecksum,
};
const char* ParseStatusName(ParseStatus status);

struct ParsedPacket {
  MacAddress dst_mac;
  MacAddress src_mac;
  bool vlan_tagged = false;
  uint16_t vlan_id = 0;
  uint8_t pcp = 0;
  uint16_t ethertype = 0;  // inner EtherType when the frame is tagged
  uint16_t l3_offset = 0;

  // ARP (ethertype == kEtherTypeArp)
  uint16_t arp_op = 0;
  MacAddress arp_sha;
  MacAddress arp_tha;
  uint32_t arp_spa = 0;
  uint32_t arp_tpa = 0;

  // IPv4 (ethertype == kEtherTypeIpv4)
  uint8_t ip_header_len = 0;
  uint8_t dscp = 0;
  uint8_t ecn = 0;
  uint8_t ttl = 0;
  uint8_t ip_proto = 0;
  uint16_t ip_total_len = 0;
  bool ip_fragment = false;
  uint32_t src_ip = 0;
  uint32_t dst_ip = 0;
  bool has_l4 = false;  // the L4 fields below are valid (first fragment, long enough)
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint8_t tcp_flags = 0;
  uint8_t icmp_type = 0;
  uint8_t icmp_code = 0;

  bool is_arp() const { return ethertype == kEtherTypeArp; }
  bool is_ipv4() const { return ethertype == kEtherTypeIpv4; }
};

// Never reads outside `frame`. The IPv4 header checksum is verified; L4
// checksums are not (a switch does not verify them either).
ParseStatus ParseFrame(std::span<const uint8_t> frame, ParsedPacket* out);

uint16_t InternetChecksum(const uint8_t* data, size_t len);
// Incremental checksum update for one changed 16-bit word (RFC 1624, eqn. 3).
uint16_t ChecksumUpdate16(uint16_t checksum, uint16_t old_word, uint16_t new_word);

// In-place rewrites of an IPv4 header; both fix the header checksum incrementally.
void DecrementTtl(uint8_t* ip_header);
void MarkEcnCe(uint8_t* ip_header);

// CRC over the 5-tuple. Fragments and non-TCP/UDP packets hash on addresses and
// protocol only, so every fragment of a datagram takes the same path.
uint32_t FlowHash(const ParsedPacket& packet, uint32_t seed);

inline bool IsLinkLocalMulticast(const MacAddress& mac) {
  // IEEE 802.1 reserved range 01:80:c2:00:00:00 - 01:80:c2:00:00:0f (LLDP, PAUSE, STP).
  return mac.bytes[0] == 0x01 && mac.bytes[1] == 0x80 && mac.bytes[2] == 0xc2 &&
         mac.bytes[3] == 0x00 && mac.bytes[4] == 0x00 && mac.bytes[5] <= 0x0f;
}

}  // namespace nanonos
