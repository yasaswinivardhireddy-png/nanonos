#include "common/types.h"

#include <charconv>
#include <cstdio>

namespace nanonos {
namespace {

int HexDigit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

MacAddress MacAddress::FromU64(uint64_t value) {
  MacAddress mac;
  for (int i = 5; i >= 0; --i) {
    mac.bytes[static_cast<size_t>(i)] = static_cast<uint8_t>(value & 0xff);
    value >>= 8;
  }
  return mac;
}

std::optional<MacAddress> MacAddress::Parse(std::string_view text) {
  if (text.size() != 17) return std::nullopt;
  MacAddress mac;
  for (size_t i = 0; i < 6; ++i) {
    const size_t pos = i * 3;
    const int hi = HexDigit(text[pos]);
    const int lo = HexDigit(text[pos + 1]);
    if (hi < 0 || lo < 0) return std::nullopt;
    if (i < 5 && text[pos + 2] != ':' && text[pos + 2] != '-') return std::nullopt;
    mac.bytes[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return mac;
}

std::string MacAddress::ToString() const {
  char buf[18];
  std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2],
                bytes[3], bytes[4], bytes[5]);
  return buf;
}

std::optional<int64_t> ParseInt(std::string_view text, int64_t min, int64_t max) {
  if (text.empty()) return std::nullopt;
  int64_t value = 0;
  const char* end = text.data() + text.size();
  const auto [ptr, ec] = std::from_chars(text.data(), end, value);
  if (ec != std::errc() || ptr != end || value < min || value > max) return std::nullopt;
  return value;
}

std::optional<uint32_t> ParseIpv4(std::string_view text) {
  uint32_t addr = 0;
  for (int octet = 0; octet < 4; ++octet) {
    const size_t dot = text.find('.');
    const std::string_view part = octet < 3 ? text.substr(0, dot) : text;
    if ((octet < 3 && dot == std::string_view::npos) || part.empty() || part.size() > 3) {
      return std::nullopt;
    }
    for (char c : part) {
      if (c < '0' || c > '9') return std::nullopt;
    }
    const auto value = ParseInt(part, 0, 255);
    if (!value) return std::nullopt;
    addr = (addr << 8) | static_cast<uint32_t>(*value);
    if (octet < 3) text.remove_prefix(dot + 1);
  }
  return addr;
}

std::string Ipv4ToString(uint32_t addr) {
  char buf[16];
  std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (addr >> 24) & 0xff, (addr >> 16) & 0xff,
                (addr >> 8) & 0xff, addr & 0xff);
  return buf;
}

namespace {

// Splits "a.b.c.d/len"; a missing length means /32.
bool SplitAddressAndLength(std::string_view text, uint32_t* ip, uint8_t* len) {
  const size_t slash = text.find('/');
  const auto addr = ParseIpv4(text.substr(0, slash));
  if (!addr) return false;
  int64_t length = 32;
  if (slash != std::string_view::npos) {
    const auto parsed = ParseInt(text.substr(slash + 1), 0, 32);
    if (!parsed) return false;
    length = *parsed;
  }
  *ip = *addr;
  *len = static_cast<uint8_t>(length);
  return true;
}

}  // namespace

std::optional<Ipv4Prefix> Ipv4Prefix::Parse(std::string_view text) {
  uint32_t ip = 0;
  uint8_t len = 0;
  if (!SplitAddressAndLength(text, &ip, &len)) return std::nullopt;
  return Make(ip, len);
}

std::string Ipv4Prefix::ToString() const { return Ipv4ToString(addr) + "/" + std::to_string(len); }

std::optional<InterfaceAddress> InterfaceAddress::Parse(std::string_view text) {
  InterfaceAddress a;
  if (text.find('/') == std::string_view::npos) return std::nullopt;
  if (!SplitAddressAndLength(text, &a.ip, &a.len)) return std::nullopt;
  return a;
}

std::string InterfaceAddress::ToString() const {
  return Ipv4ToString(ip) + "/" + std::to_string(len);
}

}  // namespace nanonos
