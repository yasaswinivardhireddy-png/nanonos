// Basic network types: MAC addresses, IPv4 addresses and prefixes.
#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace nanonos {

struct MacAddress {
  std::array<uint8_t, 6> bytes{};

  static constexpr MacAddress Broadcast() {
    return MacAddress{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
  }
  static MacAddress FromU64(uint64_t value);
  // Accepts "aa:bb:cc:dd:ee:ff" or "aa-bb-cc-dd-ee-ff".
  static std::optional<MacAddress> Parse(std::string_view text);

  uint64_t ToU64() const {
    uint64_t v = 0;
    for (uint8_t b : bytes) v = (v << 8) | b;
    return v;
  }
  bool IsBroadcast() const { return ToU64() == 0xffffffffffffULL; }
  bool IsMulticast() const { return (bytes[0] & 0x01) != 0; }  // includes broadcast
  bool IsZero() const { return ToU64() == 0; }
  std::string ToString() const;

  friend bool operator==(const MacAddress&, const MacAddress&) = default;
  friend auto operator<=>(const MacAddress&, const MacAddress&) = default;
};

// IPv4 addresses are held in host byte order.
std::optional<uint32_t> ParseIpv4(std::string_view text);
std::string Ipv4ToString(uint32_t addr);

constexpr uint32_t PrefixMask(int len) {
  return len <= 0 ? 0u : (len >= 32 ? 0xffffffffu : ~((uint32_t{1} << (32 - len)) - 1));
}

struct Ipv4Prefix {
  uint32_t addr = 0;  // host bits are always zero
  uint8_t len = 0;

  static constexpr Ipv4Prefix Make(uint32_t address, int length) {
    return Ipv4Prefix{address & PrefixMask(length), static_cast<uint8_t>(length)};
  }
  // "10.0.0.0/8"; host bits are cleared. A bare address parses as a /32.
  static std::optional<Ipv4Prefix> Parse(std::string_view text);

  bool Contains(uint32_t ip) const { return (ip & PrefixMask(len)) == addr; }
  std::string ToString() const;

  friend bool operator==(const Ipv4Prefix&, const Ipv4Prefix&) = default;
  friend auto operator<=>(const Ipv4Prefix&, const Ipv4Prefix&) = default;
};

struct Ipv4PrefixHash {
  size_t operator()(const Ipv4Prefix& p) const noexcept {
    return std::hash<uint64_t>{}((uint64_t{p.addr} << 8) | p.len);
  }
};

// An address configured on an interface keeps its host bits: 10.0.0.1/31.
struct InterfaceAddress {
  uint32_t ip = 0;
  uint8_t len = 0;

  static std::optional<InterfaceAddress> Parse(std::string_view text);
  Ipv4Prefix Subnet() const { return Ipv4Prefix::Make(ip, len); }
  std::string ToString() const;

  friend bool operator==(const InterfaceAddress&, const InterfaceAddress&) = default;
};

// Parses a decimal integer that must fit in [min, max].
std::optional<int64_t> ParseInt(std::string_view text, int64_t min, int64_t max);

}  // namespace nanonos
