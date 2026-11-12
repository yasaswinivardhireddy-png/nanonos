#include "common/hash.h"

#include <array>

namespace nanonos {
namespace {

constexpr std::array<uint32_t, 256> MakeCrcTable() {
  std::array<uint32_t, 256> table{};
  for (uint32_t i = 0; i < 256; ++i) {
    uint32_t c = i;
    for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xedb88320u ^ (c >> 1) : c >> 1;
    table[i] = c;
  }
  return table;
}

constexpr std::array<uint32_t, 256> kCrcTable = MakeCrcTable();

}  // namespace

uint32_t Crc32(const uint8_t* data, size_t len, uint32_t seed) {
  uint32_t crc = ~seed;
  for (size_t i = 0; i < len; ++i) crc = kCrcTable[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
  return ~crc;
}

}  // namespace nanonos
