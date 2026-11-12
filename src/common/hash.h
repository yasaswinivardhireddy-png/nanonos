#pragma once

#include <cstddef>
#include <cstdint>

namespace nanonos {

// CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320). Switch ASICs use CRC
// variants for ECMP/LAG member selection; a per-switch seed avoids hash
// polarization between tiers of a Clos fabric.
uint32_t Crc32(const uint8_t* data, size_t len, uint32_t seed = 0);

// 64-bit finalizer from SplitMix64; used for exact-match table bucket indexes.
constexpr uint64_t Mix64(uint64_t x) {
  x ^= x >> 30;
  x *= 0xbf58476d1ce4e5b9ULL;
  x ^= x >> 27;
  x *= 0x94d049bb133111ebULL;
  x ^= x >> 31;
  return x;
}

// Small deterministic PRNG (xorshift64*) for WRED decisions and tests.
class Xorshift {
 public:
  explicit Xorshift(uint64_t seed = 0x9e3779b97f4a7c15ULL) : state_(seed ? seed : 1) {}
  uint64_t Next() {
    state_ ^= state_ >> 12;
    state_ ^= state_ << 25;
    state_ ^= state_ >> 27;
    return state_ * 0x2545f4914f6cdd1dULL;
  }
  // Uniform in [0, bound); bound must be > 0.
  uint64_t Below(uint64_t bound) { return Next() % bound; }

 private:
  uint64_t state_;
};

}  // namespace nanonos
