// Single-rate three-color marker (RFC 2697), used for control-plane policing
// (CoPP) and storm control. Rates are in units per second, where a unit is a
// byte or a packet depending on the caller. Integer arithmetic only.
#pragma once

#include <algorithm>
#include <cstdint>

#include "common/clock.h"

namespace nanonos {

enum class Color : uint8_t { kGreen, kYellow, kRed };

class SrTcmPolicer {
 public:
  SrTcmPolicer() = default;  // disabled: everything is green

  SrTcmPolicer(uint64_t cir, uint64_t cbs, uint64_t ebs, TimeUs now)
      : enabled_(cir > 0),
        cir_(cir),
        cbs_(cbs * kScale),
        ebs_(ebs * kScale),
        tc_(cbs * kScale),
        te_(ebs * kScale),
        last_(now) {}

  bool enabled() const { return enabled_; }
  uint64_t cir() const { return cir_; }

  Color Meter(uint64_t units, TimeUs now) {
    if (!enabled_) return Color::kGreen;
    Refill(now);
    const uint64_t cost = units * kScale;
    if (tc_ >= cost) {
      tc_ -= cost;
      return Color::kGreen;
    }
    if (te_ >= cost) {
      te_ -= cost;
      return Color::kYellow;
    }
    return Color::kRed;
  }

 private:
  // Tokens are kept in micro-units so that cir * elapsed_us adds exact amounts.
  static constexpr uint64_t kScale = 1000 * 1000;

  void Refill(TimeUs now) {
    if (now <= last_) return;
    const uint64_t elapsed = static_cast<uint64_t>(std::min<TimeUs>(now - last_, 10 * kUsPerSec));
    last_ = now;
    uint64_t add = cir_ * elapsed;
    const uint64_t room_c = cbs_ - tc_;
    const uint64_t to_c = std::min(add, room_c);
    tc_ += to_c;
    add -= to_c;
    te_ = std::min(ebs_, te_ + add);  // tokens overflow from the committed into the excess bucket
  }

  bool enabled_ = false;
  uint64_t cir_ = 0;
  uint64_t cbs_ = 0;
  uint64_t ebs_ = 0;
  uint64_t tc_ = 0;
  uint64_t te_ = 0;
  TimeUs last_ = 0;
};

// Port shaper: a token bucket in bytes that may go negative by one packet, so
// the scheduler never has to peek at the next packet's size.
class Shaper {
 public:
  void Configure(uint64_t bits_per_second, TimeUs now) {
    rate_ = bits_per_second / 8;
    burst_ = std::max<int64_t>(4096, static_cast<int64_t>(rate_ / 500));  // ~2 ms of line rate
    tokens_ = burst_ * static_cast<int64_t>(kScale);
    last_ = now;
  }
  bool enabled() const { return rate_ > 0; }
  uint64_t rate_bytes_per_sec() const { return rate_; }

  bool CanSend(TimeUs now) {
    if (rate_ == 0) return true;
    if (now > last_) {
      const int64_t elapsed = std::min<int64_t>(now - last_, kUsPerSec);
      tokens_ = std::min(burst_ * static_cast<int64_t>(kScale),
                         tokens_ + static_cast<int64_t>(rate_) * elapsed);
      last_ = now;
    }
    return tokens_ > 0;
  }
  void Charge(uint32_t bytes) {
    if (rate_ != 0) tokens_ -= static_cast<int64_t>(bytes) * static_cast<int64_t>(kScale);
  }

 private:
  static constexpr uint64_t kScale = 1000 * 1000;
  uint64_t rate_ = 0;  // bytes per second; 0 = unshaped
  int64_t burst_ = 0;
  int64_t tokens_ = 0;
  TimeUs last_ = 0;
};

}  // namespace nanonos
