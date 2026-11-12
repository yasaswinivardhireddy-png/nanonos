#pragma once

#include <chrono>
#include <cstdint>

namespace nanonos {

// Monotonic time in microseconds.
using TimeUs = int64_t;
inline constexpr TimeUs kUsPerMs = 1000;
inline constexpr TimeUs kUsPerSec = 1000 * 1000;

class Clock {
 public:
  virtual ~Clock() = default;
  virtual TimeUs Now() const = 0;
};

// Time only moves when a test advances it, which makes timers deterministic.
class ManualClock final : public Clock {
 public:
  explicit ManualClock(TimeUs start = kUsPerSec) : now_(start) {}
  TimeUs Now() const override { return now_; }
  void Advance(TimeUs delta) { now_ += delta; }

 private:
  TimeUs now_;
};

class SteadyClock final : public Clock {
 public:
  TimeUs Now() const override {
    return std::chrono::duration_cast<std::chrono::microseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
  }
};

}  // namespace nanonos
