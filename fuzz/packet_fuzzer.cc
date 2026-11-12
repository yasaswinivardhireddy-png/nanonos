// Fuzzes the frame parser with arbitrary bytes.
#include <cstddef>
#include <cstdint>

#include "packet/packet.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  nanonos::ParsedPacket p;
  if (nanonos::ParseFrame(std::span<const uint8_t>(data, size), &p) == nanonos::ParseStatus::kOk &&
      p.is_ipv4()) {
    // Offsets reported by the parser must stay inside the frame.
    if (static_cast<size_t>(p.l3_offset) + p.ip_total_len > size) __builtin_trap();
    (void)nanonos::FlowHash(p, 1);
  }
  return 0;
}
