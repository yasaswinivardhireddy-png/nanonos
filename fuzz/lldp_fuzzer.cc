// Fuzzes the LLDPDU parser.
#include <cstddef>
#include <cstdint>

#include "proto/lldp.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  nanonos::lldp::Info info;
  nanonos::lldp::ParseFrame(std::span<const uint8_t>(data, size), &info);
  return 0;
}
