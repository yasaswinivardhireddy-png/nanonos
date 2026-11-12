// Fuzzes the configuration parser.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "orch/config.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  nanonos::ConfigError error;
  nanonos::ParseConfig(std::string_view(reinterpret_cast<const char*>(data), size), &error);
  return 0;
}
