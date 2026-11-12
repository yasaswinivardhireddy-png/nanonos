// Status codes in the style of SAI (switch abstraction interface) return values.
#pragma once

#include <cstdint>

namespace nanonos {

enum class Status : uint8_t {
  kOk,
  kNotFound,
  kAlreadyExists,
  kTableFull,  // hardware table (or one hash bucket of it) has no free entry
  kInvalidArgument,
  kInUse,  // object is still referenced by another object
  kNotSupported,
  kUnavailable,
};

const char* StatusName(Status status);

}  // namespace nanonos
