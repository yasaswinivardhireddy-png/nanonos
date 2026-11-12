#include "common/status.h"

namespace nanonos {

const char* StatusName(Status status) {
  switch (status) {
    case Status::kOk:
      return "OK";
    case Status::kNotFound:
      return "NOT_FOUND";
    case Status::kAlreadyExists:
      return "ALREADY_EXISTS";
    case Status::kTableFull:
      return "TABLE_FULL";
    case Status::kInvalidArgument:
      return "INVALID_ARGUMENT";
    case Status::kInUse:
      return "IN_USE";
    case Status::kNotSupported:
      return "NOT_SUPPORTED";
    case Status::kUnavailable:
      return "UNAVAILABLE";
  }
  return "UNKNOWN";
}

}  // namespace nanonos
