// Minimal streaming JSON writer for machine-readable "show ... json" output.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace nanonos {

class JsonWriter {
 public:
  JsonWriter& BeginObject() { return Open('{'); }
  JsonWriter& EndObject() { return Close('}'); }
  JsonWriter& BeginArray() { return Open('['); }
  JsonWriter& EndArray() { return Close(']'); }

  JsonWriter& Key(std::string_view key) {
    Separator();
    Quote(key);
    out_ += ':';
    after_key_ = true;
    return *this;
  }
  JsonWriter& String(std::string_view value) {
    Separator();
    Quote(value);
    return *this;
  }
  JsonWriter& Number(uint64_t value) {
    Separator();
    out_ += std::to_string(value);
    return *this;
  }
  JsonWriter& Signed(int64_t value) {
    Separator();
    out_ += std::to_string(value);
    return *this;
  }
  JsonWriter& Bool(bool value) {
    Separator();
    out_ += value ? "true" : "false";
    return *this;
  }
  template <typename T>
  JsonWriter& Field(std::string_view key, const T& value) {
    Key(key);
    if constexpr (std::is_same_v<T, bool>) {
      return Bool(value);
    } else if constexpr (std::is_convertible_v<T, std::string_view>) {
      return String(value);
    } else if constexpr (std::is_signed_v<T>) {
      return Signed(static_cast<int64_t>(value));
    } else {
      return Number(static_cast<uint64_t>(value));
    }
  }
  const std::string& str() const { return out_; }

 private:
  JsonWriter& Open(char c) {
    Separator();
    out_ += c;
    first_.push_back(true);
    return *this;
  }
  JsonWriter& Close(char c) {
    out_ += c;
    first_.pop_back();
    return *this;
  }
  void Separator() {
    if (after_key_) {
      after_key_ = false;
      return;
    }
    if (!first_.empty()) {
      if (!first_.back()) out_ += ',';
      first_.back() = false;
    }
  }
  void Quote(std::string_view s) {
    out_ += '"';
    for (char c : s) {
      switch (c) {
        case '"':
          out_ += "\\\"";
          break;
        case '\\':
          out_ += "\\\\";
          break;
        case '\n':
          out_ += "\\n";
          break;
        default:
          if (static_cast<unsigned char>(c) < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
            out_ += buf;
          } else {
            out_ += c;
          }
      }
    }
    out_ += '"';
  }

  std::string out_;
  std::vector<bool> first_;
  bool after_key_ = false;
};

}  // namespace nanonos
