#include "common/logging.h"

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <string>

namespace nanonos {
namespace {

LogLevel g_level = LogLevel::kWarn;
std::string g_tag;

const char* LevelName(LogLevel level) {
  switch (level) {
    case LogLevel::kDebug:
      return "DEBUG";
    case LogLevel::kInfo:
      return "INFO";
    case LogLevel::kWarn:
      return "WARN";
    case LogLevel::kError:
      return "ERROR";
    case LogLevel::kOff:
      break;
  }
  return "?";
}

}  // namespace

void SetLogLevel(LogLevel level) { g_level = level; }
LogLevel GetLogLevel() { return g_level; }
bool LogEnabled(LogLevel level) { return level >= g_level && level != LogLevel::kOff; }
void SetLogTag(std::string_view tag) { g_tag.assign(tag); }

void LogPrintf(LogLevel level, const char* fmt, ...) {
  const auto now = std::chrono::system_clock::now();
  const std::time_t seconds = std::chrono::system_clock::to_time_t(now);
  const auto millis =
      std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
  std::tm tm_value{};
#if defined(_WIN32)
  gmtime_s(&tm_value, &seconds);
#else
  gmtime_r(&seconds, &tm_value);
#endif
  char stamp[32];
  std::strftime(stamp, sizeof(stamp), "%H:%M:%S", &tm_value);
  std::fprintf(stderr, "%s.%03d %-5s %s%s", stamp, static_cast<int>(millis), LevelName(level),
               g_tag.c_str(), g_tag.empty() ? "" : ": ");
  va_list args;
  va_start(args, fmt);
  std::vfprintf(stderr, fmt, args);
  va_end(args);
  std::fputc('\n', stderr);
}

}  // namespace nanonos
