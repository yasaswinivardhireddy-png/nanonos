// Minimal printf-style logging to stderr.
#pragma once

#include <string_view>

#if defined(__GNUC__) || defined(__clang__)
#define NANONOS_PRINTF_FORMAT(fmt_index, args_index) \
  __attribute__((format(printf, fmt_index, args_index)))
#else
#define NANONOS_PRINTF_FORMAT(fmt_index, args_index)
#endif

namespace nanonos {

enum class LogLevel : int { kDebug = 0, kInfo = 1, kWarn = 2, kError = 3, kOff = 4 };

void SetLogLevel(LogLevel level);
LogLevel GetLogLevel();
bool LogEnabled(LogLevel level);
// Prefix printed on every line, e.g. the switch hostname.
void SetLogTag(std::string_view tag);
void LogPrintf(LogLevel level, const char* fmt, ...) NANONOS_PRINTF_FORMAT(2, 3);

}  // namespace nanonos

#define NOS_LOG(level, ...)                                                     \
  do {                                                                          \
    if (::nanonos::LogEnabled(level)) ::nanonos::LogPrintf(level, __VA_ARGS__); \
  } while (0)
#define LOG_DEBUG(...) NOS_LOG(::nanonos::LogLevel::kDebug, __VA_ARGS__)
#define LOG_INFO(...) NOS_LOG(::nanonos::LogLevel::kInfo, __VA_ARGS__)
#define LOG_WARN(...) NOS_LOG(::nanonos::LogLevel::kWarn, __VA_ARGS__)
#define LOG_ERROR(...) NOS_LOG(::nanonos::LogLevel::kError, __VA_ARGS__)
