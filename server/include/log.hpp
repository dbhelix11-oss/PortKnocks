#pragma once

#include <string>

namespace knockd {

// Leveled logging to stderr. Deliberately not syslog/file-based: knockd is
// expected to run under systemd, which already captures stderr into
// journald (`journalctl -u knockd`) with its own timestamps/rotation, so
// there is nothing else to build here. A short self-timestamp is still
// included so the same log lines are still readable when redirected to a
// plain file (e.g. in tests), outside of journald.
enum class LogLevel { DEBUG = 0, INFO = 1, WARN = 2, ERROR = 3 };

// Parses "debug"/"info"/"warn"/"error" (case-insensitive). Returns false
// and leaves `out` unchanged if `text` doesn't match any level.
bool log_level_from_string(const std::string &text, LogLevel &out);

void log_set_min_level(LogLevel level);

// printf-style; lines below the current minimum level are dropped cheaply
// (level check before formatting).
void log_line(LogLevel level, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

} // namespace knockd

#define LOG_DEBUG(...) ::knockd::log_line(::knockd::LogLevel::DEBUG, __VA_ARGS__)
#define LOG_INFO(...) ::knockd::log_line(::knockd::LogLevel::INFO, __VA_ARGS__)
#define LOG_WARN(...) ::knockd::log_line(::knockd::LogLevel::WARN, __VA_ARGS__)
#define LOG_ERROR(...) ::knockd::log_line(::knockd::LogLevel::ERROR, __VA_ARGS__)
