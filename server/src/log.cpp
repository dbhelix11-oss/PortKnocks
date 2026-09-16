#include "log.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>

namespace knockd {

namespace {

LogLevel g_min_level = LogLevel::INFO;

const char *level_name(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARN: return "WARN";
        case LogLevel::ERROR: return "ERROR";
    }
    return "?";
}

} // namespace

bool log_level_from_string(const std::string &text, LogLevel &out) {
    if (text == "debug") { out = LogLevel::DEBUG; return true; }
    if (text == "info") { out = LogLevel::INFO; return true; }
    if (text == "warn") { out = LogLevel::WARN; return true; }
    if (text == "error") { out = LogLevel::ERROR; return true; }
    return false;
}

void log_set_min_level(LogLevel level) {
    g_min_level = level;
}

void log_line(LogLevel level, const char *fmt, ...) {
    if (level < g_min_level) return;

    char timestamp[32];
    std::time_t now = std::time(nullptr);
    std::tm tm_buf{};
    gmtime_r(&now, &tm_buf);
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

    char message[1024];
    va_list args;
    va_start(args, fmt);
    std::vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    std::fprintf(stderr, "%s [%s] %s\n", timestamp, level_name(level), message);
}

} // namespace knockd
