// Small helpers shared by the engine.
#pragma once
#include <cstdio>
#include <ctime>
#include <string>

namespace aw {

inline std::string to_lower(std::string s) {
  for (auto& c : s)
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  return s;
}

inline std::string trim(const std::string& s) {
  const size_t a = s.find_first_not_of(" \t\r\n");
  if (a == std::string::npos) return "";
  const size_t b = s.find_last_not_of(" \t\r\n");
  return s.substr(a, b - a + 1);
}

// Escapes for JSON. Anything outside printable ASCII becomes \u00XX so a
// hostile request can never inject structure into the audit log.
inline std::string json_escape(const std::string& in, size_t max_len = 300) {
  std::string out;
  for (size_t i = 0; i < in.size() && i < max_len; ++i) {
    const unsigned char c = static_cast<unsigned char>(in[i]);
    if (c == '"') {
      out += "\\\"";
    } else if (c == '\\') {
      out += "\\\\";
    } else if (c < 0x20 || c >= 0x7f) {
      char b[8];
      std::snprintf(b, sizeof b, "\\u%04x", static_cast<unsigned>(c));
      out += b;
    } else {
      out.push_back(static_cast<char>(c));
    }
  }
  if (in.size() > max_len) out += "...";
  return out;
}

inline std::string iso_now() {
  const time_t t = time(nullptr);
  struct tm tmv;
  gmtime_r(&t, &tmv);
  char b[32];
  strftime(b, sizeof b, "%Y-%m-%dT%H:%M:%SZ", &tmv);
  return b;
}

// Lower-cases, removes ONE trailing dot ("example.com." == "example.com"), and
// accepts only [a-z0-9._-]. Returns "" if the name is not acceptable.
inline std::string normalize_host(const std::string& raw) {
  std::string h = to_lower(raw);
  if (!h.empty() && h.back() == '.') h.pop_back();
  if (h.empty() || h.size() > 253 || h.front() == '.' || h.front() == '-') return "";
  for (size_t i = 0; i < h.size(); ++i) {
    const char c = h[i];
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_';
    if (!ok) return "";
    if (c == '.' && i + 1 < h.size() && h[i + 1] == '.') return "";
  }
  return h;
}

// Returns 1..65535, or -1 if not a valid port number.
inline int parse_port(const std::string& s) {
  if (s.empty() || s.size() > 5) return -1;
  int v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return -1;
    v = v * 10 + (c - '0');
  }
  return (v >= 1 && v <= 65535) ? v : -1;
}

}  // namespace aw
