// Policy file: simple "key = value" lines. Default is DENY. Unknown keys are
// errors (fail closed) so a typo can never silently weaken the policy.
#pragma once
#include <fstream>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#include "util.hpp"

namespace aw {

struct Policy {
  bool enforce = true;                      // false = monitor mode (log only)
  std::vector<std::string> allow;           // "host" or "*.suffix"
  std::set<int> ports{80, 443};
  std::set<std::string> allow_private;      // hosts allowed to resolve to private IPs
  std::set<std::string> deny_methods;       // plain-HTTP verbs to block

  static bool valid_pattern(const std::string& p) {
    if (p.empty() || p.back() == '.') return false;
    const std::string body = (p.rfind("*.", 0) == 0) ? p.substr(2) : p;
    if (body.empty() || body.find('*') != std::string::npos) return false;
    return !normalize_host(body).empty();
  }

  static Policy load(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open policy file: " + path);
    Policy pol;
    bool ports_seen = false;
    std::string line;
    int n = 0;
    auto fail = [&](const std::string& why) {
      return std::runtime_error(path + ":" + std::to_string(n) + ": " + why);
    };
    while (std::getline(in, line)) {
      ++n;
      const size_t hash = line.find('#');
      if (hash != std::string::npos) line.erase(hash);
      line = trim(line);
      if (line.empty()) continue;
      const size_t eq = line.find('=');
      if (eq == std::string::npos) throw fail("expected 'key = value'");
      const std::string key = to_lower(trim(line.substr(0, eq)));
      std::string val = trim(line.substr(eq + 1));
      if (val.empty()) throw fail("empty value for '" + key + "'");
      if (key == "mode") {
        val = to_lower(val);
        if (val == "enforce") pol.enforce = true;
        else if (val == "monitor") pol.enforce = false;
        else throw fail("mode must be 'enforce' or 'monitor'");
      } else if (key == "allow") {
        val = to_lower(val);
        if (!valid_pattern(val)) throw fail("bad host pattern '" + val + "' (use name or *.name)");
        pol.allow.push_back(val);
      } else if (key == "allow_ports") {
        const int p = parse_port(val);
        if (p < 0) throw fail("bad port '" + val + "'");
        if (!ports_seen) {
          pol.ports.clear();
          ports_seen = true;
        }
        pol.ports.insert(p);
      } else if (key == "allow_private") {
        const std::string h = normalize_host(val);
        if (h.empty()) throw fail("bad host '" + val + "'");
        pol.allow_private.insert(h);
      } else if (key == "deny_method") {
        std::string m;
        for (char c : val) m.push_back((c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c);
        for (char c : m)
          if (c < 'A' || c > 'Z') throw fail("bad method '" + val + "'");
        pol.deny_methods.insert(m);
      } else {
        throw fail("unknown key '" + key + "'");
      }
    }
    return pol;
  }

  bool host_allowed(const std::string& host) const {
    for (const auto& p : allow) {
      if (p.rfind("*.", 0) == 0) {
        const std::string suffix = p.substr(1);  // ".example.com"
        if (host.size() > suffix.size() &&
            host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0)
          return true;
      } else if (host == p) {
        return true;
      }
    }
    return false;
  }

  bool port_allowed(int port) const { return ports.count(port) > 0; }
  bool private_ok(const std::string& host) const { return allow_private.count(host) > 0; }
};

}  // namespace aw
