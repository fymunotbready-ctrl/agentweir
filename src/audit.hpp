// Append-only, hash-chained audit log (JSON Lines). Each record includes the
// hash of the previous record, so editing or deleting a record in the middle
// of the file is detectable. It does NOT stop someone with write access from
// rebuilding the whole chain or cutting off the tail; ship logs off the
// machine (or sign them) for stronger guarantees.
#pragma once
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <stdexcept>
#include <string>
#include "sha256.hpp"
#include "util.hpp"

namespace aw {

class AuditLog {
 public:
  struct Event {
    uint64_t conn = 0;
    std::string event, decision, method, host, reason;
    int port = 0;
    uint64_t up = 0, down = 0;
  };

  static const std::string& genesis() {
    static const std::string g(64, '0');
    return g;
  }

  explicit AuditLog(const std::string& path) : prev_(genesis()) {
    std::ifstream probe(path);
    if (probe && probe.peek() != std::ifstream::traits_type::eof()) {
      std::string err;
      uint64_t count = 0;
      if (!verify(path, err, count, prev_, seq_))
        throw std::runtime_error("existing audit log failed verification (" + err +
                                 "). Move it aside to start a new log.");
    }
    out_.open(path, std::ios::app);
    if (!out_) throw std::runtime_error("cannot open audit log for writing: " + path);
  }

  void record(const Event& e) {
    std::lock_guard<std::mutex> lock(mu_);
    ++seq_;
    const std::string body =
        "{\"seq\":" + std::to_string(seq_) + ",\"ts\":\"" + iso_now() + "\",\"conn\":" +
        std::to_string(e.conn) + ",\"event\":\"" + json_escape(e.event) + "\",\"decision\":\"" +
        json_escape(e.decision) + "\",\"method\":\"" + json_escape(e.method) + "\",\"host\":\"" +
        json_escape(e.host) + "\",\"port\":" + std::to_string(e.port) + ",\"reason\":\"" +
        json_escape(e.reason) + "\",\"up\":" + std::to_string(e.up) + ",\"down\":" +
        std::to_string(e.down) + ",\"prev\":\"" + prev_ + "\"}";
    const std::string h = Sha256::of(body);
    out_ << body.substr(0, body.size() - 1) << ",\"hash\":\"" << h << "\"}\n";
    out_.flush();
    prev_ = h;
  }

  // Checks every record's hash, chain link and sequence number.
  static bool verify(const std::string& path, std::string& err, uint64_t& count,
                     std::string& last_hash, uint64_t& last_seq) {
    std::ifstream in(path);
    if (!in) {
      err = "cannot open " + path;
      return false;
    }
    static const std::string tag = ",\"hash\":\"";
    static const std::string ptag = "\"prev\":\"";
    std::string line, prev = genesis();
    uint64_t n = 0, seq = 0;
    while (std::getline(in, line)) {
      ++n;
      const std::string where = "line " + std::to_string(n) + ": ";
      const size_t pos = line.rfind(tag);
      if (pos == std::string::npos || line.size() != pos + tag.size() + 64 + 2 ||
          line.compare(line.size() - 2, 2, "\"}") != 0) {
        err = where + "malformed record";
        return false;
      }
      const std::string hash = line.substr(pos + tag.size(), 64);
      const std::string body = line.substr(0, pos) + "}";
      if (Sha256::of(body) != hash) {
        err = where + "hash mismatch (record was modified)";
        return false;
      }
      const size_t pp = body.rfind(ptag);
      if (pp == std::string::npos || body.size() < pp + ptag.size() + 64) {
        err = where + "malformed record";
        return false;
      }
      if (body.compare(pp + ptag.size(), 64, prev) != 0) {
        err = where + "chain broken (a record was removed, inserted or reordered)";
        return false;
      }
      const size_t sp = body.find("\"seq\":");
      if (sp == std::string::npos) {
        err = where + "missing sequence number";
        return false;
      }
      const uint64_t s = std::strtoull(body.c_str() + sp + 6, nullptr, 10);
      if (s != seq + 1) {
        err = where + "sequence gap";
        return false;
      }
      seq = s;
      prev = hash;
    }
    count = n;
    last_hash = prev;
    last_seq = seq;
    return true;
  }

 private:
  std::mutex mu_;
  std::ofstream out_;
  std::string prev_;
  uint64_t seq_ = 0;
};

}  // namespace aw
