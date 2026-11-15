// agentwall - egress firewall + audit log for AI agents (Layer 1 + 3 prototype).
//
//   agentwall run    --policy FILE [--log FILE] -- COMMAND [ARGS...]
//   agentwall proxy  --policy FILE [--log FILE] [--listen HOST:PORT]
//   agentwall check  --policy FILE HOST:PORT [METHOD]
//   agentwall verify LOGFILE
//   agentwall selftest
//
// HONEST LIMITATION: this works by pointing the agent at a local proxy through
// environment variables. A program that ignores proxy settings, or opens raw
// sockets, is NOT restricted. Treat it as a guard rail and an audit trail for
// cooperative software, not as a sandbox. A kernel-enforced mode is planned.
#include <arpa/inet.h>
#include <sys/wait.h>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <thread>
#include <utility>
#include <vector>
#include "audit.hpp"
#include "net.hpp"
#include "policy.hpp"
#include "sha256.hpp"
#include "util.hpp"

using namespace aw;

static const char* const kVersion = "0.2.0";

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_child = 0;

static void on_signal(int sig) {
  g_stop = 1;
  if (g_child > 0) kill(static_cast<pid_t>(g_child), sig);
}

struct Server {
  Policy policy;
  AuditLog* log = nullptr;
  std::atomic<uint64_t> next_id{0};
  std::atomic<int> active{0};
};

static const int kMaxConnections = 256;
static const int kIdleMs = 120000;

struct Request {
  std::string method, target, version;
  std::vector<std::pair<std::string, std::string>> headers;
};

static bool parse_request(const std::string& head, Request& req) {
  const size_t eol = head.find("\r\n");
  if (eol == std::string::npos) return false;
  const std::string first = head.substr(0, eol);
  const size_t s1 = first.find(' ');
  const size_t s2 = first.rfind(' ');
  if (s1 == std::string::npos || s2 == s1) return false;
  req.method = first.substr(0, s1);
  req.target = first.substr(s1 + 1, s2 - s1 - 1);
  req.version = first.substr(s2 + 1);
  if (req.method.empty() || req.target.empty() || req.target.find(' ') != std::string::npos) return false;
  if (req.version.rfind("HTTP/1.", 0) != 0) return false;
  for (char c : req.method)
    if (c < 'A' || c > 'Z') return false;
  size_t pos = eol + 2;
  while (pos < head.size()) {
    const size_t e = head.find("\r\n", pos);
    if (e == std::string::npos || e == pos) break;
    const std::string line = head.substr(pos, e - pos);
    pos = e + 2;
    const size_t c = line.find(':');
    if (c == std::string::npos || c == 0) return false;  // also rejects obsolete line folding
    const std::string name = line.substr(0, c);
    for (char ch : name)
      if (ch == ' ' || ch == '\t') return false;
    req.headers.emplace_back(name, trim(line.substr(c + 1)));
  }
  return true;
}

// default_port < 0 means the port is mandatory (CONNECT).
static bool split_host_port(const std::string& auth, std::string& host, int& port, int default_port) {
  if (auth.empty() || auth.find('@') != std::string::npos || auth.find('[') != std::string::npos)
    return false;  // user-info and IPv6 literals are not supported
  const size_t c = auth.rfind(':');
  const std::string h = (c == std::string::npos) ? auth : auth.substr(0, c);
  host = normalize_host(h);
  if (host.empty()) return false;
  if (c == std::string::npos) {
    if (default_port < 0) return false;
    port = default_port;
    return true;
  }
  port = parse_port(auth.substr(c + 1));
  return port > 0;
}

static bool violates_policy(const Policy& pol, const std::string& host, int port,
                            const std::string& method, bool is_connect, std::string& reason) {
  if (!pol.host_allowed(host)) {
    reason = "host not in allowlist";
    return true;
  }
  if (!pol.port_allowed(port)) {
    reason = "port " + std::to_string(port) + " not allowed";
    return true;
  }
  if (!is_connect && pol.deny_methods.count(method)) {
    reason = "method " + method + " denied by policy";
    return true;
  }
  return false;
}

static void reply(int fd, int code, const char* text, const std::string& msg) {
  const std::string body = "agentwall: " + msg + "\n";
  send_all(fd, "HTTP/1.1 " + std::to_string(code) + " " + text +
                   "\r\nContent-Type: text/plain\r\nContent-Length: " + std::to_string(body.size()) +
                   "\r\nConnection: close\r\n\r\n" + body);
}

static void handle(Server& S, Fd client, uint64_t id) {
  const timeval rcv = {10, 0}, snd = {30, 0};
  setsockopt(client.get(), SOL_SOCKET, SO_RCVTIMEO, &rcv, sizeof rcv);
  setsockopt(client.get(), SOL_SOCKET, SO_SNDTIMEO, &snd, sizeof snd);

  auto rec = [&](const char* event, const char* decision, const std::string& method,
                 const std::string& host, int port, const std::string& reason, uint64_t up = 0,
                 uint64_t down = 0) {
    AuditLog::Event e;
    e.conn = id;
    e.event = event;
    e.decision = decision;
    e.method = method;
    e.host = host;
    e.port = port;
    e.reason = reason;
    e.up = up;
    e.down = down;
    S.log->record(e);
    if (std::strcmp(event, "request") == 0 && std::strcmp(decision, "allow") != 0) {
      const std::string who = host.empty() ? "(malformed request)" : host + ":" + std::to_string(port);
      const char* label = std::strcmp(decision, "deny") == 0 ? "BLOCKED"
                          : std::strcmp(decision, "error") == 0 ? "ERROR" : "WOULD BLOCK";
      const std::string msg = std::string("agentwall: ") + label + " " + who + " - " +
                              json_escape(reason, 120) + "\n";
      std::fputs(msg.c_str(), stderr);
    }
  };
  auto bad = [&](int code, const char* text, const std::string& why) {
    rec("request", "deny", "", "", 0, why);
    reply(client.get(), code, text, why);
  };

  std::string head, rest;
  const int rc = read_head(client.get(), head, rest, 16384);
  if (rc == -2) return bad(431, "Request Header Fields Too Large", "request headers too large");
  if (rc != 0) return;

  Request rq;
  if (!parse_request(head, rq)) return bad(400, "Bad Request", "malformed request");

  const bool is_connect = rq.method == "CONNECT";
  std::string host, path;
  int port = 0;
  if (is_connect) {
    if (!split_host_port(rq.target, host, port, -1)) return bad(400, "Bad Request", "invalid CONNECT target");
  } else {
    static const std::set<std::string> known = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"};
    if (!known.count(rq.method)) return bad(405, "Method Not Allowed", "method not supported");
    const std::string lt = to_lower(rq.target);
    if (lt.rfind("https://", 0) == 0) return bad(400, "Bad Request", "use CONNECT for https");
    if (lt.rfind("http://", 0) != 0) return bad(400, "Bad Request", "proxy requests need an absolute http:// URL");
    const std::string after = rq.target.substr(7);
    const size_t slash = after.find_first_of("/?#");
    const std::string auth = after.substr(0, slash);
    path = (slash == std::string::npos) ? "/" : after.substr(slash);
    if (path[0] != '/') path = "/" + path;
    if (!split_host_port(auth, host, port, 80)) return bad(400, "Bad Request", "invalid host in URL");
  }

  std::string reason;
  const bool violates = violates_policy(S.policy, host, port, rq.method, is_connect, reason);
  if (violates && S.policy.enforce) {
    rec("request", "deny", rq.method, host, port, reason);
    return reply(client.get(), 403, "Forbidden", "blocked by policy: " + reason);
  }

  ConnectResult cr = connect_host(host, port, S.policy.enforce && !S.policy.private_ok(host), 8000);
  if (cr.blocked) {
    rec("request", "deny", rq.method, host, port, cr.error);
    return reply(client.get(), 403, "Forbidden", "blocked by policy: " + cr.error);
  }
  if (!cr.fd.ok()) {
    rec("request", "error", rq.method, host, port, cr.error);
    return reply(client.get(), 502, "Bad Gateway", cr.error);
  }
  const char* dec = "allow";
  if (violates) {
    dec = "monitor_would_deny";
    rec("request", dec, rq.method, host, port, reason);
  } else if (cr.saw_private && !S.policy.private_ok(host)) {
    dec = "monitor_would_deny";
    rec("request", dec, rq.method, host, port, "host resolves to a private or internal address");
  } else {
    rec("request", dec, rq.method, host, port, "allowlisted");
  }

  Fd upstream = std::move(cr.fd);
  const timeval usnd = {30, 0};
  setsockopt(upstream.get(), SOL_SOCKET, SO_SNDTIMEO, &usnd, sizeof usnd);

  uint64_t up = 0, down = 0;
  if (is_connect) {
    if (!send_all(client.get(), "HTTP/1.1 200 Connection Established\r\n\r\n")) return;
  } else {
    // Rebuild the request: the Host header always matches the host we vetted, so a
    // client cannot say "allowed.com" in the URL and "evil.com" in Host.
    std::string out = rq.method + " " + path + " HTTP/1.1\r\nHost: " + host +
                      (port != 80 ? ":" + std::to_string(port) : "") + "\r\n";
    for (const auto& h : rq.headers) {
      const std::string n = to_lower(h.first);
      if (n == "host" || n == "proxy-connection" || n == "proxy-authorization" || n == "connection" ||
          n == "keep-alive" || n == "upgrade")
        continue;
      out += h.first + ": " + h.second + "\r\n";
    }
    out += "Connection: close\r\n\r\n";
    if (!send_all(upstream.get(), out)) return;
  }
  if (!rest.empty()) {
    if (!send_all(upstream.get(), rest)) return;
    up += rest.size();
  }
  relay(client.get(), upstream.get(), kIdleMs, up, down);
  rec("close", dec, rq.method, host, port, "closed", up, down);
}

static Fd make_listener(const std::string& host, int port, int& bound, std::string& err) {
  Fd fd(::socket(AF_INET, SOCK_STREAM, 0));
  if (!fd.ok()) {
    err = std::strerror(errno);
    return Fd();
  }
  const int one = 1;
  setsockopt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  sockaddr_in a;
  std::memset(&a, 0, sizeof a);
  a.sin_family = AF_INET;
  a.sin_port = htons(static_cast<uint16_t>(port));
  if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) {
    err = "listen address must be an IPv4 address like 127.0.0.1";
    return Fd();
  }
  if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&a), sizeof a) != 0 || ::listen(fd.get(), 128) != 0) {
    err = std::strerror(errno);
    return Fd();
  }
  socklen_t len = sizeof a;
  getsockname(fd.get(), reinterpret_cast<sockaddr*>(&a), &len);
  bound = ntohs(a.sin_port);
  return fd;
}

static void accept_loop(Server& S, int lfd, std::atomic<bool>& stop) {
  while (!stop && !g_stop) {
    pollfd p = {lfd, POLLIN, 0};
    if (poll(&p, 1, 200) <= 0) continue;
    Fd c(::accept(lfd, nullptr, nullptr));
    if (!c.ok()) continue;
    if (S.active >= kMaxConnections) {
      reply(c.get(), 503, "Service Unavailable", "too many connections");
      continue;
    }
    ++S.active;
    const uint64_t id = ++S.next_id;
    try {
      std::thread([&S, id](Fd cl) {
        try {
          handle(S, std::move(cl), id);
        } catch (...) {
        }
        --S.active;
      }, std::move(c)).detach();
    } catch (...) {
      --S.active;
    }
  }
}

struct Opts {
  std::string policy, log = "agentwall-audit.jsonl", listen = "127.0.0.1:8899";
  std::vector<std::string> rest;
};

static bool parse_opts(int argc, char** argv, int start, bool cmd_mode, Opts& o, std::string& err) {
  for (int i = start; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--") {
      for (++i; i < argc; ++i) o.rest.push_back(argv[i]);
      return true;
    }
    if (a == "--policy" || a == "--log" || a == "--listen") {
      if (i + 1 >= argc) {
        err = "missing value for " + a;
        return false;
      }
      const std::string v = argv[++i];
      (a == "--policy" ? o.policy : a == "--log" ? o.log : o.listen) = v;
    } else if (!a.empty() && a[0] == '-') {
      err = "unknown option " + a;
      return false;
    } else {
      o.rest.push_back(a);
      if (cmd_mode) {
        for (++i; i < argc; ++i) o.rest.push_back(argv[i]);
        return true;
      }
    }
  }
  return true;
}

static int usage() {
  std::cerr << "agentwall - egress firewall and audit log for AI agents\n\n"
               "  agentwall run    --policy FILE [--log FILE] -- COMMAND [ARGS...]\n"
               "  agentwall proxy  --policy FILE [--log FILE] [--listen 127.0.0.1:8899]\n"
               "  agentwall check  --policy FILE HOST:PORT [METHOD]\n"
               "  agentwall verify LOGFILE\n"
               "  agentwall report LOGFILE            what the program connected to\n"
               "  agentwall suggest LOGFILE           draft a policy from what was observed\n"
               "  agentwall selftest\n"
               "  agentwall version\n";
  return 2;
}

static int cmd_selftest() {
  struct V { std::string in, out; };
  const std::vector<V> v = {
      {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
      {std::string(1000000, 'a'), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"}};
  int bad = 0;
  for (const auto& t : v) {
    const bool ok = Sha256::of(t.in) == t.out;
    std::cout << (ok ? "PASS" : "FAIL") << " sha256 vector (" << t.in.size() << " bytes)\n";
    if (!ok) ++bad;
  }
  return bad ? 1 : 0;
}

static int cmd_verify(const std::string& path) {
  std::string err, last;
  uint64_t count = 0, seq = 0;
  if (!AuditLog::verify(path, err, count, last, seq)) {
    std::cout << "FAILED: " << err << "\n";
    return 1;
  }
  std::cout << "OK: " << count << " records, chain valid, last hash " << last << "\n";
  return 0;
}

static std::string field_str(const std::string& line, const std::string& key) {
  const std::string tag = "\"" + key + "\":\"";
  size_t p = line.find(tag);
  if (p == std::string::npos) return "";
  p += tag.size();
  std::string out;
  while (p < line.size() && line[p] != '"') {
    if (line[p] == '\\' && p + 1 < line.size()) {
      out.push_back(line[p + 1]);
      p += 2;
    } else {
      out.push_back(line[p++]);
    }
  }
  return out;
}

static long field_num(const std::string& line, const std::string& key) {
  const std::string tag = "\"" + key + "\":";
  const size_t p = line.find(tag);
  return p == std::string::npos ? 0 : std::strtol(line.c_str() + p + tag.size(), nullptr, 10);
}

// Both report and suggest only read logs whose hash chain verifies.
static bool load_verified(const std::string& path, std::vector<std::string>& lines) {
  std::string err, last;
  uint64_t count = 0, seq = 0;
  if (!AuditLog::verify(path, err, count, last, seq)) {
    std::cerr << "error: log failed verification: " << err << "\n";
    return false;
  }
  std::ifstream in(path);
  std::string line;
  while (std::getline(in, line)) lines.push_back(line);
  return true;
}

static int cmd_report(const std::string& path) {
  std::vector<std::string> lines;
  if (!load_verified(path, lines)) return 1;
  struct C { long allow = 0, deny = 0, would = 0, err = 0; };
  std::map<std::string, C> m;
  for (const auto& l : lines) {
    if (field_str(l, "event") != "request") continue;
    const std::string host = field_str(l, "host"), d = field_str(l, "decision");
    const std::string key = host.empty() ? "(malformed request)" : host + ":" + std::to_string(field_num(l, "port"));
    C& c = m[key];
    if (d == "allow") ++c.allow;
    else if (d == "deny") ++c.deny;
    else if (d == "monitor_would_deny") ++c.would;
    else ++c.err;
  }
  std::printf("%-38s %8s %8s %12s %7s\n", "HOST:PORT", "ALLOWED", "BLOCKED", "WOULD-BLOCK", "ERRORS");
  for (const auto& kv : m)
    std::printf("%-38s %8ld %8ld %12ld %7ld\n", kv.first.c_str(), kv.second.allow, kv.second.deny,
                kv.second.would, kv.second.err);
  return 0;
}

static int cmd_suggest(const std::string& path) {
  std::vector<std::string> lines;
  if (!load_verified(path, lines)) return 1;
  std::set<std::string> hosts, priv;
  std::set<long> ports;
  for (const auto& l : lines) {
    if (field_str(l, "event") != "request") continue;
    const std::string d = field_str(l, "decision"), host = field_str(l, "host");
    if (host.empty() || (d != "allow" && d != "monitor_would_deny")) continue;
    if (field_str(l, "reason").find("private") != std::string::npos) {
      priv.insert(host);
    } else {
      hosts.insert(host);
      ports.insert(field_num(l, "port"));
    }
  }
  std::printf("# Drafted by 'agentwall suggest' from %s\n", path.c_str());
  std::printf("# REVIEW EVERY LINE. This lists what the program DID, not what is safe.\n");
  std::printf("# If the run was compromised, the bad destinations are listed here too.\n");
  std::printf("# Ports below apply to all hosts; tighten by hand if needed.\n");
  std::printf("mode = enforce\n");
  if (hosts.empty()) std::printf("# (no connections were observed)\n");
  for (const auto& h : hosts) std::printf("allow = %s\n", h.c_str());
  for (long p : ports) std::printf("allow_ports = %ld\n", p);
  for (const auto& h : priv)
    std::printf("# %s resolved to a private/internal address. Only if intended: allow = %s and allow_private = %s\n",
                h.c_str(), h.c_str(), h.c_str());
  return 0;
}

static int cmd_check(const Opts& o) {
  if (o.policy.empty() || o.rest.empty()) return usage();
  const Policy pol = Policy::load(o.policy);
  std::string host;
  int port = 0;
  if (!split_host_port(o.rest[0], host, port, -1)) {
    std::cout << "DENY: invalid host:port\n";
    return 1;
  }
  const std::string method = o.rest.size() > 1 ? o.rest[1] : "CONNECT";
  std::string reason;
  if (violates_policy(pol, host, port, method, method == "CONNECT", reason)) {
    std::cout << "DENY: " << reason << "\n";
    return 1;
  }
  std::cout << "ALLOW\n";
  return 0;
}

static int cmd_serve(const Opts& o, bool run_mode) {
  if (o.policy.empty()) {
    std::cerr << "error: --policy is required\n";
    return 2;
  }
  if (run_mode && o.rest.empty()) {
    std::cerr << "error: put the command to run after --, e.g.  agentwall run --policy p.conf -- python3 agent.py\n";
    return 2;
  }
  Server S;
  AuditLog* log = nullptr;
  try {
    S.policy = Policy::load(o.policy);
    log = new AuditLog(o.log);
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 2;
  }
  S.log = log;

  std::string lhost = "127.0.0.1";
  int lport = 0;
  if (!run_mode) {
    const size_t c = o.listen.rfind(':');
    lhost = o.listen.substr(0, c);
    lport = (c == std::string::npos) ? -1 : (o.listen.substr(c + 1) == "0" ? 0 : parse_port(o.listen.substr(c + 1)));
    if (lport < 0) {
      std::cerr << "error: --listen must look like 127.0.0.1:8899\n";
      return 2;
    }
    if (lhost != "127.0.0.1")
      std::cerr << "WARNING: listening on " << lhost << " exposes this proxy to other machines.\n";
  }
  int bound = 0;
  std::string err;
  Fd lfd = make_listener(lhost, lport, bound, err);
  if (!lfd.ok()) {
    std::cerr << "error: cannot listen: " << err << "\n";
    return 2;
  }

  struct sigaction sa;
  std::memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_signal;
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);
  signal(SIGPIPE, SIG_IGN);

  std::cerr << "agentwall: mode=" << (S.policy.enforce ? "enforce" : "monitor") << " log=" << o.log << "\n";
  std::atomic<bool> stop{false};

  int exit_code = 0;
  if (!run_mode) {
    std::cout << "listening on " << lhost << ":" << bound << std::endl;
    accept_loop(S, lfd.get(), stop);
  } else {
    const std::string proxy = "http://127.0.0.1:" + std::to_string(bound);
    for (const char* k : {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"})
      setenv(k, proxy.c_str(), 1);
    setenv("NO_PROXY", "", 1);
    setenv("no_proxy", "", 1);
    std::cerr << "agentwall: proxy " << proxy << "\n"
              << "agentwall: NOTE programs that ignore proxy settings are not restricted by this mode.\n";
    std::vector<char*> args;
    for (const auto& s : o.rest) args.push_back(const_cast<char*>(s.c_str()));
    args.push_back(nullptr);
    std::thread srv([&] { accept_loop(S, lfd.get(), stop); });
    const pid_t pid = fork();
    if (pid == 0) {
      signal(SIGPIPE, SIG_DFL);
      execvp(args[0], args.data());
      const char m[] = "agentwall: cannot run command\n";
      if (write(2, m, sizeof m - 1) < 0) {}
      _exit(127);
    }
    if (pid < 0) {
      std::cerr << "error: fork failed\n";
      exit_code = 2;
    } else {
      g_child = pid;
      int st = 0;
      while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {
      }
      g_child = 0;
      exit_code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
    }
    stop = true;
    srv.join();
  }
  for (int i = 0; i < 20 && S.active > 0; ++i) usleep(100000);
  return exit_code;
}

int main(int argc, char** argv) {
  if (argc < 2) return usage();
  const std::string cmd = argv[1];
  Opts o;
  std::string err;
  try {
    if (cmd == "version" || cmd == "--version") {
      std::cout << "agentwall " << kVersion << "\n";
      return 0;
    }
    if (cmd == "selftest") return cmd_selftest();
    if (cmd == "verify") return argc == 3 ? cmd_verify(argv[2]) : usage();
    if (cmd == "report") return argc == 3 ? cmd_report(argv[2]) : usage();
    if (cmd == "suggest") return argc == 3 ? cmd_suggest(argv[2]) : usage();
    if (!parse_opts(argc, argv, 2, cmd == "run", o, err)) {
      std::cerr << "error: " << err << "\n";
      return 2;
    }
    if (cmd == "check") return cmd_check(o);
    if (cmd == "proxy") return cmd_serve(o, false);
    if (cmd == "run") return cmd_serve(o, true);
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 2;
  }
  return usage();
}
