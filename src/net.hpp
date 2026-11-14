// Networking helpers: RAII sockets, private-address detection, vetted connect,
// and a byte relay. POSIX only (Linux, macOS, WSL).
#pragma once
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace aw {

class Fd {
 public:
  Fd() = default;
  explicit Fd(int fd) : fd_(fd) {}
  ~Fd() { reset(); }
  Fd(Fd&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
  Fd& operator=(Fd&& o) noexcept {
    if (this != &o) {
      reset();
      fd_ = o.fd_;
      o.fd_ = -1;
    }
    return *this;
  }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  int get() const { return fd_; }
  bool ok() const { return fd_ >= 0; }
  void reset() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
  }

 private:
  int fd_ = -1;
};

// Loopback, private, link-local (incl. cloud metadata 169.254.169.254), CGNAT,
// multicast and reserved ranges. 'a' is in host byte order.
inline bool is_private_v4(uint32_t a) {
  return (a >> 24) == 0 || (a >> 24) == 10 || (a >> 24) == 127 ||
         (a & 0xFFFF0000u) == 0xA9FE0000u ||  // 169.254.0.0/16
         (a & 0xFFF00000u) == 0xAC100000u ||  // 172.16.0.0/12
         (a & 0xFFFF0000u) == 0xC0A80000u ||  // 192.168.0.0/16
         (a & 0xFFC00000u) == 0x64400000u ||  // 100.64.0.0/10
         (a & 0xFFFFFF00u) == 0xC0000000u ||  // 192.0.0.0/24
         (a >> 28) >= 14;                      // 224.0.0.0/4 and 240.0.0.0/4
}

inline bool is_private_addr(const sockaddr* sa) {
  if (sa->sa_family == AF_INET) {
    const auto* s = reinterpret_cast<const sockaddr_in*>(sa);
    return is_private_v4(ntohl(s->sin_addr.s_addr));
  }
  if (sa->sa_family == AF_INET6) {
    const auto* s = reinterpret_cast<const sockaddr_in6*>(sa);
    const uint8_t* b = s->sin6_addr.s6_addr;
    bool first12_zero = true;
    for (int i = 0; i < 12; ++i)
      if (b[i]) first12_zero = false;
    if (first12_zero) return true;  // ::, ::1, IPv4-compatible
    bool mapped = true;
    for (int i = 0; i < 10; ++i)
      if (b[i]) mapped = false;
    if (mapped && b[10] == 0xFF && b[11] == 0xFF) {  // ::ffff:a.b.c.d
      const uint32_t a = (uint32_t(b[12]) << 24) | (uint32_t(b[13]) << 16) |
                         (uint32_t(b[14]) << 8) | uint32_t(b[15]);
      return is_private_v4(a);
    }
    if ((b[0] & 0xFE) == 0xFC) return true;                    // fc00::/7
    if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return true;    // fe80::/10
    if (b[0] == 0xFF) return true;                             // multicast
    return false;
  }
  return true;  // unknown address family: refuse
}

struct ConnectResult {
  Fd fd;
  bool blocked = false;       // refused because the host resolves to a private address
  bool saw_private = false;   // at least one resolved address was private
  std::string error;
};

// Resolves once, vets every address, then connects ONLY to the vetted
// addresses (no second lookup, so DNS rebinding cannot swap the target).
inline ConnectResult connect_host(const std::string& host, int port, bool block_private,
                                  int timeout_ms) {
  ConnectResult r;
  addrinfo hints;
  std::memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  const std::string svc = std::to_string(port);
  const int rc = getaddrinfo(host.c_str(), svc.c_str(), &hints, &res);
  if (rc != 0 || !res) {
    r.error = std::string("DNS lookup failed: ") + gai_strerror(rc);
    return r;
  }
  std::unique_ptr<addrinfo, void (*)(addrinfo*)> guard(res, freeaddrinfo);
  for (addrinfo* a = res; a; a = a->ai_next)
    if (is_private_addr(a->ai_addr)) r.saw_private = true;
  if (r.saw_private && block_private) {
    r.blocked = true;
    r.error = "host resolves to a private or internal address";
    return r;
  }
  std::string last = "no usable address";
  for (addrinfo* a = res; a; a = a->ai_next) {
    Fd s(::socket(a->ai_family, a->ai_socktype, a->ai_protocol));
    if (!s.ok()) {
      last = std::strerror(errno);
      continue;
    }
    const int flags = fcntl(s.get(), F_GETFL, 0);
    fcntl(s.get(), F_SETFL, flags | O_NONBLOCK);
    const int c = ::connect(s.get(), a->ai_addr, a->ai_addrlen);
    if (c < 0 && errno != EINPROGRESS) {
      last = std::strerror(errno);
      continue;
    }
    if (c < 0) {
      pollfd p = {s.get(), POLLOUT, 0};
      const int pr = poll(&p, 1, timeout_ms);
      if (pr <= 0) {
        last = pr == 0 ? "connect timed out" : std::strerror(errno);
        continue;
      }
      int so = 0;
      socklen_t sl = sizeof so;
      getsockopt(s.get(), SOL_SOCKET, SO_ERROR, &so, &sl);
      if (so != 0) {
        last = std::strerror(so);
        continue;
      }
    }
    fcntl(s.get(), F_SETFL, flags);
    const int one = 1;
    setsockopt(s.get(), IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    r.fd = std::move(s);
    return r;
  }
  r.error = "connect failed: " + last;
  return r;
}

inline bool send_all(int fd, const char* data, size_t len) {
  size_t off = 0;
  while (off < len) {
    const ssize_t w = ::send(fd, data + off, len - off, MSG_NOSIGNAL);
    if (w < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    off += static_cast<size_t>(w);
  }
  return true;
}
inline bool send_all(int fd, const std::string& s) { return send_all(fd, s.data(), s.size()); }

// Reads until the blank line that ends the HTTP header block.
// 0 = ok, -1 = closed/timeout, -2 = too large.
inline int read_head(int fd, std::string& head, std::string& rest, size_t max_bytes) {
  std::string acc;
  char buf[4096];
  while (acc.size() < max_bytes) {
    const ssize_t n = ::recv(fd, buf, sizeof buf, 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return -1;
    acc.append(buf, static_cast<size_t>(n));
    const size_t pos = acc.find("\r\n\r\n");
    if (pos != std::string::npos) {
      if (pos + 4 > max_bytes) return -2;
      head = acc.substr(0, pos + 4);
      rest = acc.substr(pos + 4);
      return 0;
    }
  }
  return -2;
}

enum class Pump { More, Eof, Error };

inline Pump pump(int from, int to, uint64_t& counter) {
  char buf[16384];
  const ssize_t n = ::recv(from, buf, sizeof buf, 0);
  if (n > 0) {
    if (!send_all(to, buf, static_cast<size_t>(n))) return Pump::Error;
    counter += static_cast<uint64_t>(n);
    return Pump::More;
  }
  if (n == 0) {
    ::shutdown(to, SHUT_WR);
    return Pump::Eof;
  }
  return errno == EINTR ? Pump::More : Pump::Error;
}

// Copies bytes both ways until both sides finish, an error occurs, or nothing
// moves for idle_ms.
inline void relay(int a, int b, int idle_ms, uint64_t& a_to_b, uint64_t& b_to_a) {
  bool a_open = true, b_open = true;
  while (a_open || b_open) {
    pollfd p[2];
    nfds_t n = 0;
    int ia = -1, ib = -1;
    if (a_open) {
      p[n] = {a, POLLIN, 0};
      ia = static_cast<int>(n++);
    }
    if (b_open) {
      p[n] = {b, POLLIN, 0};
      ib = static_cast<int>(n++);
    }
    const int r = poll(p, n, idle_ms);
    if (r == 0) return;
    if (r < 0) {
      if (errno == EINTR) continue;
      return;
    }
    if (ia >= 0 && (p[ia].revents & (POLLIN | POLLHUP | POLLERR))) {
      const Pump s = pump(a, b, a_to_b);
      if (s == Pump::Error) return;
      if (s == Pump::Eof) a_open = false;
    }
    if (ib >= 0 && (p[ib].revents & (POLLIN | POLLHUP | POLLERR))) {
      const Pump s = pump(b, a, b_to_a);
      if (s == Pump::Error) return;
      if (s == Pump::Eof) b_open = false;
    }
  }
}

}  // namespace aw
