#include "linux/tcp_transport.h"

#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/logging.h"

#ifndef IP_MINTTL
#define IP_MINTTL 21
#endif

namespace nanonos::os {
namespace {

sockaddr_in Endpoint(uint32_t ip, uint16_t port) {
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(ip);
  a.sin_port = htons(port);
  return a;
}

bool SetMd5(int fd, uint32_t peer, const std::string& key) {
  tcp_md5sig md5{};
  const sockaddr_in addr = Endpoint(peer, 0);
  std::memcpy(&md5.tcpm_addr, &addr, sizeof(addr));
  md5.tcpm_keylen = static_cast<uint16_t>(key.size());
  std::memcpy(md5.tcpm_key, key.data(), key.size());
  return setsockopt(fd, IPPROTO_TCP, TCP_MD5SIG, &md5, sizeof(md5)) == 0;
}

}  // namespace

TcpTransport::TcpTransport(EventLoop* loop, uint16_t port) : loop_(loop), port_(port) {}

TcpTransport::~TcpTransport() {
  for (auto& [id, c] : conns_) close(c.fd);
  if (listen_fd_ >= 0) close(listen_fd_);
}

void TcpTransport::AddNeighbor(uint32_t address, const std::string& password,
                               int ttl_security_hops) {
  neighbors_[address] = Neighbor{password, ttl_security_hops};
}

// TTL handling: GTSM sends with TTL 255 and only accepts packets that arrive
// with TTL >= 256 - hops; otherwise eBGP uses TTL 1 (single hop).
bool TcpTransport::ApplySecurity(int fd, uint32_t peer, bool listening_socket) {
  const auto it = neighbors_.find(peer);
  const Neighbor n = it != neighbors_.end() ? it->second : Neighbor{};
  if (!n.password.empty() && !SetMd5(fd, peer, n.password)) {
    LOG_ERROR("TCP-MD5 for %s: %s", Ipv4ToString(peer).c_str(), std::strerror(errno));
    return false;
  }
  if (listening_socket) return true;
  const int ttl = n.ttl_security_hops > 0 ? 255 : 1;
  setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
  if (n.ttl_security_hops > 0) {
    const int min_ttl = 256 - n.ttl_security_hops;
    if (setsockopt(fd, IPPROTO_IP, IP_MINTTL, &min_ttl, sizeof(min_ttl)) != 0) {
      LOG_ERROR("GTSM for %s: %s", Ipv4ToString(peer).c_str(), std::strerror(errno));
      return false;
    }
  }
  const int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  return true;
}

bool TcpTransport::Listen(std::string* error) {
  listen_fd_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (listen_fd_ < 0) {
    *error = std::string("socket: ") + std::strerror(errno);
    return false;
  }
  const int one = 1;
  setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  for (const auto& [addr, n] : neighbors_) {
    // MD5 keys must be on the listening socket before the peer's SYN arrives.
    if (!n.password.empty()) ApplySecurity(listen_fd_, addr, true);
  }
  const sockaddr_in any = Endpoint(INADDR_ANY, port_);
  if (bind(listen_fd_, reinterpret_cast<const sockaddr*>(&any), sizeof(any)) != 0 ||
      listen(listen_fd_, 64) != 0) {
    *error = "listen on port " + std::to_string(port_) + ": " + std::strerror(errno);
    return false;
  }
  return loop_->Add(listen_fd_, EPOLLIN, [this](uint32_t) { OnAccept(); });
}

void TcpTransport::OnAccept() {
  while (true) {
    sockaddr_in peer{};
    socklen_t len = sizeof(peer);
    const int fd =
        accept4(listen_fd_, reinterpret_cast<sockaddr*>(&peer), &len, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) return;
    sockaddr_in local{};
    socklen_t local_len = sizeof(local);
    getsockname(fd, reinterpret_cast<sockaddr*>(&local), &local_len);
    const uint32_t remote_ip = ntohl(peer.sin_addr.s_addr);
    if (!ApplySecurity(fd, remote_ip, false)) {
      close(fd);
      continue;
    }
    const bgp::ConnId id = next_id_++;
    conns_[id] = Conn{fd, false, {}, 0};
    loop_->Add(fd, EPOLLIN, [this, id](uint32_t events) { OnEvent(id, events); });
    if (handler_ != nullptr) handler_->OnAccepted(id, ntohl(local.sin_addr.s_addr), remote_ip);
  }
}

bgp::ConnId TcpTransport::Connect(const bgp::ConnectOptions& o) {
  const bgp::ConnId id = next_id_++;
  const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    deferred_failures_.push_back(id);
    return id;
  }
  if (!ApplySecurity(fd, o.remote_ip, false)) {
    close(fd);
    deferred_failures_.push_back(id);
    return id;
  }
  const sockaddr_in local = Endpoint(o.local_ip, 0);
  bind(fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local));
  const sockaddr_in remote = Endpoint(o.remote_ip, port_);
  if (connect(fd, reinterpret_cast<const sockaddr*>(&remote), sizeof(remote)) != 0 &&
      errno != EINPROGRESS) {
    close(fd);
    deferred_failures_.push_back(id);
    return id;
  }
  conns_[id] = Conn{fd, true, {}, 0};
  loop_->Add(fd, EPOLLOUT, [this, id](uint32_t events) { OnEvent(id, events); });
  return id;
}

void TcpTransport::ProcessDeferred() {
  std::vector<bgp::ConnId> failures;
  failures.swap(deferred_failures_);
  for (bgp::ConnId id : failures) {
    if (handler_ != nullptr) handler_->OnClosed(id);
  }
}

void TcpTransport::OnEvent(bgp::ConnId id, uint32_t events) {
  auto it = conns_.find(id);
  if (it == conns_.end()) return;
  if (it->second.connecting) {
    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(it->second.fd, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err != 0 || (events & (EPOLLERR | EPOLLHUP))) {
      Drop(id);
      return;
    }
    it->second.connecting = false;
    const bool pending = it->second.out.size() > it->second.out_offset;
    loop_->Modify(it->second.fd, EPOLLIN | (pending ? EPOLLOUT : 0));
    if (handler_ != nullptr) handler_->OnConnected(id);
    return;
  }
  if (events & EPOLLOUT) {
    if (!Flush(id, it->second)) return;
  }
  if (events & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
    uint8_t buf[65536];
    while (true) {
      it = conns_.find(id);
      if (it == conns_.end()) return;  // the handler closed it
      const ssize_t n = recv(it->second.fd, buf, sizeof(buf), MSG_DONTWAIT);
      if (n > 0) {
        if (handler_ != nullptr)
          handler_->OnData(id, std::span<const uint8_t>(buf, static_cast<size_t>(n)));
        continue;
      }
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
      Drop(id);  // EOF or error
      return;
    }
  }
}

bool TcpTransport::Flush(bgp::ConnId id, Conn& c) {
  while (c.out_offset < c.out.size()) {
    const ssize_t n = send(c.fd, c.out.data() + c.out_offset, c.out.size() - c.out_offset,
                           MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n > 0) {
      c.out_offset += static_cast<size_t>(n);
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      loop_->Modify(c.fd, EPOLLIN | EPOLLOUT);
      return true;
    }
    Drop(id);
    return false;
  }
  c.out.clear();
  c.out_offset = 0;
  loop_->Modify(c.fd, EPOLLIN);
  return true;
}

bool TcpTransport::Send(bgp::ConnId id, std::span<const uint8_t> data) {
  const auto it = conns_.find(id);
  if (it == conns_.end()) return false;
  Conn& c = it->second;
  c.out.insert(c.out.end(), data.begin(), data.end());
  if (c.connecting) return true;
  // Flush may drop the connection; the close is reported via OnClosed.
  return Flush(id, c);
}

void TcpTransport::Close(bgp::ConnId id) {
  const auto it = conns_.find(id);
  if (it == conns_.end()) return;
  loop_->Remove(it->second.fd);
  close(it->second.fd);
  conns_.erase(it);
}

void TcpTransport::Drop(bgp::ConnId id) {
  Close(id);
  // Report asynchronously so the speaker is never re-entered from Send().
  deferred_failures_.push_back(id);
}

}  // namespace nanonos::os
