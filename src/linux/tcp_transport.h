// BGP transport over Linux TCP sockets, driven by the event loop. Supports
// TCP-MD5 signatures (RFC 2385) and the Generalized TTL Security Mechanism
// (GTSM, RFC 5082) per neighbor.
#pragma once

#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "linux/event_loop.h"
#include "proto/bgp_speaker.h"

namespace nanonos::os {

class TcpTransport final : public bgp::Transport {
 public:
  TcpTransport(EventLoop* loop, uint16_t port);
  ~TcpTransport() override;

  void SetHandler(bgp::TransportEvents* handler) { handler_ = handler; }
  // Security settings for connections from a neighbor; set before Listen().
  void AddNeighbor(uint32_t address, const std::string& password, int ttl_security_hops);
  bool Listen(std::string* error);
  // Delivers connect failures queued by Connect(); call once per tick.
  void ProcessDeferred();

  bgp::ConnId Connect(const bgp::ConnectOptions& options) override;
  bool Send(bgp::ConnId conn, std::span<const uint8_t> data) override;
  void Close(bgp::ConnId conn) override;

 private:
  struct Neighbor {
    std::string password;
    int ttl_security_hops = 0;
  };
  struct Conn {
    int fd = -1;
    bool connecting = false;
    std::vector<uint8_t> out;
    size_t out_offset = 0;
  };

  void OnAccept();
  void OnEvent(bgp::ConnId id, uint32_t events);
  bool Flush(bgp::ConnId id, Conn& c);
  void Drop(bgp::ConnId id);  // close and report OnClosed
  bool ApplySecurity(int fd, uint32_t peer, bool listening_socket);

  EventLoop* loop_;
  uint16_t port_;
  bgp::TransportEvents* handler_ = nullptr;
  int listen_fd_ = -1;
  bgp::ConnId next_id_ = 1;
  std::unordered_map<bgp::ConnId, Conn> conns_;
  std::map<uint32_t, Neighbor> neighbors_;
  std::vector<bgp::ConnId> deferred_failures_;
};

}  // namespace nanonos::os
