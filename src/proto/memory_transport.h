// In-memory BGP transport for deterministic tests and simulations: speakers
// "connect" to each other's addresses, bytes are delivered in configurable
// chunk sizes (to exercise stream reassembly), and links can be cut.
#pragma once

#include <algorithm>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "proto/bgp_speaker.h"

namespace nanonos::bgp {

class MemoryNetwork {
 public:
  class Endpoint final : public Transport {
   public:
    Endpoint(MemoryNetwork* net, std::vector<uint32_t> addresses)
        : net_(net), addresses_(std::move(addresses)) {}
    void SetHandler(TransportEvents* handler) { handler_ = handler; }
    bool Owns(uint32_t ip) const {
      return std::find(addresses_.begin(), addresses_.end(), ip) != addresses_.end();
    }

    ConnId Connect(const ConnectOptions& options) override { return net_->Connect(this, options); }
    bool Send(ConnId conn, std::span<const uint8_t> data) override {
      return net_->Send(conn, data);
    }
    void Close(ConnId conn) override { net_->Close(conn); }

   private:
    friend class MemoryNetwork;
    MemoryNetwork* net_;
    std::vector<uint32_t> addresses_;
    TransportEvents* handler_ = nullptr;
  };

  Endpoint* AddEndpoint(std::vector<uint32_t> addresses) {
    endpoints_.push_back(std::make_unique<Endpoint>(this, std::move(addresses)));
    return endpoints_.back().get();
  }

  // Data is delivered in chunks of at most this many bytes.
  void SetChunkSize(size_t bytes) { chunk_ = bytes == 0 ? 1 : bytes; }

  // Cutting a link closes every connection between the two addresses and
  // refuses new ones until it is restored.
  void SetLinkUp(uint32_t a, uint32_t b, bool up) {
    const auto key = std::minmax(a, b);
    if (up) {
      down_.erase(key);
      return;
    }
    down_.insert(key);
    for (auto& [id, c] : conns_) {
      if (!c.closed && std::minmax(c.local_ip, c.remote_ip) == key) {
        c.closed = true;
        Queue(c.owner, Event{Event::kClosed, id, {}, 0, 0});
        if (conns_.count(c.peer) > 0 && !conns_[c.peer].closed) {
          conns_[c.peer].closed = true;
          Queue(conns_[c.peer].owner, Event{Event::kClosed, c.peer, {}, 0, 0});
        }
      }
    }
  }

  // Delivers queued events until none are left. Returns events delivered.
  size_t Pump(size_t max_events = 1000000) {
    size_t delivered = 0;
    while (!events_.empty() && delivered < max_events) {
      auto [endpoint, event] = std::move(events_.front());
      events_.pop_front();
      ++delivered;
      if (endpoint->handler_ == nullptr) continue;
      switch (event.kind) {
        case Event::kConnected:
          endpoint->handler_->OnConnected(event.conn);
          break;
        case Event::kAccepted:
          endpoint->handler_->OnAccepted(event.conn, event.local_ip, event.remote_ip);
          break;
        case Event::kData:
          endpoint->handler_->OnData(event.conn, event.data);
          break;
        case Event::kClosed:
          endpoint->handler_->OnClosed(event.conn);
          break;
      }
    }
    return delivered;
  }

  bool idle() const { return events_.empty(); }

 private:
  struct Event {
    enum Kind { kConnected, kAccepted, kData, kClosed } kind;
    ConnId conn;
    std::vector<uint8_t> data;
    uint32_t local_ip;
    uint32_t remote_ip;
  };
  struct Conn {
    Endpoint* owner = nullptr;
    ConnId peer = 0;
    uint32_t local_ip = 0;
    uint32_t remote_ip = 0;
    bool closed = false;
  };

  void Queue(Endpoint* e, Event ev) { events_.emplace_back(e, std::move(ev)); }

  ConnId Connect(Endpoint* from, const ConnectOptions& o) {
    const ConnId local = next_id_++;
    conns_[local] = Conn{from, 0, o.local_ip, o.remote_ip, false};
    Endpoint* target = nullptr;
    for (auto& e : endpoints_) {
      if (e.get() != from && e->Owns(o.remote_ip)) target = e.get();
    }
    if (target == nullptr || down_.count(std::minmax(o.local_ip, o.remote_ip)) > 0) {
      conns_[local].closed = true;
      Queue(from, Event{Event::kClosed, local, {}, 0, 0});
      return local;
    }
    const ConnId remote = next_id_++;
    conns_[remote] = Conn{target, local, o.remote_ip, o.local_ip, false};
    conns_[local].peer = remote;
    Queue(target, Event{Event::kAccepted, remote, {}, o.remote_ip, o.local_ip});
    Queue(from, Event{Event::kConnected, local, {}, 0, 0});
    return local;
  }

  bool Send(ConnId id, std::span<const uint8_t> data) {
    const auto it = conns_.find(id);
    if (it == conns_.end() || it->second.closed) return false;
    const Conn& peer = conns_[it->second.peer];
    if (peer.closed) return false;
    for (size_t off = 0; off < data.size(); off += chunk_) {
      const size_t n = std::min(chunk_, data.size() - off);
      Queue(peer.owner,
            Event{Event::kData, it->second.peer,
                  std::vector<uint8_t>(data.begin() + static_cast<std::ptrdiff_t>(off),
                                       data.begin() + static_cast<std::ptrdiff_t>(off + n)),
                  0, 0});
    }
    return true;
  }

  void Close(ConnId id) {
    const auto it = conns_.find(id);
    if (it == conns_.end() || it->second.closed) return;
    it->second.closed = true;
    const auto peer = conns_.find(it->second.peer);
    if (peer != conns_.end() && !peer->second.closed) {
      peer->second.closed = true;
      Queue(peer->second.owner, Event{Event::kClosed, it->second.peer, {}, 0, 0});
    }
  }

  std::vector<std::unique_ptr<Endpoint>> endpoints_;
  std::map<ConnId, Conn> conns_;
  std::deque<std::pair<Endpoint*, Event>> events_;
  std::set<std::pair<uint32_t, uint32_t>> down_;
  ConnId next_id_ = 1;
  size_t chunk_ = 65536;
};

}  // namespace nanonos::bgp
