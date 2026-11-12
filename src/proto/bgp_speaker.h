// A BGP-4 speaker for eBGP data center fabrics (the RFC 7938 design):
//
//  * per-neighbor finite state machine (Idle/Connect/Active/OpenSent/
//    OpenConfirm/Established) with connection-collision resolution (RFC 4271
//    section 6.8), hold and keepalive timers, and connect-retry jitter
//  * Adj-RIB-In, Loc-RIB and Adj-RIB-Out; best-path selection (shortest
//    AS_PATH, lowest origin, lowest MED, lowest router-id) and multipath (ECMP)
//    across paths of equal length, as RFC 7938 fabrics need
//  * loop prevention (own AS in AS_PATH), enforce-first-as, sender-side loop
//    detection, next-hop-self, and UPDATE packing by shared attributes
//
// Transport is abstract: TCP sockets on Linux (linux/tcp_transport.h), or an
// in-memory network in tests. The speaker is single-threaded and event driven.
#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/clock.h"
#include "common/hash.h"
#include "proto/bgp_message.h"

namespace nanonos::bgp {

using ConnId = uint64_t;

struct ConnectOptions {
  uint32_t local_ip = 0;
  uint32_t remote_ip = 0;
  std::string md5_password;
  int ttl_security_hops = 0;
};

class Transport {
 public:
  virtual ~Transport() = default;
  // Starts a non-blocking connect. Completion arrives later through
  // TransportEvents::OnConnected, failure through OnClosed.
  virtual ConnId Connect(const ConnectOptions& options) = 0;
  virtual bool Send(ConnId conn, std::span<const uint8_t> data) = 0;
  // Never calls back into the speaker.
  virtual void Close(ConnId conn) = 0;
};

class TransportEvents {
 public:
  virtual ~TransportEvents() = default;
  virtual void OnConnected(ConnId conn) = 0;
  virtual void OnAccepted(ConnId conn, uint32_t local_ip, uint32_t remote_ip) = 0;
  virtual void OnData(ConnId conn, std::span<const uint8_t> data) = 0;
  virtual void OnClosed(ConnId conn) = 0;
};

class RouteSink {
 public:
  virtual ~RouteSink() = default;
  // Best path changed; an empty next-hop list withdraws the route.
  virtual void OnBgpRoute(const Ipv4Prefix& prefix, const std::vector<uint32_t>& next_hops) = 0;
};

struct NeighborConfig {
  uint32_t address = 0;
  uint32_t local_address = 0;  // our address on the shared subnet
  uint32_t remote_as = 0;
  std::string description;
  std::string password;
  int ttl_security_hops = 0;
  bool passive = false;
  bool shutdown = false;
};

struct SpeakerConfig {
  uint32_t local_as = 0;
  uint32_t router_id = 0;
  uint16_t hold_time = 90;
  uint16_t keepalive = 30;
  uint16_t connect_retry = 5;
  uint16_t max_paths = 1;
  std::vector<Ipv4Prefix> networks;
  std::vector<NeighborConfig> neighbors;
};

enum class SessionState : uint8_t {
  kIdle,
  kConnect,
  kActive,
  kOpenSent,
  kOpenConfirm,
  kEstablished
};
const char* SessionStateName(SessionState state);

struct NeighborStatus {
  uint32_t address = 0;
  uint32_t remote_as = 0;
  std::string description;
  SessionState state = SessionState::kIdle;
  TimeUs established_since = 0;
  uint32_t remote_id = 0;
  uint16_t hold_time = 0;
  size_t prefixes_received = 0;
  size_t prefixes_sent = 0;
  uint64_t messages_in = 0;
  uint64_t messages_out = 0;
  uint32_t established_count = 0;
  std::string last_error;
};

struct RouteView {
  Ipv4Prefix prefix;
  bool local = false;
  std::vector<uint32_t> next_hops;
  std::vector<uint32_t> as_path;
  Origin origin = Origin::kIgp;
  size_t paths = 0;  // candidate paths considered
};

class Speaker final : public TransportEvents {
 public:
  Speaker(const SpeakerConfig& config, Transport* transport, RouteSink* sink, const Clock* clock);

  // Drives timers: connection attempts, hold timers and keepalives.
  void Tick();
  // Tears down every session to `address` (e.g. its link went down) and
  // retries after a short back-off.
  void ResetNeighbor(uint32_t address, const std::string& reason);

  std::vector<NeighborStatus> Neighbors() const;
  std::vector<RouteView> Routes() const;
  const SpeakerConfig& config() const { return config_; }

  void OnConnected(ConnId conn) override;
  void OnAccepted(ConnId conn, uint32_t local_ip, uint32_t remote_ip) override;
  void OnData(ConnId conn, std::span<const uint8_t> data) override;
  void OnClosed(ConnId conn) override;

 private:
  enum class ConnState : uint8_t { kConnecting, kOpenSent, kOpenConfirm, kEstablished };
  struct Connection {
    ConnId id = 0;
    ConnState state = ConnState::kConnecting;
    MessageReader reader;
    TimeUs started = 0;
    TimeUs hold_deadline = 0;  // 0 = no hold timer
    TimeUs keepalive_due = 0;
    uint16_t hold_time = 0;
    uint32_t remote_id = 0;
    bool as4 = false;
  };
  static constexpr int kOutgoing = 0;
  static constexpr int kIncoming = 1;

  struct Peer {
    NeighborConfig config;
    std::array<std::optional<Connection>, 2> conns;
    int established = -1;  // slot of the established connection
    TimeUs next_connect = 0;
    TimeUs established_since = 0;
    uint32_t established_count = 0;
    uint64_t messages_in = 0;
    uint64_t messages_out = 0;
    std::string last_error;
    std::map<Ipv4Prefix, PathAttributes> adj_rib_in;
    std::map<Ipv4Prefix, PathAttributes> adj_rib_out;
  };

  struct LocRibEntry {
    bool local = false;
    int best_peer = -1;
    PathAttributes attrs;
    std::vector<uint32_t> next_hops;
    size_t paths = 0;
  };

  struct Candidate {
    int peer;  // -1 = locally originated
    const PathAttributes* attrs;
  };

  void Send(Peer& peer, int slot, const std::vector<uint8_t>& message);
  void SendOpen(Peer& peer, int slot);
  void SendNotification(Peer& peer, int slot, const Error& error);
  void FsmError(size_t peer_index, int slot);
  void RefreshHold(Connection& conn);
  TimeUs KeepaliveInterval(uint16_t hold_time) const;
  uint32_t PeerRouterId(int peer) const;
  void CloseConnection(size_t peer_index, int slot, const std::string& reason);
  void PeerDown(size_t peer_index, const std::string& reason);
  void HandleMessage(size_t peer_index, int slot, MessageType type, std::span<const uint8_t> body);
  void HandleOpen(size_t peer_index, int slot, std::span<const uint8_t> body);
  void HandleUpdate(size_t peer_index, std::span<const uint8_t> body);
  void Established(size_t peer_index, int slot);
  void Recompute(const Ipv4Prefix& prefix);
  bool Better(const Candidate& a, const Candidate& b) const;
  bool MultipathEqual(const Candidate& a, const Candidate& b) const;
  std::optional<PathAttributes> OutboundAttributes(const Peer& peer,
                                                   const Ipv4Prefix& prefix) const;
  void SyncAdjRibOut(size_t peer_index, const std::set<Ipv4Prefix>& prefixes);
  void FlushAdvertisements();
  TimeUs Jitter(TimeUs base);
  int FindPeer(uint32_t address) const;

  SpeakerConfig config_;
  Transport* transport_;
  RouteSink* sink_;
  const Clock* clock_;
  std::vector<Peer> peers_;
  std::unordered_map<ConnId, std::pair<size_t, int>> conn_index_;
  std::map<Ipv4Prefix, LocRibEntry> loc_rib_;
  std::set<Ipv4Prefix> networks_;
  std::set<Ipv4Prefix> dirty_;
  PathAttributes local_attrs_;  // locally originated networks: origin IGP, empty AS_PATH
  Xorshift rng_;
};

}  // namespace nanonos::bgp
