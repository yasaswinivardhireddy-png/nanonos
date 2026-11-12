#include "proto/bgp_speaker.h"

#include <algorithm>

#include "common/logging.h"

namespace nanonos::bgp {
namespace {

constexpr TimeUs kOpenHoldTime = 240 * kUsPerSec;  // hold timer while waiting for the peer's OPEN
constexpr TimeUs kRestartDelay = 1 * kUsPerSec;    // back-off before reconnecting after a drop

std::string Addr(uint32_t ip) { return Ipv4ToString(ip); }

}  // namespace

const char* SessionStateName(SessionState state) {
  switch (state) {
    case SessionState::kIdle:
      return "Idle";
    case SessionState::kConnect:
      return "Connect";
    case SessionState::kActive:
      return "Active";
    case SessionState::kOpenSent:
      return "OpenSent";
    case SessionState::kOpenConfirm:
      return "OpenConfirm";
    case SessionState::kEstablished:
      return "Established";
  }
  return "?";
}

Speaker::Speaker(const SpeakerConfig& config, Transport* transport, RouteSink* sink,
                 const Clock* clock)
    : config_(config),
      transport_(transport),
      sink_(sink),
      clock_(clock),
      rng_(0x6267700000000000ULL ^ config.router_id) {
  const TimeUs now = clock_->Now();
  for (const NeighborConfig& n : config.neighbors) {
    Peer p;
    p.config = n;
    // Small random start delay so two speakers rarely open simultaneous connections.
    p.next_connect = now + static_cast<TimeUs>(rng_.Below(200 * kUsPerMs));
    peers_.push_back(std::move(p));
  }
  for (const Ipv4Prefix& n : config.networks) {
    networks_.insert(Ipv4Prefix::Make(n.addr, n.len));
    Recompute(Ipv4Prefix::Make(n.addr, n.len));
  }
}

TimeUs Speaker::Jitter(TimeUs base) {
  // RFC 4271 section 10: jitter timers to 75-100% of their value.
  return base * 3 / 4 + static_cast<TimeUs>(rng_.Below(static_cast<uint64_t>(base / 4) + 1));
}

TimeUs Speaker::KeepaliveInterval(uint16_t hold_time) const {
  const TimeUs third = static_cast<TimeUs>(hold_time) * kUsPerSec / 3;
  const TimeUs configured = static_cast<TimeUs>(config_.keepalive) * kUsPerSec;
  return configured > 0 ? std::min(third, configured) : third;
}

int Speaker::FindPeer(uint32_t address) const {
  for (size_t i = 0; i < peers_.size(); ++i) {
    if (peers_[i].config.address == address) return static_cast<int>(i);
  }
  return -1;
}

uint32_t Speaker::PeerRouterId(int peer) const {
  if (peer < 0) return config_.router_id;
  const Peer& p = peers_[static_cast<size_t>(peer)];
  return p.established >= 0 ? p.conns[static_cast<size_t>(p.established)]->remote_id : 0;
}

void Speaker::Send(Peer& peer, int slot, const std::vector<uint8_t>& message) {
  if (!peer.conns[static_cast<size_t>(slot)]) return;
  transport_->Send(peer.conns[static_cast<size_t>(slot)]->id, message);
  ++peer.messages_out;
}

void Speaker::SendOpen(Peer& peer, int slot) {
  OpenMessage open;
  open.my_as = config_.local_as;
  open.hold_time = config_.hold_time;
  open.bgp_id = config_.router_id;
  open.cap_as4 = true;
  open.cap_mp_ipv4_unicast = true;
  Send(peer, slot, EncodeOpen(open));
}

void Speaker::SendNotification(Peer& peer, int slot, const Error& error) {
  Send(peer, slot, EncodeNotification(error.code, error.subcode, error.data));
}

void Speaker::FsmError(size_t peer_index, int slot) {
  SendNotification(peers_[peer_index], slot, Error{err::kFsm, 0, {}});
  CloseConnection(peer_index, slot, "FSM error: unexpected message");
}

void Speaker::RefreshHold(Connection& conn) {
  conn.hold_deadline =
      conn.hold_time != 0 ? clock_->Now() + static_cast<TimeUs>(conn.hold_time) * kUsPerSec : 0;
}

void Speaker::CloseConnection(size_t peer_index, int slot, const std::string& reason) {
  Peer& p = peers_[peer_index];
  std::optional<Connection>& c = p.conns[static_cast<size_t>(slot)];
  if (!c) return;
  transport_->Close(c->id);
  conn_index_.erase(c->id);
  c.reset();
  if (p.established == slot) {
    PeerDown(peer_index, reason);
  } else if (reason != "connection collision") {
    p.last_error = reason;
  }
}

void Speaker::PeerDown(size_t peer_index, const std::string& reason) {
  Peer& p = peers_[peer_index];
  p.established = -1;
  p.last_error = reason;
  LOG_INFO("bgp neighbor %s down: %s", Addr(p.config.address).c_str(), reason.c_str());
  p.adj_rib_out.clear();
  std::vector<Ipv4Prefix> lost;
  for (const auto& [prefix, attrs] : p.adj_rib_in) lost.push_back(prefix);
  p.adj_rib_in.clear();
  for (const Ipv4Prefix& prefix : lost) Recompute(prefix);
  p.next_connect = clock_->Now() + kRestartDelay;
}

void Speaker::Tick() {
  const TimeUs now = clock_->Now();
  for (size_t i = 0; i < peers_.size(); ++i) {
    Peer& p = peers_[i];
    for (int slot = 0; slot < 2; ++slot) {
      if (!p.conns[static_cast<size_t>(slot)]) continue;
      Connection& c = *p.conns[static_cast<size_t>(slot)];
      if (c.state == ConnState::kConnecting) {
        if (now - c.started > static_cast<TimeUs>(config_.connect_retry) * kUsPerSec) {
          CloseConnection(i, slot, "connect timed out");
        }
        continue;
      }
      if (c.hold_deadline != 0 && now >= c.hold_deadline) {
        SendNotification(p, slot, Error{err::kHoldTimerExpired, 0, {}});
        CloseConnection(i, slot, "hold timer expired");
        continue;
      }
      if ((c.state == ConnState::kOpenConfirm || c.state == ConnState::kEstablished) &&
          c.keepalive_due != 0 && now >= c.keepalive_due) {
        Send(p, slot, EncodeKeepalive());
        c.keepalive_due = now + KeepaliveInterval(c.hold_time);
      }
    }
    if (p.config.shutdown || p.config.passive || p.established >= 0 || p.conns[kOutgoing] ||
        now < p.next_connect) {
      continue;
    }
    Connection c;
    c.state = ConnState::kConnecting;
    c.started = now;
    c.id = transport_->Connect(ConnectOptions{p.config.local_address, p.config.address,
                                              p.config.password, p.config.ttl_security_hops});
    conn_index_[c.id] = {i, kOutgoing};
    p.conns[kOutgoing] = std::move(c);
    p.next_connect = now + Jitter(static_cast<TimeUs>(config_.connect_retry) * kUsPerSec);
  }
  FlushAdvertisements();
}

void Speaker::ResetNeighbor(uint32_t address, const std::string& reason) {
  const int i = FindPeer(address);
  if (i < 0) return;
  for (int slot = 0; slot < 2; ++slot) CloseConnection(static_cast<size_t>(i), slot, reason);
  peers_[static_cast<size_t>(i)].next_connect = clock_->Now() + kRestartDelay;
  FlushAdvertisements();
}

void Speaker::OnConnected(ConnId conn) {
  const auto it = conn_index_.find(conn);
  if (it == conn_index_.end()) return;
  const auto [i, slot] = it->second;
  Peer& p = peers_[i];
  Connection& c = *p.conns[static_cast<size_t>(slot)];
  if (c.state != ConnState::kConnecting) return;
  c.state = ConnState::kOpenSent;
  c.hold_deadline = clock_->Now() + kOpenHoldTime;
  SendOpen(p, slot);
}

void Speaker::OnAccepted(ConnId conn, uint32_t local_ip, uint32_t remote_ip) {
  const int pi = FindPeer(remote_ip);
  if (pi < 0) {
    LOG_WARN("bgp: rejected connection from unconfigured peer %s", Addr(remote_ip).c_str());
    transport_->Close(conn);
    return;
  }
  Peer& p = peers_[static_cast<size_t>(pi)];
  // Collision with an established session: keep the established one.
  if (p.config.shutdown || p.established >= 0) {
    transport_->Close(conn);
    return;
  }
  if (p.conns[kIncoming]) CloseConnection(static_cast<size_t>(pi), kIncoming, "replaced");
  Connection c;
  c.id = conn;
  c.state = ConnState::kOpenSent;
  c.started = clock_->Now();
  c.hold_deadline = c.started + kOpenHoldTime;
  conn_index_[conn] = {static_cast<size_t>(pi), kIncoming};
  p.conns[kIncoming] = std::move(c);
  (void)local_ip;
  SendOpen(p, kIncoming);
}

void Speaker::OnClosed(ConnId conn) {
  const auto it = conn_index_.find(conn);
  if (it == conn_index_.end()) return;
  const auto [i, slot] = it->second;
  conn_index_.erase(it);
  Peer& p = peers_[i];
  const bool was_established = p.established == slot;
  const bool was_connecting = p.conns[static_cast<size_t>(slot)] &&
                              p.conns[static_cast<size_t>(slot)]->state == ConnState::kConnecting;
  p.conns[static_cast<size_t>(slot)].reset();
  if (was_established) {
    PeerDown(i, "connection closed by peer");
  } else {
    p.last_error = was_connecting ? "connection refused" : "connection closed during setup";
  }
  FlushAdvertisements();
}

void Speaker::OnData(ConnId conn, std::span<const uint8_t> data) {
  const auto it = conn_index_.find(conn);
  if (it == conn_index_.end()) return;
  const auto [i, slot] = it->second;
  Peer& p = peers_[i];
  std::optional<Connection>& c = p.conns[static_cast<size_t>(slot)];
  c->reader.Append(data);
  MessageType type{};
  std::vector<uint8_t> body;
  Error error;
  // The connection can close while a message is handled; re-check every time.
  while (c) {
    if (!c->reader.Next(&type, &body, &error)) {
      if (!error.ok()) {
        SendNotification(p, slot, error);
        CloseConnection(i, slot, "malformed message: " + ErrorString(error.code, error.subcode));
      }
      break;
    }
    ++p.messages_in;
    HandleMessage(i, slot, type, body);
  }
  FlushAdvertisements();
}

void Speaker::HandleMessage(size_t peer_index, int slot, MessageType type,
                            std::span<const uint8_t> body) {
  Peer& p = peers_[peer_index];
  Connection& c = *p.conns[static_cast<size_t>(slot)];
  switch (type) {
    case MessageType::kOpen:
      if (c.state != ConnState::kOpenSent) return FsmError(peer_index, slot);
      return HandleOpen(peer_index, slot, body);
    case MessageType::kKeepalive:
      if (c.state == ConnState::kOpenConfirm) return Established(peer_index, slot);
      if (c.state == ConnState::kEstablished) return RefreshHold(c);
      return FsmError(peer_index, slot);
    case MessageType::kUpdate:
      if (c.state != ConnState::kEstablished) return FsmError(peer_index, slot);
      RefreshHold(c);
      return HandleUpdate(peer_index, body);
    case MessageType::kNotification: {
      NotificationMessage n;
      DecodeNotification(body, &n);
      CloseConnection(peer_index, slot, "received " + ErrorString(n.code, n.subcode));
      return;
    }
  }
}

void Speaker::HandleOpen(size_t peer_index, int slot, std::span<const uint8_t> body) {
  Peer& p = peers_[peer_index];
  OpenMessage open;
  Error e = DecodeOpen(body, &open);
  if (e.ok() && open.my_as != p.config.remote_as) e = Error{err::kOpen, err::kBadPeerAs, {}};
  if (e.ok() && open.bgp_id == config_.router_id) e = Error{err::kOpen, err::kBadBgpId, {}};
  if (!e.ok()) {
    SendNotification(p, slot, e);
    CloseConnection(peer_index, slot, "rejected OPEN: " + ErrorString(e.code, e.subcode));
    return;
  }
  Connection& c = *p.conns[static_cast<size_t>(slot)];
  c.remote_id = open.bgp_id;
  c.hold_time = std::min(config_.hold_time, open.hold_time);
  c.as4 = open.cap_as4;  // we always offer 4-octet AS numbers
  c.state = ConnState::kOpenConfirm;
  Send(p, slot, EncodeKeepalive());
  RefreshHold(c);
  c.keepalive_due = c.hold_time != 0 ? clock_->Now() + KeepaliveInterval(c.hold_time) : 0;

  // Connection collision (RFC 4271 section 6.8): keep the connection opened by
  // the speaker with the higher BGP identifier.
  const int other = 1 - slot;
  if (p.conns[static_cast<size_t>(other)]) {
    const int keep = config_.router_id < open.bgp_id ? kIncoming : kOutgoing;
    const int drop = 1 - keep;
    if (p.conns[static_cast<size_t>(drop)]->state != ConnState::kConnecting) {
      SendNotification(p, drop, Error{err::kCease, err::kCollisionResolution, {}});
    }
    CloseConnection(peer_index, drop, "connection collision");
  }
}

void Speaker::Established(size_t peer_index, int slot) {
  Peer& p = peers_[peer_index];
  Connection& c = *p.conns[static_cast<size_t>(slot)];
  c.state = ConnState::kEstablished;
  RefreshHold(c);
  p.established = slot;
  p.established_since = clock_->Now();
  ++p.established_count;
  p.last_error.clear();
  const int other = 1 - slot;
  if (p.conns[static_cast<size_t>(other)]) {
    if (p.conns[static_cast<size_t>(other)]->state != ConnState::kConnecting) {
      SendNotification(p, other, Error{err::kCease, err::kCollisionResolution, {}});
    }
    CloseConnection(peer_index, other, "connection collision");
  }
  LOG_INFO("bgp neighbor %s (AS %u) established", Addr(p.config.address).c_str(),
           p.config.remote_as);
  std::set<Ipv4Prefix> all;
  for (const auto& [prefix, entry] : loc_rib_) all.insert(prefix);
  SyncAdjRibOut(peer_index, all);
}

void Speaker::HandleUpdate(size_t peer_index, std::span<const uint8_t> body) {
  Peer& p = peers_[peer_index];
  const int slot = p.established;
  UpdateMessage u;
  const Error e = DecodeUpdate(body, p.conns[static_cast<size_t>(slot)]->as4, &u);
  if (!e.ok()) {
    SendNotification(p, slot, e);
    CloseConnection(peer_index, slot, "malformed UPDATE: " + ErrorString(e.code, e.subcode));
    return;
  }
  for (const Ipv4Prefix& w : u.withdrawn) {
    if (p.adj_rib_in.erase(w) > 0) Recompute(w);
  }
  if (u.nlri.empty()) return;  // End-of-RIB markers and pure withdrawals
  u.attrs.local_pref.reset();  // LOCAL_PREF from an external peer is ignored
  // Paths we must not use are treated as withdrawals: our own AS in the path
  // (a loop) or a first AS that is not the neighbor's (enforce-first-as).
  const bool unusable =
      u.attrs.ContainsAs(config_.local_as) || u.attrs.FirstAs() != p.config.remote_as;
  for (const Ipv4Prefix& n : u.nlri) {
    if (unusable) {
      if (p.adj_rib_in.erase(n) > 0) Recompute(n);
      continue;
    }
    p.adj_rib_in[n] = u.attrs;
    Recompute(n);
  }
}

bool Speaker::Better(const Candidate& a, const Candidate& b) const {
  if ((a.peer < 0) != (b.peer < 0)) return a.peer < 0;  // locally originated wins
  const PathAttributes& x = *a.attrs;
  const PathAttributes& y = *b.attrs;
  if (x.AsPathLength() != y.AsPathLength()) return x.AsPathLength() < y.AsPathLength();
  if (x.origin != y.origin) return x.origin < y.origin;
  if (x.FirstAs() == y.FirstAs() && x.med.value_or(0) != y.med.value_or(0)) {
    return x.med.value_or(0) < y.med.value_or(0);
  }
  const uint32_t ida = PeerRouterId(a.peer);
  const uint32_t idb = PeerRouterId(b.peer);
  if (ida != idb) return ida < idb;
  const uint32_t pa = a.peer < 0 ? 0 : peers_[static_cast<size_t>(a.peer)].config.address;
  const uint32_t pb = b.peer < 0 ? 0 : peers_[static_cast<size_t>(b.peer)].config.address;
  return pa < pb;
}

// Paths equal up to the tie-breakers share traffic (as-path multipath-relax:
// the neighbor AS may differ, as in RFC 7938 fabrics).
bool Speaker::MultipathEqual(const Candidate& a, const Candidate& b) const {
  if (a.peer < 0 || b.peer < 0) return false;
  const PathAttributes& x = *a.attrs;
  const PathAttributes& y = *b.attrs;
  if (x.AsPathLength() != y.AsPathLength() || x.origin != y.origin) return false;
  return x.FirstAs() != y.FirstAs() || x.med.value_or(0) == y.med.value_or(0);
}

void Speaker::Recompute(const Ipv4Prefix& prefix) {
  std::vector<Candidate> candidates;
  if (networks_.count(prefix) > 0) candidates.push_back(Candidate{-1, &local_attrs_});
  for (size_t i = 0; i < peers_.size(); ++i) {
    if (peers_[i].established < 0) continue;
    const auto it = peers_[i].adj_rib_in.find(prefix);
    if (it != peers_[i].adj_rib_in.end()) {
      candidates.push_back(Candidate{static_cast<int>(i), &it->second});
    }
  }
  const auto current = loc_rib_.find(prefix);
  const bool had = current != loc_rib_.end();
  if (candidates.empty()) {
    if (had) {
      const bool was_local = current->second.local;
      loc_rib_.erase(current);
      if (!was_local) sink_->OnBgpRoute(prefix, {});
      dirty_.insert(prefix);
    }
    return;
  }

  // Linear scan rather than sort: MED comparison is not transitive across
  // neighbor ASes, so it is not a strict weak ordering.
  const Candidate* best = &candidates[0];
  for (const Candidate& c : candidates) {
    if (Better(c, *best)) best = &c;
  }
  LocRibEntry next;
  next.local = best->peer < 0;
  next.best_peer = best->peer;
  next.attrs = *best->attrs;
  next.paths = candidates.size();
  if (!next.local) {
    next.next_hops.push_back(best->attrs->next_hop);
    for (const Candidate& c : candidates) {
      if (next.next_hops.size() >= config_.max_paths) break;
      if (&c != best && MultipathEqual(*best, c)) next.next_hops.push_back(c.attrs->next_hop);
    }
    std::sort(next.next_hops.begin(), next.next_hops.end());
    next.next_hops.erase(std::unique(next.next_hops.begin(), next.next_hops.end()),
                         next.next_hops.end());
  }
  if (had && current->second.local == next.local && current->second.best_peer == next.best_peer &&
      current->second.attrs == next.attrs && current->second.next_hops == next.next_hops) {
    current->second.paths = next.paths;
    return;
  }
  if (!next.local) {
    sink_->OnBgpRoute(prefix, next.next_hops);
  } else if (had && !current->second.local) {
    sink_->OnBgpRoute(prefix, {});
  }
  loc_rib_[prefix] = std::move(next);
  dirty_.insert(prefix);
}

std::optional<PathAttributes> Speaker::OutboundAttributes(const Peer& peer,
                                                          const Ipv4Prefix& prefix) const {
  const auto it = loc_rib_.find(prefix);
  if (it == loc_rib_.end()) return std::nullopt;
  const LocRibEntry& e = it->second;
  if (!e.local) {
    if (e.best_peer >= 0 && &peers_[static_cast<size_t>(e.best_peer)] == &peer) return std::nullopt;
    if (e.attrs.ContainsAs(peer.config.remote_as)) return std::nullopt;  // sender-side loop check
  }
  PathAttributes out;
  out.origin = e.attrs.origin;
  out.as_path = e.attrs.as_path;
  if (!out.as_path.empty() && out.as_path[0].type == 2 && out.as_path[0].asns.size() < 255) {
    out.as_path[0].asns.insert(out.as_path[0].asns.begin(), config_.local_as);
  } else {
    out.as_path.insert(out.as_path.begin(), AsPathSegment{2, {config_.local_as}});
  }
  out.next_hop = peer.config.local_address;  // next-hop-self toward external peers
  out.atomic_aggregate = e.attrs.atomic_aggregate;
  out.communities = e.attrs.communities;
  // MED and LOCAL_PREF are not propagated to external peers.
  return out;
}

void Speaker::SyncAdjRibOut(size_t peer_index, const std::set<Ipv4Prefix>& prefixes) {
  Peer& p = peers_[peer_index];
  if (p.established < 0) return;
  const bool as4 = p.conns[static_cast<size_t>(p.established)]->as4;
  std::vector<Ipv4Prefix> withdraw;
  std::vector<std::pair<PathAttributes, std::vector<Ipv4Prefix>>> announce;
  for (const Ipv4Prefix& prefix : prefixes) {
    std::optional<PathAttributes> desired = OutboundAttributes(p, prefix);
    const auto current = p.adj_rib_out.find(prefix);
    if (!desired) {
      if (current != p.adj_rib_out.end()) {
        withdraw.push_back(prefix);
        p.adj_rib_out.erase(current);
      }
      continue;
    }
    if (current != p.adj_rib_out.end() && current->second == *desired) continue;
    p.adj_rib_out[prefix] = *desired;
    // Pack prefixes that share attributes into the same UPDATE.
    auto group = std::find_if(announce.begin(), announce.end(),
                              [&](const auto& g) { return g.first == *desired; });
    if (group == announce.end()) {
      announce.emplace_back(std::move(*desired), std::vector<Ipv4Prefix>{});
      group = announce.end() - 1;
    }
    group->second.push_back(prefix);
  }
  for (const auto& m : EncodeWithdrawals(withdraw)) Send(p, p.established, m);
  for (const auto& [attrs, list] : announce) {
    for (const auto& m : EncodeAnnouncements(attrs, list, as4)) Send(p, p.established, m);
  }
}

void Speaker::FlushAdvertisements() {
  if (dirty_.empty()) return;
  std::set<Ipv4Prefix> dirty;
  dirty.swap(dirty_);
  for (size_t i = 0; i < peers_.size(); ++i) SyncAdjRibOut(i, dirty);
}

std::vector<NeighborStatus> Speaker::Neighbors() const {
  std::vector<NeighborStatus> out;
  for (const Peer& p : peers_) {
    NeighborStatus s;
    s.address = p.config.address;
    s.remote_as = p.config.remote_as;
    s.description = p.config.description;
    s.prefixes_received = p.adj_rib_in.size();
    s.prefixes_sent = p.adj_rib_out.size();
    s.messages_in = p.messages_in;
    s.messages_out = p.messages_out;
    s.established_count = p.established_count;
    s.last_error = p.last_error;
    if (p.established >= 0) {
      const Connection& c = *p.conns[static_cast<size_t>(p.established)];
      s.state = SessionState::kEstablished;
      s.established_since = p.established_since;
      s.remote_id = c.remote_id;
      s.hold_time = c.hold_time;
    } else {
      s.state = p.config.passive ? SessionState::kActive : SessionState::kIdle;
      for (const auto& c : p.conns) {
        if (!c) continue;
        SessionState st = SessionState::kConnect;
        if (c->state == ConnState::kOpenSent) st = SessionState::kOpenSent;
        if (c->state == ConnState::kOpenConfirm) st = SessionState::kOpenConfirm;
        s.state = std::max(s.state, st);
      }
    }
    out.push_back(std::move(s));
  }
  return out;
}

std::vector<RouteView> Speaker::Routes() const {
  std::vector<RouteView> out;
  for (const auto& [prefix, e] : loc_rib_) {
    RouteView v;
    v.prefix = prefix;
    v.local = e.local;
    v.next_hops = e.next_hops;
    v.as_path = e.attrs.Flatten();
    v.origin = e.attrs.origin;
    v.paths = e.paths;
    out.push_back(std::move(v));
  }
  return out;
}

}  // namespace nanonos::bgp
