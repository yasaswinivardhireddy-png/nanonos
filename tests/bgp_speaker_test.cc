#include <map>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "proto/bgp_speaker.h"
#include "proto/memory_transport.h"
#include "test_util.h"

namespace nanonos::bgp {
namespace {

using testing::Ip;
using testing::Pfx;

struct FibRecorder : RouteSink {
  void OnBgpRoute(const Ipv4Prefix& prefix, const std::vector<uint32_t>& next_hops) override {
    if (next_hops.empty()) {
      routes.erase(prefix);
    } else {
      routes[prefix] = next_hops;
    }
  }
  std::map<Ipv4Prefix, std::vector<uint32_t>> routes;
};

class BgpHarness {
 public:
  struct Node {
    MemoryNetwork::Endpoint* endpoint = nullptr;
    FibRecorder fib;
    std::unique_ptr<Speaker> speaker;
    bool ticking = true;
    SessionState State(uint32_t neighbor) const {
      for (const NeighborStatus& s : speaker->Neighbors()) {
        if (s.address == neighbor) return s.state;
      }
      return SessionState::kIdle;
    }
    NeighborStatus Status(uint32_t neighbor) const {
      for (const NeighborStatus& s : speaker->Neighbors()) {
        if (s.address == neighbor) return s;
      }
      return NeighborStatus{};
    }
  };

  Node& Add(const SpeakerConfig& config, std::vector<uint32_t> addresses) {
    nodes.push_back(std::make_unique<Node>());
    Node& n = *nodes.back();
    n.endpoint = net.AddEndpoint(std::move(addresses));
    n.speaker = std::make_unique<Speaker>(config, n.endpoint, &n.fib, &clock);
    n.endpoint->SetHandler(n.speaker.get());
    return n;
  }

  void Run(TimeUs duration, TimeUs step = 10 * kUsPerMs) {
    for (TimeUs t = 0; t < duration; t += step) {
      clock.Advance(step);
      for (auto& n : nodes) {
        if (n->ticking) n->speaker->Tick();
      }
      net.Pump();
    }
  }

  ManualClock clock;
  MemoryNetwork net;
  std::vector<std::unique_ptr<Node>> nodes;
};

SpeakerConfig Config(uint32_t asn, const char* router_id, std::vector<Ipv4Prefix> networks = {}) {
  SpeakerConfig c;
  c.local_as = asn;
  c.router_id = Ip(router_id);
  c.hold_time = 3;
  c.keepalive = 1;
  c.connect_retry = 2;
  c.max_paths = 4;
  c.networks = std::move(networks);
  return c;
}

NeighborConfig Neighbor(const char* address, const char* local, uint32_t asn) {
  NeighborConfig n;
  n.address = Ip(address);
  n.local_address = Ip(local);
  n.remote_as = asn;
  return n;
}

TEST(BgpSpeakerTest, RejectsUnexpectedPeerAs) {
  BgpHarness h;
  SpeakerConfig a = Config(65001, "1.1.1.1");
  a.neighbors = {Neighbor("10.0.0.1", "10.0.0.0", 65002)};  // but B is AS 4200000002
  SpeakerConfig b = Config(4200000002, "2.2.2.2");
  b.neighbors = {Neighbor("10.0.0.0", "10.0.0.1", 65001)};
  auto& na = h.Add(a, {Ip("10.0.0.0")});
  auto& nb = h.Add(b, {Ip("10.0.0.1")});
  h.Run(1 * kUsPerSec);
  EXPECT_NE(na.State(Ip("10.0.0.1")), SessionState::kEstablished);
  EXPECT_NE(nb.State(Ip("10.0.0.0")), SessionState::kEstablished);
  EXPECT_NE(na.Status(Ip("10.0.0.1")).last_error.find("OPEN message error (2/2)"),
            std::string::npos)
      << na.Status(Ip("10.0.0.1")).last_error;
}

TEST(BgpSpeakerTest, EstablishesAndExchangesRoutes) {
  BgpHarness h;
  SpeakerConfig a = Config(65001, "1.1.1.1", {Pfx("10.1.0.0/16")});
  a.neighbors = {Neighbor("10.0.0.1", "10.0.0.0", 4200000002)};
  SpeakerConfig b = Config(4200000002, "2.2.2.2", {Pfx("10.2.0.0/16")});
  b.neighbors = {Neighbor("10.0.0.0", "10.0.0.1", 65001)};
  auto& na = h.Add(a, {Ip("10.0.0.0")});
  auto& nb = h.Add(b, {Ip("10.0.0.1")});
  h.Run(1 * kUsPerSec);
  ASSERT_EQ(na.State(Ip("10.0.0.1")), SessionState::kEstablished);
  ASSERT_EQ(nb.State(Ip("10.0.0.0")), SessionState::kEstablished);
  EXPECT_EQ(na.fib.routes[Pfx("10.2.0.0/16")], (std::vector<uint32_t>{Ip("10.0.0.1")}));
  EXPECT_EQ(nb.fib.routes[Pfx("10.1.0.0/16")], (std::vector<uint32_t>{Ip("10.0.0.0")}));
  bool found = false;
  for (const RouteView& r : na.speaker->Routes()) {
    if (r.prefix == Pfx("10.2.0.0/16")) {
      found = true;
      EXPECT_EQ(r.as_path, (std::vector<uint32_t>{4200000002u}));  // 4-octet AS end to end
    }
  }
  EXPECT_TRUE(found);
  // Keepalives hold the session up well past the 3 s hold time.
  h.Run(10 * kUsPerSec);
  EXPECT_EQ(na.Status(Ip("10.0.0.1")).established_count, 1u);
  EXPECT_EQ(nb.Status(Ip("10.0.0.0")).established_count, 1u);
}

TEST(BgpSpeakerTest, ByteByByteDeliveryAndConnectionCollision) {
  BgpHarness h;
  h.net.SetChunkSize(1);
  SpeakerConfig a = Config(65001, "1.1.1.1", {Pfx("10.1.0.0/16")});
  a.neighbors = {Neighbor("10.0.0.1", "10.0.0.0", 65002)};
  SpeakerConfig b = Config(65002, "2.2.2.2", {Pfx("10.2.0.0/16")});
  b.neighbors = {Neighbor("10.0.0.0", "10.0.0.1", 65001)};
  auto& na = h.Add(a, {Ip("10.0.0.0")});
  auto& nb = h.Add(b, {Ip("10.0.0.1")});
  // A 500 ms step makes both speakers connect in the same tick: a collision.
  h.Run(3 * kUsPerSec, 500 * kUsPerMs);
  h.Run(5 * kUsPerSec);
  EXPECT_EQ(na.State(Ip("10.0.0.1")), SessionState::kEstablished);
  EXPECT_EQ(nb.State(Ip("10.0.0.0")), SessionState::kEstablished);
  EXPECT_EQ(na.Status(Ip("10.0.0.1")).established_count, 1u);
  EXPECT_EQ(nb.Status(Ip("10.0.0.0")).established_count, 1u);
  EXPECT_EQ(na.fib.routes.count(Pfx("10.2.0.0/16")), 1u);
}

TEST(BgpSpeakerTest, HoldTimerExpiresWhenThePeerGoesSilent) {
  BgpHarness h;
  SpeakerConfig a = Config(65001, "1.1.1.1");
  a.neighbors = {Neighbor("10.0.0.1", "10.0.0.0", 65002)};
  SpeakerConfig b = Config(65002, "2.2.2.2", {Pfx("10.2.0.0/16")});
  b.neighbors = {Neighbor("10.0.0.0", "10.0.0.1", 65001)};
  auto& na = h.Add(a, {Ip("10.0.0.0")});
  auto& nb = h.Add(b, {Ip("10.0.0.1")});
  h.Run(1 * kUsPerSec);
  ASSERT_EQ(na.State(Ip("10.0.0.1")), SessionState::kEstablished);
  ASSERT_EQ(na.fib.routes.count(Pfx("10.2.0.0/16")), 1u);
  nb.ticking = false;  // B stops sending keepalives (but still answers new connections)
  const TimeUs stopped = h.clock.Now();
  TimeUs expired_after = 0;
  while (h.clock.Now() - stopped < 5 * kUsPerSec) {
    h.Run(10 * kUsPerMs);
    if (na.State(Ip("10.0.0.1")) != SessionState::kEstablished) {
      expired_after = h.clock.Now() - stopped;
      break;
    }
  }
  // B's last keepalive was at most 1 s before it went silent; hold time is 3 s.
  EXPECT_GE(expired_after, 2 * kUsPerSec - 20 * kUsPerMs);
  EXPECT_LE(expired_after, 3 * kUsPerSec + 20 * kUsPerMs);
  EXPECT_EQ(na.Status(Ip("10.0.0.1")).last_error, "hold timer expired");
  EXPECT_EQ(na.fib.routes.count(Pfx("10.2.0.0/16")), 0u);  // routes withdrawn with the session
}

// leaf1 (AS 65001) -- spine1, spine2 (AS 65100) -- leaf2 (AS 65002)
struct Clos {
  explicit Clos(uint16_t max_paths) {
    SpeakerConfig l1 = Config(65001, "1.1.1.1", {Pfx("10.1.0.0/16")});
    l1.max_paths = max_paths;
    l1.neighbors = {Neighbor("10.0.0.1", "10.0.0.0", 65100),
                    Neighbor("10.0.1.1", "10.0.1.0", 65100)};
    SpeakerConfig s1 = Config(65100, "3.3.3.1");
    s1.neighbors = {Neighbor("10.0.0.0", "10.0.0.1", 65001),
                    Neighbor("10.0.2.0", "10.0.2.1", 65002)};
    SpeakerConfig s2 = Config(65100, "3.3.3.2");
    s2.neighbors = {Neighbor("10.0.1.0", "10.0.1.1", 65001),
                    Neighbor("10.0.3.0", "10.0.3.1", 65002)};
    SpeakerConfig l2 = Config(65002, "2.2.2.2", {Pfx("10.2.0.0/16")});
    l2.neighbors = {Neighbor("10.0.2.1", "10.0.2.0", 65100),
                    Neighbor("10.0.3.1", "10.0.3.0", 65100)};
    leaf1 = &h.Add(l1, {Ip("10.0.0.0"), Ip("10.0.1.0")});
    spine1 = &h.Add(s1, {Ip("10.0.0.1"), Ip("10.0.2.1")});
    spine2 = &h.Add(s2, {Ip("10.0.1.1"), Ip("10.0.3.1")});
    leaf2 = &h.Add(l2, {Ip("10.0.2.0"), Ip("10.0.3.0")});
    h.Run(2 * kUsPerSec);
  }
  BgpHarness h;
  BgpHarness::Node* leaf1;
  BgpHarness::Node* spine1;
  BgpHarness::Node* spine2;
  BgpHarness::Node* leaf2;
};

TEST(BgpSpeakerTest, MultipathAcrossSpinesAndWithdrawalOnFailure) {
  Clos c(4);
  EXPECT_EQ(c.leaf1->fib.routes[Pfx("10.2.0.0/16")],
            (std::vector<uint32_t>{Ip("10.0.0.1"), Ip("10.0.1.1")}));
  EXPECT_EQ(c.leaf2->fib.routes[Pfx("10.1.0.0/16")],
            (std::vector<uint32_t>{Ip("10.0.2.1"), Ip("10.0.3.1")}));
  // Cut spine1 <-> leaf2: spine1 withdraws, leaf1 keeps only spine2.
  c.h.net.SetLinkUp(Ip("10.0.2.1"), Ip("10.0.2.0"), false);
  c.h.Run(200 * kUsPerMs);
  EXPECT_EQ(c.leaf1->fib.routes[Pfx("10.2.0.0/16")], (std::vector<uint32_t>{Ip("10.0.1.1")}));
  c.h.net.SetLinkUp(Ip("10.0.2.1"), Ip("10.0.2.0"), true);
  c.h.Run(5 * kUsPerSec);
  EXPECT_EQ(c.leaf1->fib.routes[Pfx("10.2.0.0/16")].size(), 2u);
}

TEST(BgpSpeakerTest, SinglePathWithoutMultipath) {
  Clos c(1);
  EXPECT_EQ(c.leaf1->fib.routes[Pfx("10.2.0.0/16")].size(), 1u);
}

TEST(BgpSpeakerTest, LoopPreventionKeepsPathsValleyFree) {
  Clos c(4);
  // spine2 must not learn leaf1's prefix back through leaf2 (its own AS is in
  // that path), so it has exactly one path: directly from leaf1.
  for (const RouteView& r : c.spine2->speaker->Routes()) {
    if (r.prefix == Pfx("10.1.0.0/16")) {
      EXPECT_EQ(r.paths, 1u);
      EXPECT_EQ(r.as_path, (std::vector<uint32_t>{65001}));
      EXPECT_EQ(r.next_hops, (std::vector<uint32_t>{Ip("10.0.1.0")}));
    }
  }
  // leaf1 learns leaf2's prefix with AS_PATH 65100 65002 and never its own back.
  for (const RouteView& r : c.leaf1->speaker->Routes()) {
    if (r.prefix == Pfx("10.2.0.0/16")) {
      EXPECT_EQ(r.as_path, (std::vector<uint32_t>{65100, 65002}));
    }
    EXPECT_FALSE(!r.local && r.prefix == Pfx("10.1.0.0/16"));
  }
}

TEST(BgpSpeakerTest, ShutdownNeighborNeverConnects) {
  BgpHarness h;
  SpeakerConfig a = Config(65001, "1.1.1.1");
  NeighborConfig n = Neighbor("10.0.0.1", "10.0.0.0", 65002);
  n.shutdown = true;
  a.neighbors = {n};
  SpeakerConfig b = Config(65002, "2.2.2.2");
  b.neighbors = {Neighbor("10.0.0.0", "10.0.0.1", 65001)};
  auto& na = h.Add(a, {Ip("10.0.0.0")});
  h.Add(b, {Ip("10.0.0.1")});
  h.Run(3 * kUsPerSec);
  EXPECT_EQ(na.State(Ip("10.0.0.1")), SessionState::kIdle);
}

}  // namespace
}  // namespace nanonos::bgp
