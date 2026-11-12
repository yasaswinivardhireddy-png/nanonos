// Shared helpers for the unit tests.
#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "common/clock.h"
#include "common/logging.h"
#include "packet/builder.h"
#include "packet/packet.h"
#include "sw/switch_node.h"

namespace nanonos::testing {

inline MacAddress Mac(uint64_t value) { return MacAddress::FromU64(value); }

inline uint32_t Ip(const char* text) {
  const auto ip = ParseIpv4(text);
  EXPECT_TRUE(ip.has_value()) << text;
  return ip.value_or(0);
}

inline Ipv4Prefix Pfx(const char* text) {
  const auto p = Ipv4Prefix::Parse(text);
  EXPECT_TRUE(p.has_value()) << text;
  return p.value_or(Ipv4Prefix{});
}

struct Flow {
  MacAddress dst;
  MacAddress src;
  uint32_t src_ip = 0;
  uint32_t dst_ip = 0;
  uint16_t src_port = 1000;
  uint16_t dst_port = 2000;
  uint8_t proto = kIpProtoUdp;
  int vlan = -1;
  uint8_t dscp = 0;
  uint8_t ecn = 0;
  uint8_t ttl = 64;
  uint16_t payload = 18;
};

inline std::vector<uint8_t> FlowFrame(const Flow& f) {
  std::vector<uint8_t> buf(kMaxFrameSize);
  FlowFrameSpec s;
  s.dst_mac = f.dst;
  s.src_mac = f.src;
  s.vlan = f.vlan;
  s.src_ip = f.src_ip;
  s.dst_ip = f.dst_ip;
  s.proto = f.proto;
  s.src_port = f.src_port;
  s.dst_port = f.dst_port;
  s.ttl = f.ttl;
  s.dscp = f.dscp;
  s.ecn = f.ecn;
  s.payload_len = f.payload;
  buf.resize(BuildFlowFrame(buf, s));
  return buf;
}

inline std::vector<uint8_t> ArpFrame(const MacAddress& eth_dst, uint16_t op, const MacAddress& sha,
                                     uint32_t spa, const MacAddress& tha, uint32_t tpa,
                                     int vlan = -1) {
  std::vector<uint8_t> buf(kMinFrameSize + kVlanTagLen);
  buf.resize(BuildArpFrame(buf, eth_dst, op, sha, spa, tha, tpa, vlan));
  return buf;
}

inline ParsedPacket Parse(const std::vector<uint8_t>& frame) {
  ParsedPacket p;
  EXPECT_EQ(ParseFrame(frame, &p), ParseStatus::kOk);
  return p;
}

// One switch with a manual clock; every transmitted frame is recorded.
class TestSwitch {
 public:
  explicit TestSwitch(const std::string& config_text, uint16_t ports = 8,
                      bgp::Transport* transport = nullptr, VirtualAsic::Options options = {}) {
    SwitchNode::Platform p;
    p.clock = &clock;
    p.bgp_transport = transport;
    p.transmit = [this](uint16_t port, std::span<const uint8_t> frame) {
      sent.emplace_back(port, std::vector<uint8_t>(frame.begin(), frame.end()));
    };
    options.num_ports = ports;
    p.asic = options;
    p.sai_record = [this](const std::string& line) { sai_log.push_back(line); };
    node = std::make_unique<SwitchNode>(std::move(p));
    ConfigError error;
    const auto config = ParseConfig(config_text, &error);
    EXPECT_TRUE(config.has_value()) << "line " << error.line << ": " << error.message;
    if (config) {
      std::vector<std::string> errors;
      EXPECT_TRUE(node->Configure(*config, &errors)) << (errors.empty() ? "" : errors[0]);
    }
  }

  void Rx(uint16_t port, const std::vector<uint8_t>& frame) {
    node->ReceiveFrame(port, frame);
    node->Drain();
  }

  void Advance(TimeUs us, TimeUs step = 10 * kUsPerMs) {
    for (TimeUs t = 0; t < us; t += step) {
      clock.Advance(step);
      node->Tick();
    }
  }

  // Frames sent on `port` since the last call (all ports when port < 0).
  std::vector<std::vector<uint8_t>> Take(int port) {
    std::vector<std::vector<uint8_t>> out;
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> keep;
    for (auto& [p, f] : sent) {
      if (port < 0 || p == port) {
        out.push_back(std::move(f));
      } else {
        keep.emplace_back(p, std::move(f));
      }
    }
    sent = std::move(keep);
    return out;
  }

  uint64_t Drops(sai::DropReason reason) { return node->asic().GetDropCount(reason); }

  ManualClock clock;
  std::unique_ptr<SwitchNode> node;
  std::vector<std::pair<uint16_t, std::vector<uint8_t>>> sent;
  std::vector<std::string> sai_log;
};

}  // namespace nanonos::testing
