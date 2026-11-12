// LLDP (IEEE 802.1AB): TLV encoding/decoding and a per-port agent. Data
// center operators use LLDP neighbor tables to validate cabling against the
// intended topology.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <span>
#include <string>
#include <vector>

#include "common/clock.h"
#include "common/types.h"

namespace nanonos::lldp {

inline constexpr uint16_t kCapBridge = 0x0004;
inline constexpr uint16_t kCapRouter = 0x0010;

struct Info {
  std::string chassis_id;  // MAC address (subtype 4) rendered as text
  std::string port_id;     // interface name (subtype 5)
  std::string port_description;
  std::string system_name;
  std::string system_description;
  uint16_t ttl = 120;
  uint16_t capabilities = kCapBridge | kCapRouter;
  uint16_t enabled_capabilities = kCapBridge | kCapRouter;
  uint32_t mgmt_ip = 0;
};

// Builds a complete untagged LLDPDU frame to 01:80:c2:00:00:0e. Returns the
// frame length, or 0 if `out` is too small.
size_t BuildFrame(std::span<uint8_t> out, const MacAddress& src, const MacAddress& chassis_mac,
                  const Info& info);
// Parses an Ethernet frame carrying an LLDPDU. Rejects frames whose mandatory
// TLVs (chassis id, port id, TTL) are missing or out of order.
bool ParseFrame(std::span<const uint8_t> frame, Info* out);

struct Neighbor {
  uint16_t local_port = 0;
  MacAddress src_mac;
  Info info;
  TimeUs expires = 0;
};

class Agent {
 public:
  explicit Agent(const Clock* clock) : clock_(clock) {}

  void Configure(std::string system_name, std::string system_description,
                 const MacAddress& chassis_mac, uint16_t tx_interval_s, uint16_t hold_multiplier);
  void AddPort(uint16_t port, std::string name, std::string description, uint32_t mgmt_ip);
  void SetPortUp(uint16_t port, bool up);

  void OnFrame(uint16_t port, std::span<const uint8_t> frame);
  // Sends LLDPDUs that are due and expires stale neighbors.
  void Tick(const std::function<void(uint16_t port, std::span<const uint8_t> frame)>& send);

  const std::map<uint16_t, Neighbor>& neighbors() const { return neighbors_; }
  uint64_t rx_frames() const { return rx_frames_; }
  uint64_t rx_errors() const { return rx_errors_; }

 private:
  struct Port {
    std::string name;
    std::string description;
    uint32_t mgmt_ip = 0;
    bool up = true;
    TimeUs next_tx = 0;
  };

  const Clock* clock_;
  std::string system_name_;
  std::string system_description_;
  MacAddress chassis_mac_;
  uint16_t tx_interval_s_ = 30;
  uint16_t hold_multiplier_ = 4;
  std::map<uint16_t, Port> ports_;
  std::map<uint16_t, Neighbor> neighbors_;
  uint64_t rx_frames_ = 0;
  uint64_t rx_errors_ = 0;
};

}  // namespace nanonos::lldp
