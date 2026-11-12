// A complete switch: software ASIC + SAI + orchagent + BGP + LLDP + CLI.
//
// SwitchNode is platform-neutral. The Linux daemon (tools/nanonosd.cc) feeds
// it frames from AF_PACKET sockets and delivers trapped packets to TAP host
// interfaces; the fabric simulation in the tests wires several nodes together
// in memory with a manual clock.
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "asic/vasic.h"
#include "orch/config.h"
#include "orch/orchagent.h"
#include "proto/bgp_speaker.h"
#include "proto/lldp.h"
#include "sai/recorder.h"

namespace nanonos {

inline constexpr const char* kNanonosVersion = "0.1.0";

class SwitchNode final : public bgp::RouteSink {
 public:
  struct Platform {
    const Clock* clock = nullptr;
    bgp::Transport* bgp_transport = nullptr;  // null disables BGP
    std::function<void(uint16_t port, std::span<const uint8_t> frame)> transmit;
    // Trapped packets for the host network stack (TAP host interfaces). When
    // unset, the node answers ARP and ping for its own addresses itself.
    std::function<void(int rif, std::span<const uint8_t> frame)> deliver_to_host;
    // Optional log of every SAI programming call (sairedis.rec style).
    std::function<void(const std::string& line)> sai_record;
    VirtualAsic::Options asic;
  };

  explicit SwitchNode(Platform platform);

  bool Configure(const SwitchConfig& config, std::vector<std::string>* errors);

  void ReceiveFrame(uint16_t port, std::span<const uint8_t> frame);
  void ReceiveFromHost(int rif, std::span<const uint8_t> frame);
  void SetPortOperStatus(uint16_t port, bool up);
  // Periodic work; call every few milliseconds.
  void Tick();
  void Drain() { asic_.Drain(); }

  // CLI: "show ...", "clear counters", runtime interface and route changes.
  std::string Execute(std::string_view command);

  VirtualAsic& asic() { return asic_; }
  Orchagent& orch() { return *orch_; }
  bgp::Speaker* bgp() { return speaker_.get(); }
  lldp::Agent& lldp() { return lldp_; }
  const SwitchConfig& config() const { return config_; }

  void OnBgpRoute(const Ipv4Prefix& prefix, const std::vector<uint32_t>& next_hops) override;

 private:
  void OnCpuPacket(const CpuPacket& packet);
  void AnswerPing(const RouterInterfaceInfo& rif, std::span<const uint8_t> frame);
  void ResolveNeighbors();
  void SendArpRequest(int rif, uint32_t target);

  std::string ShowInterfaces(bool json) const;
  std::string ShowMac(bool json) const;
  std::string ShowArp(bool json) const;
  std::string ShowRoutes(bool json) const;
  std::string ShowBgpSummary(bool json) const;
  std::string ShowBgpRoutes(bool json) const;
  std::string ShowLldp(bool json) const;
  std::string ShowQueues(bool json) const;
  std::string ShowDrops(bool json) const;
  std::string ShowCopp(bool json) const;
  std::string ShowAcl(bool json) const;
  std::string ShowResources(bool json) const;

  Platform platform_;
  VirtualAsic asic_;
  std::unique_ptr<sai::RecordingSwitchApi> recorder_;
  std::unique_ptr<Orchagent> orch_;
  std::unique_ptr<bgp::Speaker> speaker_;
  lldp::Agent lldp_;
  SwitchConfig config_;
  TimeUs next_slow_tick_ = 0;
  TimeUs started_ = 0;
  std::map<uint32_t, TimeUs> arp_sent_;
};

}  // namespace nanonos
