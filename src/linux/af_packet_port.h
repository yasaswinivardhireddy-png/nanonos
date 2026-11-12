// A front-panel port backed by a Linux network interface (a veth in tests):
// an AF_PACKET raw socket in promiscuous mode.
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <span>
#include <string>

namespace nanonos::os {

class AfPacketPort {
 public:
  AfPacketPort() = default;
  ~AfPacketPort();
  AfPacketPort(const AfPacketPort&) = delete;
  AfPacketPort& operator=(const AfPacketPort&) = delete;

  bool Open(const std::string& ifname, std::string* error);
  int fd() const { return fd_; }
  int ifindex() const { return ifindex_; }
  const std::string& name() const { return name_; }

  // Reads one frame into `buf` (capacity `cap`). Returns the frame length,
  // 0 when no frame is waiting, or -1 for a frame to skip (our own
  // transmissions, oversize frames). A VLAN tag the kernel stripped into
  // metadata (VLAN offload) is reinserted, as libpcap does.
  ssize_t Receive(uint8_t* buf, size_t cap);
  bool Send(std::span<const uint8_t> frame);
  // Administratively up and carrier present (IFF_UP and IFF_RUNNING).
  bool LinkUp() const;

  uint64_t tx_errors() const { return tx_errors_; }

 private:
  int fd_ = -1;
  int ifindex_ = 0;
  std::string name_;
  uint64_t tx_errors_ = 0;
};

}  // namespace nanonos::os
