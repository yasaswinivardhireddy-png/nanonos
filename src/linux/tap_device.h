// TAP host interface: the Linux kernel's view of a router interface, like
// SONiC's hostif netdevs. Packets the ASIC traps to the CPU are written here,
// so the kernel TCP/IP stack terminates BGP, ARP and ping; what the kernel
// sends is read back and transmitted by the ASIC.
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <span>
#include <string>

#include "common/types.h"

namespace nanonos::os {

class TapDevice {
 public:
  TapDevice() = default;
  ~TapDevice();
  TapDevice(const TapDevice&) = delete;
  TapDevice& operator=(const TapDevice&) = delete;

  bool Open(const std::string& name, const MacAddress& mac, uint16_t mtu,
            const InterfaceAddress& address, std::string* error);
  int fd() const { return fd_; }
  const std::string& name() const { return name_; }
  ssize_t Read(uint8_t* buf, size_t cap);  // 0 when nothing is waiting
  bool Write(std::span<const uint8_t> frame);

 private:
  int fd_ = -1;
  std::string name_;
};

}  // namespace nanonos::os
