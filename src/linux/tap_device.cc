#include "linux/tap_device.h"

#include <cerrno>
#include <cstdio>
#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_tun.h>

namespace nanonos::os {
namespace {

bool Ioctl(int s, unsigned long request, ifreq* ifr, const char* what, std::string* error) {
  if (ioctl(s, request, ifr) == 0) return true;
  *error = std::string(what) + ": " + std::strerror(errno);
  return false;
}

void WriteProc(const std::string& path, const char* value) {
  if (FILE* f = std::fopen(path.c_str(), "w")) {
    std::fputs(value, f);
    std::fclose(f);
  }
}

}  // namespace

TapDevice::~TapDevice() {
  if (fd_ >= 0) close(fd_);
}

bool TapDevice::Open(const std::string& name, const MacAddress& mac, uint16_t mtu,
                     const InterfaceAddress& address, std::string* error) {
  name_ = name;
  fd_ = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
  if (fd_ < 0) {
    *error = std::string("/dev/net/tun: ") + std::strerror(errno);
    return false;
  }
  ifreq ifr{};
  std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  if (!Ioctl(fd_, TUNSETIFF, &ifr, "TUNSETIFF", error)) return false;

  // No IPv6 on host interfaces: avoids router solicitations and MLD noise.
  WriteProc("/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6", "1");

  const int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (s < 0) {
    *error = std::string("socket: ") + std::strerror(errno);
    return false;
  }
  bool ok = true;
  ifreq r{};
  std::strncpy(r.ifr_name, name.c_str(), IFNAMSIZ - 1);
  r.ifr_hwaddr.sa_family = ARPHRD_ETHER;
  std::memcpy(r.ifr_hwaddr.sa_data, mac.bytes.data(), 6);
  ok = ok && Ioctl(s, SIOCSIFHWADDR, &r, "set MAC", error);

  std::memset(&r, 0, sizeof(r));
  std::strncpy(r.ifr_name, name.c_str(), IFNAMSIZ - 1);
  r.ifr_mtu = mtu;
  ok = ok && Ioctl(s, SIOCSIFMTU, &r, "set MTU", error);

  std::memset(&r, 0, sizeof(r));
  std::strncpy(r.ifr_name, name.c_str(), IFNAMSIZ - 1);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(address.ip);
  std::memcpy(&r.ifr_addr, &addr, sizeof(addr));
  ok = ok && Ioctl(s, SIOCSIFADDR, &r, "set address", error);

  std::memset(&r, 0, sizeof(r));
  std::strncpy(r.ifr_name, name.c_str(), IFNAMSIZ - 1);
  addr.sin_addr.s_addr = htonl(PrefixMask(address.len));
  std::memcpy(&r.ifr_netmask, &addr, sizeof(addr));
  ok = ok && Ioctl(s, SIOCSIFNETMASK, &r, "set netmask", error);

  std::memset(&r, 0, sizeof(r));
  std::strncpy(r.ifr_name, name.c_str(), IFNAMSIZ - 1);
  ok = ok && Ioctl(s, SIOCGIFFLAGS, &r, "get flags", error);
  r.ifr_flags = static_cast<short>(r.ifr_flags | IFF_UP | IFF_RUNNING);
  ok = ok && Ioctl(s, SIOCSIFFLAGS, &r, "bring up", error);
  close(s);
  return ok;
}

ssize_t TapDevice::Read(uint8_t* buf, size_t cap) {
  const ssize_t n = read(fd_, buf, cap);
  return n < 0 ? 0 : n;
}

bool TapDevice::Write(std::span<const uint8_t> frame) {
  return write(fd_, frame.data(), frame.size()) == static_cast<ssize_t>(frame.size());
}

}  // namespace nanonos::os
