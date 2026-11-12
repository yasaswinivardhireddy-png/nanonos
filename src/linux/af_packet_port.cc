#include "linux/af_packet_port.h"

#include <cerrno>
#include <cstdio>
#include <cstring>

#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "common/byte_order.h"

namespace nanonos::os {
namespace {

bool InterfaceFlags(const std::string& name, short* flags) {
  const int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (s < 0) return false;
  ifreq ifr{};
  std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
  const bool ok = ioctl(s, SIOCGIFFLAGS, &ifr) == 0;
  if (ok) *flags = ifr.ifr_flags;
  close(s);
  return ok;
}

// The switch owns the port: the kernel must not answer ARP on it (it would
// reply for addresses that belong to the TAP host interfaces, with the wrong
// MAC) or send IPv6 neighbor discovery out of it.
void PreparePort(const std::string& name) {
  const int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (s < 0) return;
  ifreq ifr{};
  std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
  if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
    ifr.ifr_flags = static_cast<short>(ifr.ifr_flags | IFF_UP | IFF_NOARP);
    ioctl(s, SIOCSIFFLAGS, &ifr);
  }
  close(s);
  const std::string path = "/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6";
  if (FILE* f = std::fopen(path.c_str(), "w")) {
    std::fputs("1", f);
    std::fclose(f);
  }
}

}  // namespace

AfPacketPort::~AfPacketPort() {
  if (fd_ >= 0) close(fd_);
}

bool AfPacketPort::Open(const std::string& ifname, std::string* error) {
  name_ = ifname;
  ifindex_ = static_cast<int>(if_nametoindex(ifname.c_str()));
  if (ifindex_ == 0) {
    *error = "no such interface: " + ifname;
    return false;
  }
  fd_ = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
  if (fd_ < 0) {
    *error = std::string("socket(AF_PACKET): ") + std::strerror(errno);
    return false;
  }
  sockaddr_ll sll{};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = ifindex_;
  if (bind(fd_, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) != 0) {
    *error = std::string("bind(") + ifname + "): " + std::strerror(errno);
    return false;
  }
  packet_mreq mr{};
  mr.mr_ifindex = ifindex_;
  mr.mr_type = PACKET_MR_PROMISC;
  if (setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) != 0) {
    *error = std::string("promiscuous mode: ") + std::strerror(errno);
    return false;
  }
  const int one = 1;
  setsockopt(fd_, SOL_PACKET, PACKET_AUXDATA, &one, sizeof(one));
#ifdef PACKET_IGNORE_OUTGOING
  setsockopt(fd_, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one));
#endif
  const int bufsize = 4 << 20;
  setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
  setsockopt(fd_, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
  PreparePort(ifname);
  return true;
}

ssize_t AfPacketPort::Receive(uint8_t* buf, size_t cap) {
  // Receive 4 bytes into the buffer so a VLAN tag can be reinserted in place.
  constexpr size_t kTag = 4;
  sockaddr_ll from{};
  iovec iov{buf + kTag, cap - kTag};
  alignas(cmsghdr) char control[CMSG_SPACE(sizeof(tpacket_auxdata))];
  msghdr msg{};
  msg.msg_name = &from;
  msg.msg_namelen = sizeof(from);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  const ssize_t n = recvmsg(fd_, &msg, MSG_DONTWAIT | MSG_TRUNC);
  if (n < 0) return 0;
  if (from.sll_pkttype == PACKET_OUTGOING) return -1;
  if (static_cast<size_t>(n) > cap - kTag || (msg.msg_flags & MSG_TRUNC)) return -1;
  size_t len = static_cast<size_t>(n);
  for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
    if (c->cmsg_level != SOL_PACKET || c->cmsg_type != PACKET_AUXDATA) continue;
    tpacket_auxdata aux;
    std::memcpy(&aux, CMSG_DATA(c), sizeof(aux));
    if ((aux.tp_status & TP_STATUS_VLAN_VALID) && len >= 12) {
      uint16_t tpid = ETH_P_8021Q;
#ifdef TP_STATUS_VLAN_TPID_VALID
      if (aux.tp_status & TP_STATUS_VLAN_TPID_VALID) tpid = aux.tp_vlan_tpid;
#endif
      std::memmove(buf, buf + kTag, 12);  // MAC addresses move 4 bytes earlier
      StoreBe16(buf + 12, tpid);
      StoreBe16(buf + 14, aux.tp_vlan_tci);
      return static_cast<ssize_t>(len + kTag);
    }
  }
  std::memmove(buf, buf + kTag, len);
  return static_cast<ssize_t>(len);
}

bool AfPacketPort::Send(std::span<const uint8_t> frame) {
  if (send(fd_, frame.data(), frame.size(), MSG_DONTWAIT) < 0) {
    ++tx_errors_;
    return false;
  }
  return true;
}

bool AfPacketPort::LinkUp() const {
  short flags = 0;
  return InterfaceFlags(name_, &flags) && (flags & IFF_UP) && (flags & IFF_RUNNING);
}

}  // namespace nanonos::os
