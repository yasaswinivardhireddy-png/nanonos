#include "linux/netlink_monitor.h"

#include <cerrno>
#include <cstring>

#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

namespace nanonos::os {

NetlinkMonitor::~NetlinkMonitor() {
  if (fd_ >= 0) close(fd_);
}

bool NetlinkMonitor::Open(std::string* error) {
  fd_ = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd_ < 0) {
    *error = std::string("netlink socket: ") + std::strerror(errno);
    return false;
  }
  sockaddr_nl sa{};
  sa.nl_family = AF_NETLINK;
  sa.nl_groups = RTMGRP_LINK;
  if (bind(fd_, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
    *error = std::string("netlink bind: ") + std::strerror(errno);
    return false;
  }
  return true;
}

void NetlinkMonitor::Read(const std::function<void(int, bool)>& fn) {
  alignas(nlmsghdr) char buf[16384];
  while (true) {
    const ssize_t n = recv(fd_, buf, sizeof(buf), MSG_DONTWAIT);
    if (n <= 0) return;
    const size_t total = static_cast<size_t>(n);
    size_t off = 0;
    // Explicit bounds checks rather than NLMSG_OK/NLMSG_NEXT, which mix signed
    // and unsigned arithmetic.
    while (off + sizeof(nlmsghdr) <= total) {
      nlmsghdr hdr;
      std::memcpy(&hdr, buf + off, sizeof(hdr));
      if (hdr.nlmsg_len < sizeof(nlmsghdr) || hdr.nlmsg_len > total - off) break;
      if (hdr.nlmsg_type == NLMSG_DONE || hdr.nlmsg_type == NLMSG_ERROR) break;
      if ((hdr.nlmsg_type == RTM_NEWLINK || hdr.nlmsg_type == RTM_DELLINK) &&
          hdr.nlmsg_len >= NLMSG_LENGTH(sizeof(ifinfomsg))) {
        ifinfomsg ifi;
        std::memcpy(&ifi, buf + off + NLMSG_HDRLEN, sizeof(ifi));
        const bool up = hdr.nlmsg_type == RTM_NEWLINK && (ifi.ifi_flags & IFF_UP) &&
                        (ifi.ifi_flags & IFF_RUNNING);
        fn(ifi.ifi_index, up);
      }
      off += NLMSG_ALIGN(hdr.nlmsg_len);
    }
  }
}

}  // namespace nanonos::os
