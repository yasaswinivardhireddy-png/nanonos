// rtnetlink link monitor: reports carrier and admin state changes of the
// front-panel interfaces, so a pulled cable becomes a port-down event.
#pragma once

#include <functional>
#include <string>

namespace nanonos::os {

class NetlinkMonitor {
 public:
  NetlinkMonitor() = default;
  ~NetlinkMonitor();
  NetlinkMonitor(const NetlinkMonitor&) = delete;
  NetlinkMonitor& operator=(const NetlinkMonitor&) = delete;

  bool Open(std::string* error);
  int fd() const { return fd_; }
  // Drains pending messages; calls fn(ifindex, up) for every link message.
  void Read(const std::function<void(int ifindex, bool up)>& fn);

 private:
  int fd_ = -1;
};

}  // namespace nanonos::os
