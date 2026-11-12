// Management interface: a Unix-domain socket that takes one command line
// per connection and returns its output ("show bgp summary json", ...).
#pragma once

#include <functional>
#include <map>
#include <string>
#include <string_view>

#include "linux/event_loop.h"

namespace nanonos::os {

class CliServer {
 public:
  using Handler = std::function<std::string(std::string_view command)>;

  CliServer(EventLoop* loop, Handler handler) : loop_(loop), handler_(std::move(handler)) {}
  ~CliServer();
  CliServer(const CliServer&) = delete;
  CliServer& operator=(const CliServer&) = delete;

  bool Listen(const std::string& path, std::string* error);

 private:
  void OnAccept();
  void OnClient(int fd);
  void Finish(int fd);

  EventLoop* loop_;
  Handler handler_;
  int listen_fd_ = -1;
  std::string path_;
  std::map<int, std::string> pending_;  // partial command per client
};

}  // namespace nanonos::os
