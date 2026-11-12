// Single-threaded epoll event loop with a periodic timer (timerfd) and
// SIGINT/SIGTERM handling (signalfd).
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>

namespace nanonos::os {

class EventLoop {
 public:
  using Handler = std::function<void(uint32_t events)>;

  EventLoop();
  ~EventLoop();
  EventLoop(const EventLoop&) = delete;
  EventLoop& operator=(const EventLoop&) = delete;

  bool ok() const { return epoll_fd_ >= 0; }
  bool Add(int fd, uint32_t events, Handler handler);
  bool Modify(int fd, uint32_t events);
  void Remove(int fd);
  // Calls `tick` every `period_ms` milliseconds.
  bool SetTicker(int period_ms, std::function<void()> tick);
  // Stops the loop on SIGINT or SIGTERM.
  bool HandleTerminationSignals();

  void Run();
  void Stop() { running_ = false; }

 private:
  int epoll_fd_ = -1;
  int timer_fd_ = -1;
  int signal_fd_ = -1;
  bool running_ = false;
  // shared_ptr so a handler can remove itself (or others) while running.
  std::unordered_map<int, std::shared_ptr<Handler>> handlers_;
};

}  // namespace nanonos::os
