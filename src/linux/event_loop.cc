#include "linux/event_loop.h"

#include <cerrno>
#include <csignal>
#include <cstring>

#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "common/logging.h"

namespace nanonos::os {

EventLoop::EventLoop() : epoll_fd_(epoll_create1(EPOLL_CLOEXEC)) {
  if (epoll_fd_ < 0) LOG_ERROR("epoll_create1: %s", std::strerror(errno));
}

EventLoop::~EventLoop() {
  if (timer_fd_ >= 0) close(timer_fd_);
  if (signal_fd_ >= 0) close(signal_fd_);
  if (epoll_fd_ >= 0) close(epoll_fd_);
}

bool EventLoop::Add(int fd, uint32_t events, Handler handler) {
  epoll_event ev{};
  ev.events = events;
  ev.data.fd = fd;
  if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) != 0) {
    LOG_ERROR("epoll_ctl(ADD %d): %s", fd, std::strerror(errno));
    return false;
  }
  handlers_[fd] = std::make_shared<Handler>(std::move(handler));
  return true;
}

bool EventLoop::Modify(int fd, uint32_t events) {
  epoll_event ev{};
  ev.events = events;
  ev.data.fd = fd;
  return epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, fd, &ev) == 0;
}

void EventLoop::Remove(int fd) {
  epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
  handlers_.erase(fd);
}

bool EventLoop::SetTicker(int period_ms, std::function<void()> tick) {
  timer_fd_ = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (timer_fd_ < 0) return false;
  itimerspec spec{};
  spec.it_interval.tv_sec = period_ms / 1000;
  spec.it_interval.tv_nsec = static_cast<long>(period_ms % 1000) * 1000000L;
  spec.it_value = spec.it_interval;
  if (timerfd_settime(timer_fd_, 0, &spec, nullptr) != 0) return false;
  const int fd = timer_fd_;
  return Add(fd, EPOLLIN, [fd, tick = std::move(tick)](uint32_t) {
    uint64_t expirations = 0;
    if (read(fd, &expirations, sizeof(expirations)) == sizeof(expirations)) tick();
  });
}

bool EventLoop::HandleTerminationSignals() {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) != 0) return false;
  signal_fd_ = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (signal_fd_ < 0) return false;
  const int fd = signal_fd_;
  return Add(fd, EPOLLIN, [this, fd](uint32_t) {
    signalfd_siginfo info;
    if (read(fd, &info, sizeof(info)) == sizeof(info)) {
      LOG_INFO("received signal %u, shutting down", info.ssi_signo);
      Stop();
    }
  });
}

void EventLoop::Run() {
  running_ = true;
  epoll_event events[64];
  while (running_) {
    const int n = epoll_wait(epoll_fd_, events, 64, 100);
    if (n < 0) {
      if (errno == EINTR) continue;
      LOG_ERROR("epoll_wait: %s", std::strerror(errno));
      break;
    }
    for (int i = 0; i < n && running_; ++i) {
      const auto it = handlers_.find(events[i].data.fd);
      if (it == handlers_.end()) continue;
      const std::shared_ptr<Handler> handler = it->second;
      (*handler)(events[i].events);
    }
  }
}

}  // namespace nanonos::os
