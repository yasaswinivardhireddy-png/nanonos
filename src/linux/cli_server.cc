#include "linux/cli_server.h"

#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

namespace nanonos::os {

CliServer::~CliServer() {
  for (const auto& [fd, text] : pending_) close(fd);
  if (listen_fd_ >= 0) {
    close(listen_fd_);
    unlink(path_.c_str());
  }
}

bool CliServer::Listen(const std::string& path, std::string* error) {
  path_ = path;
  listen_fd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (listen_fd_ < 0 || path.size() >= sizeof(addr.sun_path)) {
    *error = "cannot create CLI socket " + path;
    return false;
  }
  std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  unlink(path.c_str());
  if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
      listen(listen_fd_, 16) != 0) {
    *error = "CLI socket " + path + ": " + std::strerror(errno);
    return false;
  }
  return loop_->Add(listen_fd_, EPOLLIN, [this](uint32_t) { OnAccept(); });
}

void CliServer::OnAccept() {
  while (true) {
    const int fd = accept4(listen_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) return;
    pending_[fd] = "";
    loop_->Add(fd, EPOLLIN, [this, fd](uint32_t) { OnClient(fd); });
  }
}

void CliServer::OnClient(int fd) {
  char buf[1024];
  while (true) {
    const ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n > 0) {
      std::string& line = pending_[fd];
      line.append(buf, static_cast<size_t>(n));
      if (line.size() > 4096) return Finish(fd);  // oversized command
      const size_t nl = line.find('\n');
      if (nl == std::string::npos) continue;
      const std::string output = handler_(std::string_view(line).substr(0, nl));
      // Small responses: write synchronously with a timeout.
      const int flags = fcntl(fd, F_GETFL, 0);
      fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
      timeval tv{1, 0};
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
      size_t sent = 0;
      while (sent < output.size()) {
        const ssize_t w = send(fd, output.data() + sent, output.size() - sent, MSG_NOSIGNAL);
        if (w <= 0) break;
        sent += static_cast<size_t>(w);
      }
      return Finish(fd);
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
    return Finish(fd);  // client went away
  }
}

void CliServer::Finish(int fd) {
  loop_->Remove(fd);
  pending_.erase(fd);
  close(fd);
}

}  // namespace nanonos::os
