// nosctl: sends one command to a running nanonosd over its CLI socket.
//   nosctl -s /run/nanonos/leaf1.sock show bgp summary
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char** argv) {
  std::string path = "/run/nanonos/nanonos.sock";
  if (const char* env = std::getenv("NANONOS_SOCKET")) path = env;
  int first = 1;
  if (argc > 2 && std::strcmp(argv[1], "-s") == 0) {
    path = argv[2];
    first = 3;
  }
  std::string command;
  for (int i = first; i < argc; ++i) {
    if (!command.empty()) command += ' ';
    command += argv[i];
  }
  if (command.empty()) command = "help";
  command += '\n';

  const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (fd < 0 || path.size() >= sizeof(addr.sun_path)) return 2;
  std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
  if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    std::fprintf(stderr, "nosctl: cannot connect to %s: %s\n", path.c_str(), std::strerror(errno));
    return 2;
  }
  if (write(fd, command.data(), command.size()) != static_cast<ssize_t>(command.size())) return 2;
  std::string output;
  char buf[4096];
  ssize_t n = 0;
  while ((n = read(fd, buf, sizeof(buf))) > 0) output.append(buf, static_cast<size_t>(n));
  close(fd);
  std::fwrite(output.data(), 1, output.size(), stdout);
  return output.rfind("% Error", 0) == 0 ? 1 : 0;
}
