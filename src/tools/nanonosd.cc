// nanonosd: runs one NanoNOS switch on Linux.
//
// Front-panel ports are Linux interfaces ("port <netdev>" in the config)
// opened with AF_PACKET; each router interface gets a TAP host interface
// named after it (Ethernet4, Vlan10) so the kernel terminates BGP, ARP and
// ping; link changes arrive over rtnetlink; the CLI listens on a Unix socket.
#include <sys/epoll.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "common/logging.h"
#include "linux/af_packet_port.h"
#include "linux/cli_server.h"
#include "linux/event_loop.h"
#include "linux/netlink_monitor.h"
#include "linux/tap_device.h"
#include "linux/tcp_transport.h"
#include "orch/config.h"
#include "sw/switch_node.h"

namespace nanonos {
namespace {

struct Options {
  std::string config_path;
  std::string socket_path;
  int tick_ms = 5;
  bool verbose = false;
  bool record_sai = false;
};

void Usage() {
  std::fprintf(stderr,
               "usage: nanonosd -c CONFIG [-s CLI_SOCKET] [-t TICK_MS] [-v] [--sai-record]\n");
}

bool ParseArgs(int argc, char** argv, Options* o) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    const bool has_value = i + 1 < argc;
    if (arg == "-c" && has_value) {
      o->config_path = argv[++i];
    } else if (arg == "-s" && has_value) {
      o->socket_path = argv[++i];
    } else if (arg == "-t" && has_value) {
      o->tick_ms = std::max(1, std::atoi(argv[++i]));
    } else if (arg == "-v") {
      o->verbose = true;
    } else if (arg == "--sai-record") {
      o->record_sai = true;
    } else {
      return false;
    }
  }
  return !o->config_path.empty();
}

int Run(const Options& opt) {
  SetLogLevel(opt.verbose ? LogLevel::kDebug : LogLevel::kInfo);
  std::ifstream in(opt.config_path);
  if (!in) {
    LOG_ERROR("cannot read %s", opt.config_path.c_str());
    return 1;
  }
  std::stringstream text;
  text << in.rdbuf();
  ConfigError config_error;
  const auto config = ParseConfig(text.str(), &config_error);
  if (!config) {
    LOG_ERROR("%s:%d: %s", opt.config_path.c_str(), config_error.line,
              config_error.message.c_str());
    return 1;
  }
  SetLogTag(config->hostname);

  uint16_t num_ports = 1;
  for (const InterfaceConfig& ic : config->interfaces) {
    num_ports = std::max<uint16_t>(num_ports, static_cast<uint16_t>(ic.index + 1));
  }
  if (num_ports > VirtualAsic::kMaxPorts) {
    LOG_ERROR("at most %u ports are supported", VirtualAsic::kMaxPorts);
    return 1;
  }

  SteadyClock clock;
  os::EventLoop loop;
  os::TcpTransport tcp(&loop, 179);
  std::vector<std::unique_ptr<os::AfPacketPort>> ports(num_ports);
  std::vector<std::unique_ptr<os::TapDevice>> taps;  // indexed by router interface index

  SwitchNode::Platform platform;
  platform.clock = &clock;
  platform.bgp_transport = config->bgp.enabled ? &tcp : nullptr;
  platform.asic.num_ports = num_ports;
  platform.transmit = [&ports](uint16_t port, std::span<const uint8_t> frame) {
    if (port < ports.size() && ports[port]) ports[port]->Send(frame);
  };
  platform.deliver_to_host = [&taps](int rif, std::span<const uint8_t> frame) {
    if (rif >= 0 && static_cast<size_t>(rif) < taps.size() && taps[static_cast<size_t>(rif)]) {
      taps[static_cast<size_t>(rif)]->Write(frame);
    }
  };
  if (opt.record_sai) {
    platform.sai_record = [](const std::string& line) { LOG_INFO("sai %s", line.c_str()); };
  }
  SwitchNode node(std::move(platform));

  for (const BgpNeighborConfig& n : config->bgp.neighbors) {
    tcp.AddNeighbor(n.address, n.password, n.ttl_security_hops);
  }
  std::vector<std::string> errors;
  if (!node.Configure(*config, &errors)) {
    for (const std::string& e : errors) LOG_ERROR("config: %s", e.c_str());
    return 1;
  }
  if (node.bgp() != nullptr) tcp.SetHandler(node.bgp());

  // Host interfaces for every router interface.
  for (const RouterInterfaceInfo& rif : node.orch().rifs()) {
    if (static_cast<size_t>(rif.index) >= taps.size())
      taps.resize(static_cast<size_t>(rif.index) + 1);
    auto tap = std::make_unique<os::TapDevice>();
    std::string error;
    uint16_t mtu = 1500;
    if (const InterfaceConfig* ic = config->FindInterface(rif.name)) mtu = ic->mtu;
    if (!tap->Open(rif.name, rif.mac, mtu, rif.address, &error)) {
      LOG_ERROR("host interface %s: %s", rif.name.c_str(), error.c_str());
      return 1;
    }
    const int index = rif.index;
    os::TapDevice* raw = tap.get();
    loop.Add(raw->fd(), EPOLLIN, [&node, raw, index](uint32_t) {
      uint8_t buf[kMaxFrameSize];
      for (int i = 0; i < 64; ++i) {
        const ssize_t n = raw->Read(buf, sizeof(buf));
        if (n <= 0) break;
        node.ReceiveFromHost(index, std::span<const uint8_t>(buf, static_cast<size_t>(n)));
      }
      node.Drain();
    });
    taps[static_cast<size_t>(rif.index)] = std::move(tap);
  }

  // Front-panel ports.
  for (const InterfaceConfig& ic : config->interfaces) {
    if (ic.netdev.empty()) continue;
    auto port = std::make_unique<os::AfPacketPort>();
    std::string error;
    if (!port->Open(ic.netdev, &error)) {
      LOG_ERROR("%s: %s", ic.name.c_str(), error.c_str());
      return 1;
    }
    const uint16_t index = ic.index;
    os::AfPacketPort* raw = port.get();
    loop.Add(raw->fd(), EPOLLIN, [&node, raw, index](uint32_t) {
      uint8_t buf[kMaxFrameSize + 4];
      for (int i = 0; i < 256; ++i) {
        const ssize_t n = raw->Receive(buf, sizeof(buf));
        if (n == 0) break;
        if (n > 0) node.ReceiveFrame(index, std::span<const uint8_t>(buf, static_cast<size_t>(n)));
      }
      node.Drain();
    });
    node.SetPortOperStatus(index, raw->LinkUp());
    LOG_INFO("%s bound to %s (link %s)", ic.name.c_str(), ic.netdev.c_str(),
             raw->LinkUp() ? "up" : "down");
    ports[index] = std::move(port);
  }

  os::NetlinkMonitor links;
  std::string error;
  if (links.Open(&error)) {
    loop.Add(links.fd(), EPOLLIN, [&](uint32_t) {
      links.Read([&](int ifindex, bool up) {
        for (uint16_t i = 0; i < ports.size(); ++i) {
          if (ports[i] && ports[i]->ifindex() == ifindex &&
              node.asic().GetPortOperStatus(node.asic().GetPortId(i)) != up) {
            node.SetPortOperStatus(i, up);
          }
        }
      });
    });
  } else {
    LOG_WARN("link monitoring disabled: %s", error.c_str());
  }

  if (node.bgp() != nullptr && !tcp.Listen(&error)) {
    LOG_ERROR("bgp: %s", error.c_str());
    return 1;
  }

  const std::string socket_path =
      opt.socket_path.empty() ? "/run/nanonos/" + config->hostname + ".sock" : opt.socket_path;
  os::CliServer cli(&loop, [&node](std::string_view command) { return node.Execute(command); });
  if (!cli.Listen(socket_path, &error)) {
    LOG_ERROR("%s", error.c_str());
    return 1;
  }

  loop.HandleTerminationSignals();
  loop.SetTicker(opt.tick_ms, [&] {
    tcp.ProcessDeferred();
    node.Tick();
  });
  LOG_INFO("NanoNOS %s ready: %u ports, CLI on %s", kNanonosVersion, num_ports,
           socket_path.c_str());
  loop.Run();
  return 0;
}

}  // namespace
}  // namespace nanonos

int main(int argc, char** argv) {
  nanonos::Options options;
  if (!nanonos::ParseArgs(argc, argv, &options)) {
    nanonos::Usage();
    return 2;
  }
  return nanonos::Run(options);
}
