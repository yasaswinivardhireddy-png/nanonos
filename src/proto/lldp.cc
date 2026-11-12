#include "proto/lldp.h"

#include <algorithm>
#include <cstring>

#include "common/byte_order.h"
#include "packet/packet.h"

namespace nanonos::lldp {
namespace {

constexpr MacAddress kLldpMulticast{{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}};

enum TlvType : uint8_t {
  kEnd = 0,
  kChassisId = 1,
  kPortId = 2,
  kTtl = 3,
  kPortDescription = 4,
  kSystemName = 5,
  kSystemDescription = 6,
  kCapabilities = 7,
  kManagementAddress = 8,
};

constexpr uint8_t kChassisSubtypeMac = 4;
constexpr uint8_t kPortSubtypeMac = 3;
constexpr uint8_t kPortSubtypeIfName = 5;

class Writer {
 public:
  explicit Writer(std::span<uint8_t> out) : out_(out) {}
  bool ok() const { return ok_; }
  size_t size() const { return pos_; }

  void Tlv(uint8_t type, std::span<const uint8_t> value) {
    if (value.size() > 511 || pos_ + 2 + value.size() > out_.size()) {
      ok_ = false;
      return;
    }
    StoreBe16(out_.data() + pos_, static_cast<uint16_t>((type << 9) | value.size()));
    // memcpy from a null pointer is undefined even for 0 bytes (the End TLV).
    if (!value.empty()) std::memcpy(out_.data() + pos_ + 2, value.data(), value.size());
    pos_ += 2 + value.size();
  }
  void TlvWithSubtype(uint8_t type, uint8_t subtype, std::string_view text) {
    std::vector<uint8_t> v;
    v.push_back(subtype);
    v.insert(v.end(), text.begin(), text.end());
    Tlv(type, v);
  }
  void TextTlv(uint8_t type, std::string_view text) {
    if (text.empty()) return;
    Tlv(type, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(text.data()),
                                       std::min<size_t>(text.size(), 255)));
  }
  void Raw(const uint8_t* data, size_t len) {
    if (pos_ + len > out_.size()) {
      ok_ = false;
      return;
    }
    std::memcpy(out_.data() + pos_, data, len);
    pos_ += len;
  }

 private:
  std::span<uint8_t> out_;
  size_t pos_ = 0;
  bool ok_ = true;
};

// Printable ASCII only, so neighbor-supplied strings are safe to show and log.
std::string Sanitize(std::span<const uint8_t> bytes) {
  std::string s;
  for (uint8_t b : bytes) s += (b >= 0x20 && b < 0x7f) ? static_cast<char>(b) : '.';
  return s;
}

}  // namespace

size_t BuildFrame(std::span<uint8_t> out, const MacAddress& src, const MacAddress& chassis_mac,
                  const Info& info) {
  Writer w(out);
  uint8_t eth[kEthHeaderLen];
  std::memcpy(eth, kLldpMulticast.bytes.data(), 6);
  std::memcpy(eth + 6, src.bytes.data(), 6);
  StoreBe16(eth + 12, kEtherTypeLldp);
  w.Raw(eth, sizeof(eth));

  uint8_t chassis[7];
  chassis[0] = kChassisSubtypeMac;
  std::memcpy(chassis + 1, chassis_mac.bytes.data(), 6);
  w.Tlv(kChassisId, chassis);
  w.TlvWithSubtype(kPortId, kPortSubtypeIfName, info.port_id);
  uint8_t ttl[2];
  StoreBe16(ttl, info.ttl);
  w.Tlv(kTtl, ttl);
  w.TextTlv(kPortDescription, info.port_description);
  w.TextTlv(kSystemName, info.system_name);
  w.TextTlv(kSystemDescription, info.system_description);
  uint8_t caps[4];
  StoreBe16(caps, info.capabilities);
  StoreBe16(caps + 2, info.enabled_capabilities);
  w.Tlv(kCapabilities, caps);
  if (info.mgmt_ip != 0) {
    // address length, subtype IPv4, address, interface numbering (ifIndex), id, OID length
    uint8_t mgmt[12] = {5, 1, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0};
    StoreBe32(mgmt + 2, info.mgmt_ip);
    w.Tlv(kManagementAddress, mgmt);
  }
  w.Tlv(kEnd, {});
  if (!w.ok()) return 0;
  size_t len = w.size();
  if (len < kMinFrameSize) {
    if (out.size() < kMinFrameSize) return 0;
    std::memset(out.data() + len, 0, kMinFrameSize - len);
    len = kMinFrameSize;
  }
  return len;
}

bool ParseFrame(std::span<const uint8_t> frame, Info* out) {
  if (frame.size() < kEthHeaderLen || LoadBe16(frame.data() + 12) != kEtherTypeLldp) return false;
  *out = Info{};
  const uint8_t* p = frame.data() + kEthHeaderLen;
  size_t remaining = frame.size() - kEthHeaderLen;
  int index = 0;
  bool have_ttl = false;
  bool saw_end = false;
  while (remaining >= 2) {
    const uint16_t header = LoadBe16(p);
    const uint8_t type = static_cast<uint8_t>(header >> 9);
    const size_t len = header & 0x01ff;
    if (len > remaining - 2) return false;
    const std::span<const uint8_t> v(p + 2, len);
    // The first three TLVs must be chassis id, port id and TTL, in that order.
    if (index == 0 && type != kChassisId) return false;
    if (index == 1 && type != kPortId) return false;
    if (index == 2 && type != kTtl) return false;
    switch (type) {
      case kEnd:
        saw_end = true;
        break;
      case kChassisId:
        if (len < 2) return false;
        out->chassis_id = (v[0] == kChassisSubtypeMac && len == 7)
                              ? MacAddress{{v[1], v[2], v[3], v[4], v[5], v[6]}}.ToString()
                              : Sanitize(v.subspan(1));
        break;
      case kPortId:
        if (len < 2) return false;
        out->port_id = (v[0] == kPortSubtypeMac && len == 7)
                           ? MacAddress{{v[1], v[2], v[3], v[4], v[5], v[6]}}.ToString()
                           : Sanitize(v.subspan(1));
        break;
      case kTtl:
        if (len != 2) return false;
        out->ttl = LoadBe16(v.data());
        have_ttl = true;
        break;
      case kPortDescription:
        out->port_description = Sanitize(v);
        break;
      case kSystemName:
        out->system_name = Sanitize(v);
        break;
      case kSystemDescription:
        out->system_description = Sanitize(v);
        break;
      case kCapabilities:
        if (len != 4) return false;
        out->capabilities = LoadBe16(v.data());
        out->enabled_capabilities = LoadBe16(v.data() + 2);
        break;
      case kManagementAddress:
        if (len >= 6 && v[0] == 5 && v[1] == 1) out->mgmt_ip = LoadBe32(v.data() + 2);
        break;
      default:
        break;  // organizationally specific and unknown TLVs are skipped
    }
    if (saw_end) break;
    p += 2 + len;
    remaining -= 2 + len;
    ++index;
  }
  return have_ttl && index >= 3;
}

void Agent::Configure(std::string system_name, std::string system_description,
                      const MacAddress& chassis_mac, uint16_t tx_interval_s,
                      uint16_t hold_multiplier) {
  system_name_ = std::move(system_name);
  system_description_ = std::move(system_description);
  chassis_mac_ = chassis_mac;
  tx_interval_s_ = std::max<uint16_t>(tx_interval_s, 1);
  hold_multiplier_ = std::max<uint16_t>(hold_multiplier, 1);
}

void Agent::AddPort(uint16_t port, std::string name, std::string description, uint32_t mgmt_ip) {
  Port& p = ports_[port];
  p.name = std::move(name);
  p.description = std::move(description);
  p.mgmt_ip = mgmt_ip;
  p.next_tx = clock_->Now();
}

void Agent::SetPortUp(uint16_t port, bool up) {
  const auto it = ports_.find(port);
  if (it == ports_.end()) return;
  it->second.up = up;
  if (up) {
    it->second.next_tx = clock_->Now();  // fast start: announce as soon as the link comes up
  } else {
    neighbors_.erase(port);
  }
}

void Agent::OnFrame(uint16_t port, std::span<const uint8_t> frame) {
  Info info;
  if (!ParseFrame(frame, &info)) {
    ++rx_errors_;
    return;
  }
  ++rx_frames_;
  if (info.ttl == 0) {  // shutdown LLDPDU
    neighbors_.erase(port);
    return;
  }
  Neighbor& n = neighbors_[port];
  n.local_port = port;
  std::memcpy(n.src_mac.bytes.data(), frame.data() + 6, 6);
  n.info = std::move(info);
  n.expires = clock_->Now() + static_cast<TimeUs>(n.info.ttl) * kUsPerSec;
}

void Agent::Tick(const std::function<void(uint16_t, std::span<const uint8_t>)>& send) {
  const TimeUs now = clock_->Now();
  for (auto it = neighbors_.begin(); it != neighbors_.end();) {
    it = now >= it->second.expires ? neighbors_.erase(it) : std::next(it);
  }
  uint8_t frame[512];
  for (auto& [index, port] : ports_) {
    if (!port.up || now < port.next_tx) continue;
    port.next_tx = now + static_cast<TimeUs>(tx_interval_s_) * kUsPerSec;
    Info info;
    info.port_id = port.name;
    info.port_description = port.description;
    info.system_name = system_name_;
    info.system_description = system_description_;
    info.ttl = static_cast<uint16_t>(std::min<int>(tx_interval_s_ * hold_multiplier_, 65535));
    info.mgmt_ip = port.mgmt_ip;
    const size_t len = BuildFrame(frame, chassis_mac_, chassis_mac_, info);
    if (len > 0) send(index, std::span<const uint8_t>(frame, len));
  }
}

}  // namespace nanonos::lldp
