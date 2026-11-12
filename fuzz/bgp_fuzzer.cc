// Fuzzes BGP stream framing and message decoding. Any UPDATE that decodes is
// re-encoded and decoded again, and must round-trip to the same content.
#include <cstddef>
#include <cstdint>
#include <vector>

#include "proto/bgp_message.h"

using namespace nanonos::bgp;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  for (bool as4 : {true, false}) {
    MessageReader reader;
    reader.Append(std::span<const uint8_t>(data, size));
    MessageType type{};
    std::vector<uint8_t> body;
    Error error;
    while (reader.Next(&type, &body, &error)) {
      switch (type) {
        case MessageType::kOpen: {
          OpenMessage open;
          DecodeOpen(body, &open);
          break;
        }
        case MessageType::kUpdate: {
          UpdateMessage u;
          if (!DecodeUpdate(body, as4, &u).ok() || u.nlri.empty()) break;
          for (const auto& m : EncodeAnnouncements(u.attrs, u.nlri, as4)) {
            UpdateMessage again;
            const std::span<const uint8_t> b(m.data() + kHeaderLen, m.size() - kHeaderLen);
            if (!DecodeUpdate(b, as4, &again).ok()) __builtin_trap();
            // Unknown optional attributes are dropped; everything else survives.
            if (again.attrs.origin != u.attrs.origin || again.attrs.next_hop != u.attrs.next_hop ||
                again.attrs.Flatten() != u.attrs.Flatten()) {
              __builtin_trap();
            }
          }
          break;
        }
        case MessageType::kNotification: {
          NotificationMessage n;
          DecodeNotification(body, &n);
          break;
        }
        case MessageType::kKeepalive:
          break;
      }
    }
  }
  return 0;
}
