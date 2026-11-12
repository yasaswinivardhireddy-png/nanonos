// BGP-4 message encoding and decoding (RFC 4271), with 4-octet AS numbers
// (RFC 6793), multiprotocol and extended optional parameter parsing
// (RFC 4760 capability, RFC 9072). Every decode error carries the
// NOTIFICATION code/subcode RFC 4271 section 6 requires.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "common/types.h"

namespace nanonos::bgp {

inline constexpr size_t kHeaderLen = 19;
inline constexpr size_t kMaxMessageLen = 4096;
inline constexpr uint32_t kAsTrans = 23456;

enum class MessageType : uint8_t { kOpen = 1, kUpdate = 2, kNotification = 3, kKeepalive = 4 };

namespace err {
inline constexpr uint8_t kHeader = 1;
inline constexpr uint8_t kOpen = 2;
inline constexpr uint8_t kUpdate = 3;
inline constexpr uint8_t kHoldTimerExpired = 4;
inline constexpr uint8_t kFsm = 5;
inline constexpr uint8_t kCease = 6;

// Message header subcodes
inline constexpr uint8_t kNotSynchronized = 1;
inline constexpr uint8_t kBadLength = 2;
inline constexpr uint8_t kBadType = 3;
// OPEN subcodes
inline constexpr uint8_t kUnsupportedVersion = 1;
inline constexpr uint8_t kBadPeerAs = 2;
inline constexpr uint8_t kBadBgpId = 3;
inline constexpr uint8_t kUnsupportedOptParam = 4;
inline constexpr uint8_t kUnacceptableHoldTime = 6;
// UPDATE subcodes
inline constexpr uint8_t kMalformedAttrList = 1;
inline constexpr uint8_t kUnrecognizedWellKnown = 2;
inline constexpr uint8_t kMissingWellKnown = 3;
inline constexpr uint8_t kAttrFlags = 4;
inline constexpr uint8_t kAttrLength = 5;
inline constexpr uint8_t kInvalidOrigin = 6;
inline constexpr uint8_t kInvalidNextHop = 8;
inline constexpr uint8_t kOptionalAttr = 9;
inline constexpr uint8_t kInvalidNetwork = 10;
inline constexpr uint8_t kMalformedAsPath = 11;
// Cease subcodes (RFC 4486)
inline constexpr uint8_t kAdminShutdown = 2;
inline constexpr uint8_t kAdminReset = 4;
inline constexpr uint8_t kConnectionRejected = 5;
inline constexpr uint8_t kCollisionResolution = 7;
}  // namespace err

struct Error {
  uint8_t code = 0;
  uint8_t subcode = 0;
  std::vector<uint8_t> data;
  bool ok() const { return code == 0; }
};
std::string ErrorString(uint8_t code, uint8_t subcode);

struct OpenMessage {
  uint8_t version = 4;
  uint32_t my_as = 0;  // the real AS: from the 4-octet AS capability when present
  uint16_t hold_time = 90;
  uint32_t bgp_id = 0;
  bool cap_as4 = false;
  bool cap_mp_ipv4_unicast = false;
};

enum class Origin : uint8_t { kIgp = 0, kEgp = 1, kIncomplete = 2 };

struct AsPathSegment {
  uint8_t type = 2;  // 1 = AS_SET, 2 = AS_SEQUENCE
  std::vector<uint32_t> asns;
  friend bool operator==(const AsPathSegment&, const AsPathSegment&) = default;
};

struct PathAttributes {
  Origin origin = Origin::kIgp;
  std::vector<AsPathSegment> as_path;
  uint32_t next_hop = 0;
  std::optional<uint32_t> med;
  std::optional<uint32_t> local_pref;
  bool atomic_aggregate = false;
  std::vector<uint32_t> communities;

  // Path length for best-path selection: an AS_SET counts as one hop.
  size_t AsPathLength() const;
  bool ContainsAs(uint32_t asn) const;
  uint32_t FirstAs() const;  // neighbor AS, 0 if the path is empty
  std::vector<uint32_t> Flatten() const;
  friend bool operator==(const PathAttributes&, const PathAttributes&) = default;
};

struct UpdateMessage {
  std::vector<Ipv4Prefix> withdrawn;
  bool has_attributes = false;
  PathAttributes attrs;
  std::vector<Ipv4Prefix> nlri;
};

struct NotificationMessage {
  uint8_t code = 0;
  uint8_t subcode = 0;
  std::vector<uint8_t> data;
};

std::vector<uint8_t> EncodeOpen(const OpenMessage& open);
std::vector<uint8_t> EncodeKeepalive();
std::vector<uint8_t> EncodeNotification(uint8_t code, uint8_t subcode,
                                        std::span<const uint8_t> data = {});
// Withdrawals in as few UPDATE messages as fit in 4096 bytes each.
std::vector<std::vector<uint8_t>> EncodeWithdrawals(const std::vector<Ipv4Prefix>& prefixes);
// Announcements sharing one attribute set, split across messages as needed.
std::vector<std::vector<uint8_t>> EncodeAnnouncements(const PathAttributes& attrs,
                                                      const std::vector<Ipv4Prefix>& prefixes,
                                                      bool as4);

Error DecodeOpen(std::span<const uint8_t> body, OpenMessage* out);
Error DecodeUpdate(std::span<const uint8_t> body, bool as4, UpdateMessage* out);
Error DecodeNotification(std::span<const uint8_t> body, NotificationMessage* out);

// Reassembles BGP messages from a TCP byte stream: bytes arrive in arbitrary
// chunks and a message may span many reads.
class MessageReader {
 public:
  void Append(std::span<const uint8_t> data);
  // True when a complete message was extracted into *type and *body. False
  // when more bytes are needed or on a header error (then error->ok() is false).
  bool Next(MessageType* type, std::vector<uint8_t>* body, Error* error);
  size_t buffered() const { return buffer_.size() - offset_; }

 private:
  std::vector<uint8_t> buffer_;
  size_t offset_ = 0;
};

}  // namespace nanonos::bgp
