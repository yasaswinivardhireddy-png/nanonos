#include "proto/bgp_message.h"

#include <algorithm>
#include <cstring>

#include "common/byte_order.h"

namespace nanonos::bgp {
namespace {

constexpr uint8_t kAttrFlagOptional = 0x80;
constexpr uint8_t kAttrFlagTransitive = 0x40;
constexpr uint8_t kAttrFlagPartial = 0x20;
constexpr uint8_t kAttrFlagExtendedLength = 0x10;

enum AttrType : uint8_t {
  kOrigin = 1,
  kAsPath = 2,
  kNextHop = 3,
  kMed = 4,
  kLocalPref = 5,
  kAtomicAggregate = 6,
  kAggregator = 7,
  kCommunities = 8,
};

constexpr uint8_t kCapMultiprotocol = 1;
constexpr uint8_t kCapAs4 = 65;

std::vector<uint8_t> Message(MessageType type, std::span<const uint8_t> body) {
  std::vector<uint8_t> m(kHeaderLen, 0xff);
  StoreBe16(m.data() + 16, static_cast<uint16_t>(kHeaderLen + body.size()));
  m[18] = static_cast<uint8_t>(type);
  m.insert(m.end(), body.begin(), body.end());
  return m;
}

void PutBe16(std::vector<uint8_t>* v, uint16_t x) {
  v->push_back(static_cast<uint8_t>(x >> 8));
  v->push_back(static_cast<uint8_t>(x));
}

void PutBe32(std::vector<uint8_t>* v, uint32_t x) {
  PutBe16(v, static_cast<uint16_t>(x >> 16));
  PutBe16(v, static_cast<uint16_t>(x));
}

size_t PrefixWireSize(const Ipv4Prefix& p) { return 1 + (p.len + 7) / 8; }

void PutPrefix(std::vector<uint8_t>* v, const Ipv4Prefix& p) {
  v->push_back(p.len);
  for (int i = 0; i < (p.len + 7) / 8; ++i) {
    v->push_back(static_cast<uint8_t>(p.addr >> (24 - 8 * i)));
  }
}

void PutAttr(std::vector<uint8_t>* v, uint8_t flags, uint8_t type, std::span<const uint8_t> value) {
  if (value.size() > 255) flags |= kAttrFlagExtendedLength;
  v->push_back(flags);
  v->push_back(type);
  if (flags & kAttrFlagExtendedLength) {
    PutBe16(v, static_cast<uint16_t>(value.size()));
  } else {
    v->push_back(static_cast<uint8_t>(value.size()));
  }
  v->insert(v->end(), value.begin(), value.end());
}

std::vector<uint8_t> EncodeAttributes(const PathAttributes& a, bool as4) {
  std::vector<uint8_t> out;
  const uint8_t origin = static_cast<uint8_t>(a.origin);
  PutAttr(&out, kAttrFlagTransitive, kOrigin, std::span<const uint8_t>(&origin, 1));

  std::vector<uint8_t> path;
  for (const AsPathSegment& seg : a.as_path) {
    // A segment holds at most 255 ASNs; split longer ones.
    for (size_t start = 0; start < seg.asns.size(); start += 255) {
      const size_t count = std::min<size_t>(255, seg.asns.size() - start);
      path.push_back(seg.type);
      path.push_back(static_cast<uint8_t>(count));
      for (size_t i = start; i < start + count; ++i) {
        const uint32_t asn = seg.asns[i];
        if (as4) {
          PutBe32(&path, asn);
        } else {
          PutBe16(&path, static_cast<uint16_t>(asn > 0xffff ? kAsTrans : asn));
        }
      }
    }
  }
  PutAttr(&out, kAttrFlagTransitive, kAsPath, path);

  uint8_t nh[4];
  StoreBe32(nh, a.next_hop);
  PutAttr(&out, kAttrFlagTransitive, kNextHop, nh);
  if (a.med) {
    uint8_t v[4];
    StoreBe32(v, *a.med);
    PutAttr(&out, kAttrFlagOptional, kMed, v);
  }
  if (a.local_pref) {
    uint8_t v[4];
    StoreBe32(v, *a.local_pref);
    PutAttr(&out, kAttrFlagTransitive, kLocalPref, v);
  }
  if (a.atomic_aggregate) PutAttr(&out, kAttrFlagTransitive, kAtomicAggregate, {});
  if (!a.communities.empty()) {
    std::vector<uint8_t> v;
    for (uint32_t c : a.communities) PutBe32(&v, c);
    PutAttr(&out, kAttrFlagOptional | kAttrFlagTransitive, kCommunities, v);
  }
  return out;
}

Error Fail(uint8_t code, uint8_t subcode, std::vector<uint8_t> data = {}) {
  return Error{code, subcode, std::move(data)};
}

// NLRI and withdrawn-routes encoding: length byte, then the significant octets.
Error DecodePrefixes(std::span<const uint8_t> in, std::vector<Ipv4Prefix>* out, uint8_t subcode) {
  size_t i = 0;
  while (i < in.size()) {
    const uint8_t len = in[i++];
    const size_t octets = (static_cast<size_t>(len) + 7) / 8;
    if (len > 32 || i + octets > in.size()) return Fail(err::kUpdate, subcode);
    uint32_t addr = 0;
    for (size_t k = 0; k < octets; ++k) addr |= static_cast<uint32_t>(in[i + k]) << (24 - 8 * k);
    i += octets;
    out->push_back(Ipv4Prefix::Make(addr, len));
  }
  return Error{};
}

Error DecodeAsPath(std::span<const uint8_t> v, bool as4, std::vector<AsPathSegment>* out) {
  const size_t asn_size = as4 ? 4 : 2;
  size_t i = 0;
  while (i < v.size()) {
    if (i + 2 > v.size()) return Fail(err::kUpdate, err::kMalformedAsPath);
    AsPathSegment seg;
    seg.type = v[i];
    const size_t count = v[i + 1];
    i += 2;
    if ((seg.type != 1 && seg.type != 2) || count == 0 || i + count * asn_size > v.size()) {
      return Fail(err::kUpdate, err::kMalformedAsPath);
    }
    for (size_t k = 0; k < count; ++k) {
      seg.asns.push_back(as4 ? LoadBe32(v.data() + i) : LoadBe16(v.data() + i));
      i += asn_size;
    }
    out->push_back(std::move(seg));
  }
  return Error{};
}

// Attribute data for error NOTIFICATIONs: flags, type, length and value.
std::vector<uint8_t> AttrData(std::span<const uint8_t> whole_attr) {
  return std::vector<uint8_t>(whole_attr.begin(), whole_attr.end());
}

}  // namespace

std::string ErrorString(uint8_t code, uint8_t subcode) {
  static constexpr const char* kCodes[] = {"",
                                           "message header error",
                                           "OPEN message error",
                                           "UPDATE message error",
                                           "hold timer expired",
                                           "FSM error",
                                           "cease"};
  std::string s = code < 7 ? kCodes[code] : "error " + std::to_string(code);
  return s + " (" + std::to_string(code) + "/" + std::to_string(subcode) + ")";
}

size_t PathAttributes::AsPathLength() const {
  size_t n = 0;
  for (const AsPathSegment& s : as_path) n += s.type == 1 ? 1 : s.asns.size();
  return n;
}

bool PathAttributes::ContainsAs(uint32_t asn) const {
  for (const AsPathSegment& s : as_path) {
    for (uint32_t a : s.asns) {
      if (a == asn) return true;
    }
  }
  return false;
}

uint32_t PathAttributes::FirstAs() const {
  if (as_path.empty() || as_path[0].type != 2 || as_path[0].asns.empty()) return 0;
  return as_path[0].asns[0];
}

std::vector<uint32_t> PathAttributes::Flatten() const {
  std::vector<uint32_t> out;
  for (const AsPathSegment& s : as_path) out.insert(out.end(), s.asns.begin(), s.asns.end());
  return out;
}

std::vector<uint8_t> EncodeOpen(const OpenMessage& open) {
  std::vector<uint8_t> body;
  body.push_back(open.version);
  PutBe16(&body, static_cast<uint16_t>(open.my_as > 0xffff ? kAsTrans : open.my_as));
  PutBe16(&body, open.hold_time);
  PutBe32(&body, open.bgp_id);
  std::vector<uint8_t> caps;
  if (open.cap_mp_ipv4_unicast) {
    caps.insert(caps.end(), {kCapMultiprotocol, 4, 0, 1, 0, 1});  // AFI 1 (IPv4), SAFI 1 (unicast)
  }
  if (open.cap_as4) {
    caps.push_back(kCapAs4);
    caps.push_back(4);
    PutBe32(&caps, open.my_as);
  }
  if (caps.empty()) {
    body.push_back(0);
  } else {
    body.push_back(static_cast<uint8_t>(caps.size() + 2));
    body.push_back(2);  // optional parameter: capabilities
    body.push_back(static_cast<uint8_t>(caps.size()));
    body.insert(body.end(), caps.begin(), caps.end());
  }
  return Message(MessageType::kOpen, body);
}

std::vector<uint8_t> EncodeKeepalive() { return Message(MessageType::kKeepalive, {}); }

std::vector<uint8_t> EncodeNotification(uint8_t code, uint8_t subcode,
                                        std::span<const uint8_t> data) {
  std::vector<uint8_t> body{code, subcode};
  const size_t room = kMaxMessageLen - kHeaderLen - 2;
  body.insert(body.end(), data.begin(),
              data.begin() + static_cast<std::ptrdiff_t>(std::min(room, data.size())));
  return Message(MessageType::kNotification, body);
}

std::vector<std::vector<uint8_t>> EncodeWithdrawals(const std::vector<Ipv4Prefix>& prefixes) {
  std::vector<std::vector<uint8_t>> out;
  const size_t budget = kMaxMessageLen - kHeaderLen - 4;
  size_t i = 0;
  while (i < prefixes.size()) {
    std::vector<uint8_t> withdrawn;
    while (i < prefixes.size() && withdrawn.size() + PrefixWireSize(prefixes[i]) <= budget) {
      PutPrefix(&withdrawn, prefixes[i++]);
    }
    std::vector<uint8_t> body;
    PutBe16(&body, static_cast<uint16_t>(withdrawn.size()));
    body.insert(body.end(), withdrawn.begin(), withdrawn.end());
    PutBe16(&body, 0);
    out.push_back(Message(MessageType::kUpdate, body));
  }
  return out;
}

std::vector<std::vector<uint8_t>> EncodeAnnouncements(const PathAttributes& attrs,
                                                      const std::vector<Ipv4Prefix>& prefixes,
                                                      bool as4) {
  std::vector<std::vector<uint8_t>> out;
  const std::vector<uint8_t> encoded = EncodeAttributes(attrs, as4);
  const size_t fixed = kHeaderLen + 4 + encoded.size();
  if (fixed >= kMaxMessageLen) return out;
  const size_t budget = kMaxMessageLen - fixed;
  size_t i = 0;
  while (i < prefixes.size()) {
    std::vector<uint8_t> nlri;
    while (i < prefixes.size() && nlri.size() + PrefixWireSize(prefixes[i]) <= budget) {
      PutPrefix(&nlri, prefixes[i++]);
    }
    std::vector<uint8_t> body;
    PutBe16(&body, 0);
    PutBe16(&body, static_cast<uint16_t>(encoded.size()));
    body.insert(body.end(), encoded.begin(), encoded.end());
    body.insert(body.end(), nlri.begin(), nlri.end());
    out.push_back(Message(MessageType::kUpdate, body));
  }
  return out;
}

Error DecodeOpen(std::span<const uint8_t> body, OpenMessage* out) {
  *out = OpenMessage{};
  if (body.size() < 10) return Fail(err::kHeader, err::kBadLength);
  out->version = body[0];
  if (out->version != 4) return Fail(err::kOpen, err::kUnsupportedVersion, {0, 4});
  const uint16_t my_as16 = LoadBe16(body.data() + 1);
  out->hold_time = LoadBe16(body.data() + 3);
  out->bgp_id = LoadBe32(body.data() + 5);
  size_t opt_len = body[9];
  size_t pos = 10;
  bool extended = false;
  // RFC 9072: Non-Ext OP Len = 255 and Non-Ext OP Type = 255 announce
  // 2-octet parameter lengths.
  if (opt_len == 255 && body.size() > 10 && body[10] == 255) {
    if (body.size() < 13) return Fail(err::kOpen, 0);
    opt_len = LoadBe16(body.data() + 11);
    pos = 13;
    extended = true;
  }
  if (pos + opt_len != body.size()) return Fail(err::kOpen, 0);
  uint32_t as4_value = 0;
  const size_t end = pos + opt_len;
  while (pos < end) {
    const size_t header = extended ? 3 : 2;
    if (pos + header > end) return Fail(err::kOpen, 0);
    const uint8_t type = body[pos];
    const size_t len = extended ? LoadBe16(body.data() + pos + 1) : body[pos + 1];
    pos += header;
    if (pos + len > end) return Fail(err::kOpen, 0);
    if (type != 2) return Fail(err::kOpen, err::kUnsupportedOptParam);
    size_t c = pos;
    while (c < pos + len) {
      if (c + 2 > pos + len) return Fail(err::kOpen, 0);
      const uint8_t code = body[c];
      const size_t clen = body[c + 1];
      c += 2;
      if (c + clen > pos + len) return Fail(err::kOpen, 0);
      if (code == kCapMultiprotocol && clen == 4 && LoadBe16(body.data() + c) == 1 &&
          body[c + 3] == 1) {
        out->cap_mp_ipv4_unicast = true;
      } else if (code == kCapAs4 && clen == 4) {
        out->cap_as4 = true;
        as4_value = LoadBe32(body.data() + c);
      }
      c += clen;  // other capabilities (graceful restart, add-path, FQDN, ...) are ignored
    }
    pos += len;
  }
  out->my_as = out->cap_as4 ? as4_value : my_as16;
  if (out->hold_time == 1 || out->hold_time == 2) {
    return Fail(err::kOpen, err::kUnacceptableHoldTime);
  }
  if (out->bgp_id == 0) return Fail(err::kOpen, err::kBadBgpId);
  return Error{};
}

Error DecodeUpdate(std::span<const uint8_t> body, bool as4, UpdateMessage* out) {
  *out = UpdateMessage{};
  if (body.size() < 4) return Fail(err::kUpdate, err::kMalformedAttrList);
  const size_t withdrawn_len = LoadBe16(body.data());
  if (2 + withdrawn_len + 2 > body.size()) return Fail(err::kUpdate, err::kMalformedAttrList);
  Error e = DecodePrefixes(body.subspan(2, withdrawn_len), &out->withdrawn, err::kInvalidNetwork);
  if (!e.ok()) return e;
  const size_t attr_len = LoadBe16(body.data() + 2 + withdrawn_len);
  const size_t attr_start = 4 + withdrawn_len;
  if (attr_start + attr_len > body.size()) return Fail(err::kUpdate, err::kMalformedAttrList);
  out->has_attributes = attr_len > 0;

  bool seen[256] = {};
  size_t i = attr_start;
  const size_t attr_end = attr_start + attr_len;
  while (i < attr_end) {
    if (i + 3 > attr_end) return Fail(err::kUpdate, err::kMalformedAttrList);
    const uint8_t flags = body[i];
    const uint8_t type = body[i + 1];
    const bool ext = (flags & kAttrFlagExtendedLength) != 0;
    if (ext && i + 4 > attr_end) return Fail(err::kUpdate, err::kMalformedAttrList);
    const size_t len = ext ? LoadBe16(body.data() + i + 2) : body[i + 2];
    const size_t hdr = ext ? 4 : 3;
    if (i + hdr + len > attr_end) return Fail(err::kUpdate, err::kMalformedAttrList);
    const std::span<const uint8_t> whole = body.subspan(i, hdr + len);
    const std::span<const uint8_t> v = body.subspan(i + hdr, len);
    i += hdr + len;
    if (seen[type]) return Fail(err::kUpdate, err::kMalformedAttrList);
    seen[type] = true;

    const bool optional = (flags & kAttrFlagOptional) != 0;
    const bool transitive = (flags & kAttrFlagTransitive) != 0;
    const auto well_known = [&] {
      return !optional && transitive && (flags & kAttrFlagPartial) == 0;
    };
    switch (type) {
      case kOrigin:
        if (!well_known()) return Fail(err::kUpdate, err::kAttrFlags, AttrData(whole));
        if (len != 1) return Fail(err::kUpdate, err::kAttrLength, AttrData(whole));
        if (v[0] > 2) return Fail(err::kUpdate, err::kInvalidOrigin, AttrData(whole));
        out->attrs.origin = static_cast<Origin>(v[0]);
        break;
      case kAsPath:
        if (!well_known()) return Fail(err::kUpdate, err::kAttrFlags, AttrData(whole));
        e = DecodeAsPath(v, as4, &out->attrs.as_path);
        if (!e.ok()) return e;
        break;
      case kNextHop: {
        if (!well_known()) return Fail(err::kUpdate, err::kAttrFlags, AttrData(whole));
        if (len != 4) return Fail(err::kUpdate, err::kAttrLength, AttrData(whole));
        const uint32_t nh = LoadBe32(v.data());
        if (nh == 0 || nh == 0xffffffffu || (nh >> 28) == 0xe) {
          return Fail(err::kUpdate, err::kInvalidNextHop, AttrData(whole));
        }
        out->attrs.next_hop = nh;
        break;
      }
      case kMed:
        if (!optional || transitive) return Fail(err::kUpdate, err::kAttrFlags, AttrData(whole));
        if (len != 4) return Fail(err::kUpdate, err::kAttrLength, AttrData(whole));
        out->attrs.med = LoadBe32(v.data());
        break;
      case kLocalPref:
        if (optional) return Fail(err::kUpdate, err::kAttrFlags, AttrData(whole));
        if (len != 4) return Fail(err::kUpdate, err::kAttrLength, AttrData(whole));
        out->attrs.local_pref = LoadBe32(v.data());
        break;
      case kAtomicAggregate:
        if (len != 0) return Fail(err::kUpdate, err::kAttrLength, AttrData(whole));
        out->attrs.atomic_aggregate = true;
        break;
      case kCommunities:
        if (len % 4 != 0) return Fail(err::kUpdate, err::kOptionalAttr, AttrData(whole));
        for (size_t k = 0; k < len; k += 4)
          out->attrs.communities.push_back(LoadBe32(v.data() + k));
        break;
      default:
        // Unknown optional attributes (aggregator, AS4_PATH, MP_REACH, ...) are
        // ignored; an unknown well-known attribute is an error.
        if (!optional) return Fail(err::kUpdate, err::kUnrecognizedWellKnown, AttrData(whole));
        break;
    }
  }

  e = DecodePrefixes(body.subspan(attr_end), &out->nlri, err::kInvalidNetwork);
  if (!e.ok()) return e;
  if (!out->nlri.empty()) {
    for (uint8_t required : {kOrigin, kAsPath, kNextHop}) {
      if (!seen[required]) return Fail(err::kUpdate, err::kMissingWellKnown, {required});
    }
  }
  return Error{};
}

Error DecodeNotification(std::span<const uint8_t> body, NotificationMessage* out) {
  if (body.size() < 2) return Fail(err::kHeader, err::kBadLength);
  out->code = body[0];
  out->subcode = body[1];
  out->data.assign(body.begin() + 2, body.end());
  return Error{};
}

void MessageReader::Append(std::span<const uint8_t> data) {
  // Compact consumed bytes before growing, so the buffer stays bounded.
  if (offset_ > 0 && offset_ == buffer_.size()) {
    buffer_.clear();
    offset_ = 0;
  } else if (offset_ > 65536) {
    buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(offset_));
    offset_ = 0;
  }
  buffer_.insert(buffer_.end(), data.begin(), data.end());
}

bool MessageReader::Next(MessageType* type, std::vector<uint8_t>* body, Error* error) {
  *error = Error{};
  const size_t avail = buffer_.size() - offset_;
  if (avail < kHeaderLen) return false;
  const uint8_t* h = buffer_.data() + offset_;
  for (size_t i = 0; i < 16; ++i) {
    if (h[i] != 0xff) {
      *error = Fail(err::kHeader, err::kNotSynchronized);
      return false;
    }
  }
  const uint16_t len = LoadBe16(h + 16);
  const uint8_t t = h[18];
  bool length_ok = len >= kHeaderLen && len <= kMaxMessageLen;
  switch (t) {
    case static_cast<uint8_t>(MessageType::kOpen):
      length_ok = length_ok && len >= kHeaderLen + 10;
      break;
    case static_cast<uint8_t>(MessageType::kUpdate):
      length_ok = length_ok && len >= kHeaderLen + 4;
      break;
    case static_cast<uint8_t>(MessageType::kNotification):
      length_ok = length_ok && len >= kHeaderLen + 2;
      break;
    case static_cast<uint8_t>(MessageType::kKeepalive):
      length_ok = length_ok && len == kHeaderLen;
      break;
    default:
      *error = Fail(err::kHeader, err::kBadType, {t});
      return false;
  }
  if (!length_ok) {
    *error = Fail(err::kHeader, err::kBadLength, {h[16], h[17]});
    return false;
  }
  if (avail < len) return false;
  *type = static_cast<MessageType>(t);
  body->assign(h + kHeaderLen, h + len);
  offset_ += len;
  return true;
}

}  // namespace nanonos::bgp
