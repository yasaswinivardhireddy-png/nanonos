#!/usr/bin/env bash
# Layer-2 switching on Linux: MAC learning, VLAN isolation and an 802.1Q trunk.
source "$(dirname "$0")/lib.sh"

for ns in sw h1 h2 h3 h4; do make_ns "$ns"; done
connect sw sw-h1 h1 eth0
connect sw sw-h2 h2 eth0
connect sw sw-h3 h3 eth0
connect sw sw-h4 h4 eth0
ip -n h1 addr add 10.10.0.1/24 dev eth0
ip -n h2 addr add 10.10.0.2/24 dev eth0
ip -n h3 addr add 10.10.0.3/24 dev eth0 # VLAN 20: must stay isolated from VLAN 10
# h4 sits behind the trunk: VLAN 10 arrives tagged on eth0.10.
ip -n h4 link add link eth0 name eth0.10 type vlan id 10
ip -n h4 addr add 10.10.0.4/24 dev eth0.10
ip -n h4 link set eth0.10 up

start_switch sw "$ROOT/configs/l2/switch.conf"

ip netns exec h1 ping -c 3 -W 1 10.10.0.2 > /dev/null || fail "h1 -> h2 in VLAN 10"
pass "bridging within VLAN 10 (h1 -> h2)"
ip netns exec h1 ping -c 3 -W 1 10.10.0.4 > /dev/null || fail "h1 -> h4 over the 802.1Q trunk"
pass "802.1Q trunk: h1 (access port) <-> h4 (tagged VLAN 10)"
if ip netns exec h1 ping -c 2 -W 1 10.10.0.3 > /dev/null 2>&1; then
  fail "a VLAN 20 host answered from VLAN 10"
fi
pass "VLAN isolation: h3 in VLAN 20 is unreachable from VLAN 10"

macs=$(nosctl sw show mac json | json "len([e for e in d if e['vlan'] == 10])")
[ "$macs" -ge 3 ] || fail "expected at least 3 MACs learned in VLAN 10, got $macs"
pass "MAC learning: $macs entries in VLAN 10"

ip netns exec h2 iperf3 -s -D -1 > /dev/null
sleep 0.5
ip netns exec h1 iperf3 -c 10.10.0.2 -t 3 -J > "$RUN/iperf.json" || fail "iperf3 failed"
mbps=$(json "round(d['end']['sum_received']['bits_per_second'] / 1e6)" < "$RUN/iperf.json")
pass "iperf3 h1 -> h2 bridged: ${mbps} Mbit/s"
nosctl sw show mac
nosctl sw show interfaces
echo "L2 test passed"
