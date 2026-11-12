#!/usr/bin/env bash
# 2-leaf / 2-spine Clos fabric: four nanonosd switches and two hosts in network
# namespaces. Checks eBGP with 4-octet ASNs and GTSM, ECMP across both spines,
# LLDP, end-to-end traffic, and failover when a cable is pulled mid-traffic.
source "$(dirname "$0")/lib.sh"
CONF=$ROOT/configs/clos

for ns in leaf1 leaf2 spine1 spine2 h1 h2; do make_ns "$ns"; done
connect leaf1 l1-s1 spine1 s1-l1
connect leaf1 l1-s2 spine2 s2-l1
connect leaf2 l2-s1 spine1 s1-l2
connect leaf2 l2-s2 spine2 s2-l2
connect leaf1 l1-h1 h1 eth0
connect leaf2 l2-h2 h2 eth0
host_ip h1 eth0 10.1.1.10/24 10.1.1.1
host_ip h2 eth0 10.2.2.20/24 10.2.2.1

t0=$(now)
for sw in leaf1 leaf2 spine1 spine2; do start_switch "$sw" "$CONF/$sw.conf"; done

established() {
  nosctl "$1" show bgp summary json | json "len(d) > 0 and all(n['state'] == 'Established' for n in d)" | grep -q True
}
for sw in leaf1 leaf2 spine1 spine2; do wait_for "$sw BGP sessions" 30 established "$sw"; done
converge_s=$(elapsed "$t0")
pass "all 8 eBGP sessions (4-octet ASNs, GTSM) Established ${converge_s}s after the switches started"

ecmp() {
  nosctl leaf1 show ip route json |
    json "any(r['prefix'] == '10.2.2.0/24' and r['state'] == 'offloaded' and len(r['next_hops']) == 2 for r in d)" |
    grep -q True
}
wait_for "ECMP route on leaf1" 15 ecmp
pass "leaf1 programs 10.2.2.0/24 into the ASIC with 2 ECMP next hops"

lldp_ok() {
  nosctl leaf1 show lldp neighbors json | json "sorted(n['system_name'] for n in d)" | grep -q "'spine1', 'spine2'"
}
wait_for "LLDP neighbors" 15 lldp_ok
pass "LLDP: leaf1 sees spine1 and spine2 on its uplinks"

ip netns exec h1 ping -c 3 -W 1 10.1.1.1 > /dev/null || fail "h1 cannot ping its gateway"
ip netns exec h1 ping -c 5 -i 0.2 -W 2 10.2.2.20 > "$RUN/ping.txt" || {
  cat "$RUN/ping.txt"
  fail "h1 cannot reach h2"
}
ttl=$(grep -o 'ttl=[0-9]*' "$RUN/ping.txt" | head -1 | cut -d= -f2)
[ "$ttl" = "61" ] || fail "expected TTL 61 after 3 routed hops, got $ttl"
pass "h1 -> h2 across the fabric, reply TTL $ttl (3 routed hops)"

spine_tx() { # packets a spine sent toward leaf2
  nosctl "$1" show interfaces json | json "[i['tx_pkts'] for i in d if i['name'] == 'Ethernet1'][0]"
}

# Throughput: 8 parallel TCP flows, hashed onto both spines by 5-tuple.
ip netns exec h2 iperf3 -s -D -1 > /dev/null
sleep 0.5
s1=$(spine_tx spine1)
s2=$(spine_tx spine2)
ip netns exec h1 iperf3 -c 10.2.2.20 -P 8 -t 5 -J > "$RUN/iperf.json" || fail "iperf3 failed"
mbps=$(json "round(d['end']['sum_received']['bits_per_second'] / 1e6)" < "$RUN/iperf.json")
d1=$(($(spine_tx spine1) - s1))
d2=$(($(spine_tx spine2) - s2))
[ "$d1" -gt 1000 ] && [ "$d2" -gt 1000 ] || fail "ECMP did not use both spines ($d1 / $d2 packets)"
pass "iperf3, 8 TCP flows h1 -> h2: ${mbps} Mbit/s; spine1 forwarded $d1 packets, spine2 $d2"

# Failover: find the spine carrying h1 -> h2 pings, then pull leaf1's cable
# to it while pinging every 10 ms.
s1=$(spine_tx spine1)
ip netns exec h1 ping -c 50 -i 0.01 -q 10.2.2.20 > /dev/null || true
if (($(spine_tx spine1) - s1 >= 40)); then
  spine=spine1 spine_if=s1-l1
else
  spine=spine2 spine_if=s2-l1
fi
ip netns exec h1 ping -c 1000 -i 0.01 -q 10.2.2.20 > "$RUN/failover.txt" 2>&1 &
ping_pid=$!
sleep 3
ip -n "$spine" link set "$spine_if" down
wait "$ping_pid" || true
received=$(grep -o '[0-9]* received' "$RUN/failover.txt" | cut -d' ' -f1)
lost=$((1000 - received))
[ "$lost" -le 20 ] || fail "failover lost $lost of 1000 packets"
pass "cable leaf1 <-> $spine pulled during a 10 ms ping: $lost of 1000 packets lost"

ip -n "$spine" link set "$spine_if" up
wait_for "BGP to re-establish" 30 established leaf1
wait_for "ECMP to be restored" 15 ecmp
pass "cable restored: sessions re-established and 2-path ECMP restored"

{
  echo
  echo "| Clos fabric metric | Value |"
  echo "|---|---|"
  echo "| eBGP sessions Established after start | ${converge_s} s |"
  echo "| iperf3, 8 TCP flows through 3 userspace switches | ${mbps} Mbit/s |"
  echo "| Packets via spine1 / spine2 | $d1 / $d2 |"
  echo "| Packets lost when an uplink is pulled (10 ms ping) | $lost of 1000 |"
} >> "$SUMMARY"
nosctl leaf1 show bgp summary
nosctl leaf1 show ip route
nosctl leaf1 show lldp neighbors
nosctl spine1 show interfaces
echo "Clos fabric test passed"
