#!/usr/bin/env bash
# Interoperability with FRRouting's bgpd: an eBGP session protected by TCP-MD5
# (RFC 2385), routes exchanged in both directions.
source "$(dirname "$0")/lib.sh"
[ -x /usr/lib/frr/bgpd ] || fail "FRRouting is not installed (apt-get install frr)"

make_ns sw
make_ns frr
connect sw sw-frr frr eth0
ip -n frr addr add 10.0.0.1/31 dev eth0

cat > "$RUN/sw.conf" << 'EOF'
hostname nanonos1
interface Ethernet0
  port sw-frr
  ip address 10.0.0.0/31
router bgp 4200000001
  router-id 10.255.0.1
  timers 1 3
  network 10.1.1.0/24
  neighbor 10.0.0.1 remote-as 65002
  neighbor 10.0.0.1 description frr
  neighbor 10.0.0.1 password interop-md5-key
EOF

FRR=$RUN/frr
mkdir -p "$FRR"
cat > "$FRR/bgpd.conf" << 'EOF'
hostname frr1
log file /tmp/nanonos-test/frr/bgpd.log debugging
router bgp 65002
 bgp router-id 10.255.0.2
 no bgp ebgp-requires-policy
 no bgp network import-check
 timers bgp 1 3
 neighbor 10.0.0.0 remote-as 4200000001
 neighbor 10.0.0.0 password interop-md5-key
 address-family ipv4 unicast
  network 10.99.0.0/16
 exit-address-family
EOF
chown -R frr:frr "$FRR"
ip netns exec frr /usr/lib/frr/zebra -d -i "$FRR/zebra.pid" -z "$FRR/zserv.api" --vty_socket "$FRR" -u frr -g frr
ip netns exec frr /usr/lib/frr/bgpd -d -f "$FRR/bgpd.conf" -i "$FRR/bgpd.pid" -z "$FRR/zserv.api" --vty_socket "$FRR" -u frr -g frr
cleanup_frr() {
  for p in "$FRR"/*.pid; do [ -e "$p" ] && kill "$(cat "$p")" 2> /dev/null; done
  cleanup
}
trap cleanup_frr EXIT

start_switch sw "$RUN/sw.conf"

established() {
  nosctl sw show bgp summary json | json "d[0]['state'] == 'Established' and d[0]['prefixes_received'] == 1" | grep -q True
}
wait_for "the FRR session" 30 established
pass "eBGP session with FRR bgpd Established, authenticated with TCP-MD5"

installed() {
  nosctl sw show ip route json |
    json "any(r['prefix'] == '10.99.0.0/16' and r['next_hops'] == ['10.0.0.1'] and r['state'] == 'offloaded' for r in d)" |
    grep -q True
}
wait_for "FRR's route in the ASIC" 10 installed
pass "route 10.99.0.0/16 learned from FRR and offloaded to the ASIC"

frr_received() {
  ip netns exec frr vtysh --vty_socket "$FRR" -c 'show bgp ipv4 unicast summary json' |
    json "d.get('ipv4Unicast', d)['peers']['10.0.0.0']['pfxRcd'] == 1" | grep -q True
}
wait_for "FRR to accept our route" 10 frr_received
pass "FRR accepted 10.1.1.0/24 from NanoNOS (4-octet AS path 4200000001)"

ip netns exec frr vtysh --vty_socket "$FRR" -c 'show bgp ipv4 unicast' || true
nosctl sw show bgp summary
echo "FRR interop test passed"
