# Managed dual-stack rtnetlink fixture

These records were captured on 2026-09-07 from Linux 6.18.44 in a fresh
user-owned network namespace using the AOS iproute2 6.18.0 package:

    /nix/store/1lj55s8mgia4189djcvfyafq6z703jc1-iproute2-6.18.0/sbin/ip

The exact setup inside the outer unshare was:

    unshare --net sleep 120 &
    child=$!
    ip link add aoh000000000001 type veth peer name aog000000000001
    ip link set aog000000000001 netns "$child"
    ip link set dev aoh000000000001 addrgenmode none
    ip link set dev aoh000000000001 address 02:aa:bb:00:00:02 mtu 1500 up
    ip address add 192.0.2.0/31 dev aoh000000000001
    ip -6 address add 2001:db8::/127 dev aoh000000000001
    nsenter -t "$child" -n ip link set lo up
    nsenter -t "$child" -n ip link set dev aog000000000001 addrgenmode none
    nsenter -t "$child" -n ip link set dev aog000000000001 \
      address 02:aa:bb:00:00:03 mtu 1500 up
    nsenter -t "$child" -n ip address add \
      192.0.2.1/31 dev aog000000000001
    nsenter -t "$child" -n ip -6 address add \
      2001:db8::1/127 dev aog000000000001
    sleep 2
    nsenter -t "$child" -n ip route add \
      203.0.113.0/24 via 192.0.2.0 dev aog000000000001 \
      proto static src 192.0.2.1
    nsenter -t "$child" -n ip -6 route add \
      2001:db8:1::/64 via 2001:db8:: dev aog000000000001 \
      proto static src 2001:db8::1

The six sandbox commands were:

    ip -j -details link show
    ip -j address show
    ip -j -4 route show table all
    ip -j -6 route show table all
    ip -j -4 rule show
    ip -j -6 rule show

The outer setup was run beneath:

    unshare --user --map-root-user --mount --net

Here, each ip token in the transcript denotes the fixed store executable shown
above. The fixture is host-kernel observation evidence, not AOS guest
qualification and not proof that PID-based namespace selection is safe for the
production broker.
