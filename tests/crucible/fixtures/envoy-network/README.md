# Five-node Envoy network guest

`nix build .#crucible-envoy-network-guest` builds one immutable `root.ext4` for
all five Crucible VMs. Each VM boots the AOS Linux kernel with
`root=/dev/vda init=/init console=ttyS0 network.role=NAME`, where `NAME` is one
of `router-a`, `router-b`, `router-c`, `traffic-west`, or `traffic-east`. The
QEMU world must give each VM a branch-private writable overlay of the immutable
image. This is the same root-image arrangement as the packaged Crucible flights.

The modeled fabric has these bidirectional links:

```text
traffic-west -- router-a -- router-b -- router-c -- traffic-east
                   \_________________________/
```

All nodes use one NIC on `10.77.0.0/24`, with addresses `.1` through `.5` in
the order west, A, B, C, east. Envoy A normally proxies through B; B proxies
through C; C proxies to nginx on east. Envoy A has C as a health-checked backup.
The east response echoes its request sequence and the route-hop headers that
the three Envoys inserted. West sends continuous concurrent requests and checks
each response against its sequence and permitted path.

Router A registers `recovery.strategy`, `recovery.hold_down_us`,
`recovery.retry_limit`, and `recovery.fast_reroute` with the public
`crucible-guest` typed-choice CLI. The choice changes its live Envoy route,
backup availability, retry policy, restart, or hold-down time. The explicit
`unsafe_short_circuit` strategy returns a successful response from A without
reaching east; west reports it as a `forbidden-destination-delivery` finding.
West reports request failures, per-request identity violations, repeated route
hops, and concurrent response-completion inversions. Completion inversions are
application observations; packet-order claims need the modeled fabric's own
evidence.

The campaign materializer must bind its typed environment fault choices to
Crucible's modeled network adapters and deliver the RFC-0014 fault signal at
the transport boundary. The guest image does not inject host-side faults.

The guest-to-guest readiness channel uses A's port 9090 on the modeled fabric.
West sends `converged` after a successful A-B-C-east request. A then emits
`fault.transport.ready`. West keeps sending requests while A receives and
applies its first recovery choice, then begins the 120-request measurement
window. West commits the measurement and sends `followup-ready`; A emits
`fault.followup.ready` before requesting the second recovery choice. The guest
monitor continues traffic after `campaign.complete` so a retained child still
has an active workload.

`nix build .#checks.x86_64-linux.crucible-envoy-network-smoke` runs AOS-built
Envoy and nginx on loopback. It verifies the initial three-proxy route, the
A-to-C backup after B exits, and the unsafe direct response. The smoke check
does not substitute for a five-VM QEMU campaign run or the independent operator
flight in RFC-0020 §14.
