# Worked network fixture

`crucible campaign fixture worked-network` generates the reference campaign
used to exercise the whole model end to end: a routed network product that
chooses its recovery strategy in the guest while Crucible independently shapes
the network disruption. It is built in
`crucible-cli/src/cli/campaign/fixture.rs` through the same typed constructors
and artifact verifier used by campaign import, and it writes an owner-only
import set that it revalidates before reporting success. Operator steps for
generating, validating, and running it are in
[Operating lazy campaigns](../../../users/crucible/campaigns.md#build-and-validate-inputs).

## Question under test

After a transport disruption, the product receives a fault signal and may
alter its recovery strategy; the environment may vary the disruption and later
faults. The campaign asks which combinations recover fastest without
blackholes or control-plane instability, which good first responses remain
robust under a second fault, and which combinations are Pareto-optimal for
convergence time, packet loss, and control-plane work. It is a search, not a
population estimate.

## Topology and boundaries

Three routers (`router-a`, `router-b`, `router-c`) and two traffic endpoints
(`traffic-west`, `traffic-east`):

```text
traffic-west -- router-a ==primary== router-b ==primary== router-c -- traffic-east
                    \__________________backup__________________/
```

The A-B and B-C segments form the `primary` fault domain and A-C the `backup`
domain; each domain names both directed sides of its links. The endpoint
attachments are outside every fault domain, so a branch can disrupt the route
while keeping its traffic source and sink.

Declared semantic boundaries:

| Boundary | Meaning |
| --- | --- |
| `network.converged` | Initial routing and forwarding invariants hold |
| `fault.transport.ready` | Every participant is quiescent just before the first disruption |
| `fault.transport.signaled` | The fault signal has been delivered |
| `recovery.measured` | The first recovery window has ended and measurements are committed |
| `network.failover.observed` | West received a sequenced response through the A-C backup route |
| `fault.followup.ready` | Survivors are eligible for a second disruption |
| `campaign.complete` | Terminal properties and measurements are committed |

`fault.transport.ready` and `fault.followup.ready` are fork-safe scenario
boundaries: the host verifies that every VM, the virtual fabric, observation
streams, and logical time have reached them.

## Selectables

The guest on `router-a` registers one atomic group, `recovery.response`, as a
Cartesian product of four members:

| Member | Domain | Default |
| --- | --- | --- |
| `recovery.strategy` | `retain_and_probe`, `withdraw_then_relearn`, `restart_adjacency`, `recompute_all`, `unsafe_short_circuit` | `retain_and_probe` |
| `recovery.hold_down_us` | unsigned `[0, 5_000_000]` µs | 20,000 |
| `recovery.retry_limit` | unsigned `[0, 12]` count | 3 |
| `recovery.fast_reroute` | Boolean | `true` |

The environment owns one `fault.network` group opportunity at each verified
network phase boundary (`crucible_engine::decision::network_fault_selectable`):

| Member | Domain | Default |
| --- | --- | --- |
| `fault.kind` | `link_down`, `packet_loss`, `latency_step`, `asymmetric_partition` | `packet_loss` |
| `fault.affected_path` | `primary`, `backup`, `both` | `primary` |
| `fault.duration_us` | `[1_000, 30_000_000]` µs, landmarks 1,000 / 1,000,000 / 30,000,000 | 1,000,000 |
| `fault.loss_bps` | `[0, 10_000]` basis points, landmarks 0 / 100 / 1,000 / 10,000 | 0 |
| `fault.latency_us` | `[0, 2_000_000]` µs, landmarks 0 / 1,000 / 100,000 / 2,000,000 | 0 |

Kind-dependent constraints force inactive parameters to zero: loss and latency
for `link_down` and `asymmetric_partition`, latency for `packet_loss`, and
loss for `latency_step`. First and follow-up disruptions use the same
declaration but distinct phase identities, so they produce different
opportunity IDs and exact replay parents.

## Measurements and properties

Guest and model measurements include `recovery_time_us`,
`traffic_loss_packets`, and `control_plane_cpu_us`. The
`network.failover.observed` marker carries typed `path` and `sequence`
details from the measured west response. Hard safety properties are evaluated
alongside, and a property violation creates a finding rather than a poor
score.

## Policy

| Setting | Value |
| --- | --- |
| Mode | `Strict` |
| Explorer | `TreeSearch` with PUCT weights 1.4 (exploration), 0.25 (novelty), 0.1 (fairness) |
| Widening | `k = 2`, `alpha = 1/2`, 4 initial children, at most 4,096, one completed visit per child |
| Generator | `GroupProgressive`, at most 4,096 tuples, for both groups |
| Objectives | Minimize `recovery_time_us.elapsed_virtual_time`, `traffic_loss_packets.modeled_drop_count`, and `control_plane_cpu_us.router_a_instruction_work` |
| Guidance | Coverage, weight 0.25 |
| Stop condition | `campaign.complete` |

## Boot artifacts

Without boot options the fixture's VM records carry no kernel or root-image
references; it exercises import, creation, and the control plane only. Passing
`--kernel`, `--root-image`, `--qemu`, and `--plugin` (the AOS kernel, the
`crucible-envoy-network-guest` `root.ext4`, and the matched packaged QEMU and
plugin) hashes the boot files into portable scenario references, gives each
node its Envoy role and boot arguments, authenticates the QEMU and plugin build
markers, and binds the lineage to that build and to the current control and
shared-memory protocol versions. Campaign import stores the scenario and
schedule only; the boot files remain deployment inputs to the executor, which
must use the same immutable files and QEMU/plugin pair. The guest image is described in
[`tests/crucible/fixtures/envoy-network`](../../../../tests/crucible/fixtures/envoy-network/README.md),
and the five-VM product is exercised by `gate:campaign-envoy-network-five-vm`,
`gate:campaign-envoy-known-finding`, and
`gate:campaign-envoy-product-lifecycle`.
