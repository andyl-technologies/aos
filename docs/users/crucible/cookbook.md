# Fault experiment cookbook

These recipes show how Crucible pieces fit together. They are adapter-neutral
patterns, not hand-written canonical TOML: build the listed model values through
Rust, resolve the plan against the World, and serialize with
`ScenarioDefForm::to_canonical_toml` so all identities are correct.

Every recipe begins with an unfaulted baseline, explicit seed, virtual-time and
quantum bounds, and a retained canonical trace.

## Scheduled outage and recovery

Use this for a deterministic partition, device outage, or service maintenance
window.

```text
virtual-time pulse/step (Boolean)
  -> boundary sampling
  -> active_when_true
  -> exact target or fault domain
  -> persistent availability/hang contribution
```

For network availability declare directional state plus queued/in-flight
policy. For storage choose online/offline/read-only/degraded plus reconnect
policy. For a hang declare recovery event/watchdog behavior. Assert adapter
state transition, then an `eventually` application-ready marker with a deadline.

Replay the failure artifact once, then vary only the pulse coordinates or
recovery policy. Do not model a continuous outage as repeated independent loss.

## Per-operation probabilistic failure

Use this for frame loss or typed I/O failure.

```text
bernoulli source keyed by opportunity
  -> at_opportunity sampling with exact operation/phase filter
  -> hazard mapping
  -> opportunity-lifetime loss/failure effect
```

The selector names the physical target and the filter limits operations. A
network binding might select transmit/receive opportunities; storage limits the
operation set and supplies a typed status artifact. Assert a positive path
witness so “nothing happened” cannot pass the test, then assert the required
application outcome.

Use `branch_outcome` only with the hazard mapping and a finite maximum. Finding
artifacts retain fired/not-fired choices by stable opportunity identity.

## Correlated burst failures

Use a `burst_process` signal or the adapter's explicit burst state effect when
failures cluster.

Declare exact good-to-bad and bad-to-good probabilities and the opportunity
identity. The state is checkpointed; a save/resume during a bad burst must not
restart in the good state. Assert both the correlated decision evidence and the
system's bounded recovery/error budget.

Choose one layer for correlation. Combining a burst signal with a separate
burst adapter state can unintentionally create two state machines.

## Congestion and bounded service

Use topology queues plus service effects rather than only adding latency.

1. Declare queue owner, byte/frame or request capacity, service resource, and
   baseline policy.
2. Bind a persistent `network.queue_policy`, `network.service_curve`,
   `network.token_bucket`, `storage.service`, `memory.service`, or accelerator
   service request.
3. Choose `queue` opportunities and the registry lifetime/composition.
4. Assert occupancy/overflow/service-ledger evidence and an end-to-end deadline.

Service composition selects the most restrictive active cap while preserving
all contributors. Overflow outcome is explicit and may differ from timeout.
Checkpoint/replay retains occupancy, tokens, and integration coordinates.

## Data corruption with provenance

Use ordered transforms for frame, block-read, register, memory, or accelerator
data mutation.

The selector must identify a bounded field/range and the effect must run at a
legal phase. Evidence retains before/after digests (and bytes where required),
selector, occurrence, and canonical transform order. For memory/register
targets, the QEMU capability manifest must authorize the exact address/register
and writable phase.

Assert the adapter mutation separately from guest detection/recovery. If the
guest is expected to reject corrupted data, a missing success marker alone is
not sufficient; require an explicit error/health marker by a deadline.

## Crash plus volatile storage loss

Model one shared power cause and bind it to multiple targets:

- `node.lifecycle` impulse/state transition with RAM and device-state policy;
- `storage.volatile_cache_loss` impulse selecting eligible unprotected entries;
- optional controller/forwarder lifecycle transition with explicit queued-work
  and retained-state policy.

All bindings consume the same event signal but retain independent effect
evidence. The ordering and exact durable frontier are recorded. After restart,
assert guest-visible recovered state, not merely node liveness.

The certified shared-cause Rust example implements this recipe end to end.

## Recorded environmental exposure

Use this for temperature, RF attenuation, vibration, mobility, or other
externally measured causes.

1. Import raw CSV/JSONL/PCAP/PCAPNG through the Rust importer.
2. Retain raw provenance and normalized manifest/chunks in a DAG store.
3. Add a `trace`, spatial, or transmitter-field source with explicit unit,
   interpolation, boundary, missing, quality, and time mapping.
4. Derive the fault parameter through typed pure/stateful nodes.
5. Supply the object closure to the production lifecycle and bind the output.

For exploration, declare finite trace-window or mapping-point mutations.
Crucible materializes exact candidates; it never synthesizes unspecified
measurements. Replay authenticates normalized and raw provenance identities.

## Hardware fault at a precise opportunity

Use exact node capability declarations and an opportunity filter:

```text
event or keyed operation signal
  -> at_event / at_opportunity
  -> impulse_on_event / hazard / parameter mapping
  -> exact register, memory, interrupt, clock, or accelerator target
  -> registry-approved QEMU phase
```

Admission checks CPU model, register mask, memory/address translation, DRAM
geometry, interrupt route, clock source, or accelerator manifest. QEMU then
acknowledges the exact effect and retains architecture evidence. A schema-valid
target not advertised by the realized machine is rejected before execution.

## Array degradation and rebuild

Declare the complete storage array first: layout, members and ordinals, paths,
capacity/chunk geometry, read/write quorum, selection, consistency, rebuild
service, and typed no-quorum result. Then apply `storage.array_state` as one
state transition replacing the five baseline policy references.

Assert selected members, degraded/quorum state, rebuild progress and durability,
then the application's availability or consistency result. Rebuild consumes
bounded modeled service and its progress survives checkpoints.

## Contact windows and custody

For disrupted/delay-tolerant networks, declare contact intervals, range-delay
lookup, beams/gateways, custody policy, capacity, expiry, route/contact plan,
priority, hop limit, and service policy. Bind `network.contact` for availability
and `network.custody_queue` for durable queue/routing state.

Assert contact acquisition/teardown and custody transitions separately from
eventual application delivery. Expiry, overflow, no-route, and timeout are
distinct modeled outcomes.

## Search, minimize, and hand off any recipe

Start with a fixed binding and prove deterministic `verify`. Then expose only
the specific schedule/fault dimensions needed for the question. Set depth and
state budgets, retain the findings ledger, replay each retained artifact on the
ordinary production backend, and triage/minimize equivalent failures.

For handoff, provide scenario, seed, canonical trace, reproduction artifact,
backend identity, and the property/message that failed. See
[Stores and artifacts](artifacts.md) for the retention contract.

