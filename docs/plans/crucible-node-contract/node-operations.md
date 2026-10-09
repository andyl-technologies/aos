# Installed node observation commands

`crucible node` exposes a separate versioned local daemon interface for installed
node profiles. The current catalog runs isolated host clocks and output-only
closed-ingress checksum smoke profiles. The separate public CNP reference
provider's input/output profile is exercised by the vendor conformance suite.
This catalog compiles complete mixed scenarios using the actual owning
daemon's implementation identities, reserves an independent execution nonce,
and retains incoming/outgoing provenance and result evidence in durable storage.

Create an operator-owned mode-0700 state directory and install a policy JSON:

```json
{
  "format":"crucible.node-daemon-policy",
  "version":1,
  "state_directory":"/absolute/private/node-state",
  "socket":"/absolute/private/node-state/node.sock",
  "device_executable":"/absolute/installed/crucible-reference-device",
  "expected_device":{
    "hash":{
      "algorithm":"blake3-256",
      "domain":"cnp.blob.v1",
      "digest":"EXPECTED_PACKAGE_ARTIFACT_DIGEST"
    },
    "length":"EXPECTED_PACKAGE_ARTIFACT_LENGTH",
    "media_type":"application/octet-stream"
  },
  "control_timeout_ms":3000,
  "maximum_worlds":2,
  "maximum_pending_requests":4
}
```

Supply `expected_device` from the independently authenticated source-package
inventory. The daemon measures the selected installed executable and requires
an exact match; client requests cannot replace policy or supply qualification.
The illustrative digest and length placeholders must be replaced by the actual
complete CNP ContentRef. Start the daemon with:

```text
crucible node serve --policy installed-node-policy.json
```

Author a closed selection array:

```json
[
  {"node":"clock","owner":"clock-owner","kind":{"implementation":"host_clock"}},
  {"node":"device","owner":"device-owner","kind":{
    "implementation":"reference_device","quantum_ps":"50","host_budget_ns":"20000000"
  }}
]
```

Compile on the owning daemon so the scenario binds its actual host executable:

```text
crucible node compile --socket /absolute/private/node-state/node.sock \
  --selections selections.json --output scenario.json
```

The explicit run configuration is:

```json
{"format":"crucible.node-run-configuration","version":1,"horizon_ps":"100","maximum_rounds":"8"}
```

Select a fresh independent nonzero 16-byte execution nonce, encoded as 32
lowercase hexadecimal digits. Preserve it for every retry and status query:

```text
crucible node observe --socket /absolute/private/node-state/node.sock \
  --ledger operator-observations --execution 29292929292929292929292929292929 \
  --selections selections.json --scenario scenario.json --configuration configuration.json
crucible node status --socket /absolute/private/node-state/node.sock \
  --execution 29292929292929292929292929292929
```

Status JSON reports the original plan, complete capabilities, input closure,
repeatability, lifecycle state, and completed result/provenance/evidence roots.
Mixed reference-device worlds report `repeatable:false`. Same-actor retries
authenticate original inputs before returning the retained state. After daemon
restart, status reads unchanged durable state. An observation retry authenticates
the complete original source identities, configuration, whole-world owner roster
and input context before returning that unchanged state. Changed inputs refuse;
the recovered record grants no new native dispatch or resume authority.

The private same-UID socket carries one bounded canonical exchange per
connection. The daemon holds an exclusive lifetime state lock and registers the
actor's independent retention owner before accepting requests. Its namespace
exposes no deletion authority. Native cleanup keeps that lock and active roots
until authentic complete reclamation; SIGINT and SIGTERM stop admission and
drain original worlds before endpoint retirement.
