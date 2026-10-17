# Confined held-index listener and controller

This fixture supplies the missing listener and process controller for the
existing stale-placement hold. It does not authenticate StorageWork, qualify
a provider, or report Native bulk bytes from an index error.

## Setup contract

Fleet installs the three implementation leaves and the existing
`_hub-direct-stale-placement-hold.mjs` and `_hub-direct-stale-placement.py`
from the selected immutable source. Fleet owns the Nginx template and main
hook. Configure only Native's exact `/_internal/storage/v1/execute` location
to use `https://127.0.0.1:4650` with strict `localhost` TLS verification.
Keep the existing original capture before the listener and Worker received
capture after it. Other upstream routes retain their existing configuration.
The listener runs unarmed throughout baseline and load, so those windows have
the same transport overhead.

Load `_hub-direct-stale-index.py` and call:

```python
installation = start_direct_stale_index_listener(native, tools, configuration)
environment = capture_direct_stale_index_environment(
    native, tools, actual_native_process, private_environment_file)
receipt = run_direct_stale_index_case(
    native, worker, client, database_machine, tools, controls,
    registry_setup, actual_signed_source, actual_worker_process)
```

`configuration` has exactly these fields:

```json
{
  "version": 1,
  "root": "/var/lib/hybrid-stale-index-listener",
  "listenPort": 4650,
  "upstreamHost": "worker",
  "upstreamPort": 443,
  "originHost": "aos.andyl.org",
  "certificateFile": "<selected localhost leaf>",
  "privateKeyFile": "<private matching key>",
  "caFile": "<selected Worker CA>",
  "holdModuleFile": "<immutable hold adapter>"
}
```

The listener binds loopback only. Upstream TLS keeps the original authority
and verifies the actual Worker certificate. Private control uses
`root/control.sock`, mode 0600, with an independently checked process
lifetime and `SO_PEERCRED`. The closed commands are `arm` with `selection`,
`status`, `transport-status`, `release` with the retained `requestSha256`, and `close`.
Neither socket custody nor the transport receipt proves request HMAC validity.

Required `tools` entries are:

| Entry | Actual selected input |
| --- | --- |
| `node`, `python`, `aosHub` | Source-built selected executables |
| `staleIndexListener`, `staleIndexProcess` | New immutable source leaves |
| `stalePlacementHelper` | Existing reviewed public PlanApply helper |
| `staleIndexInstallation` | Actual `start` receipt above |
| `staleIndexEnvironmentCapture` | Actual `capture` receipt above |
| `staleIndexControllerRoot` | Fresh owner-private controller directory |
| `staleIndexSqlQuery` | SELECT-only callable returning typed scalar row lists |
| `staleIndexReadIndex` | Callable returning the complete fixed 25-table index projection |
| `staleIndexRetain` | Owner-private receipt retention callable `(name, value)` |
| `deploymentId` | Actual selected deployment identity |

The selected registry supplies `registry.slug` and `placement.name`.
The source supplies the actual signed `sourceCommit`. The controller obtains
numeric placement and binding IDs, revisions, kind and prefix from current SQL;
it does not accept a caller-provided StorageWork context.

The process capture requires the previously observed `pid`, `startTicks`,
`ownerUid` and `executableSha256` and checks them against the live process before and after
reading `/proc/PID/environ`. It adds the actual command-line digest and owner
UID. A root fixture observer may read the independently pinned service UID;
it never relabels that service as root. The index child has its separate
observer-owned process lifetime and UID, checked against the same executable.
Raw environment bytes are bounded to 256 KiB, retained exclusively in a
0600 file, and never returned or logged. Before launch, the child rechecks the
same live process, exact retained environment and selected executable. HOME
and other variables are inherited exactly; no value is assigned or defaulted.
The child runs the ordinary installed command:

```text
aos-hub index <actual registry slug> --topology hybrid
```

## Evidence and failure contract

The adapter holds one actual `InspectMetadata(info/refs)` original before
forwarding. Exact body bytes, signature and both transport correlation
headers remain unchanged. The controller reads those retained original bytes,
executes real `PlanUpdatePlacement`/`UpdatePlacement` with only
`read_order + 1`, then releases the same original once. The original retains
its initial deadline of at most 30 seconds; no renewed authorization is made.
The listener checks actual UTC again immediately before forwarding.

Acceptance requires a genuine non-timeout ordinary index failure containing
the current-SQL stale-result fence, with every selected authoritative row
unchanged except the genuine failed index state/error. The full 25-table
projection must include actual package, release and channel rows. Eligible old
provider reads may occur before the retained cutoff. Provider request counts
and Native bulk bytes are explicitly unknown until independent existing
observers establish them. Response loss, process timeout, missed rendezvous,
deadline expiry or control failure retains originals and remains unresolved;
the controller does not replay, restore placement revisions, or infer rollback.

The listener bounds 128 concurrent requests and one MiB per metadata body.
This accommodates two overlapping configured publisher envelopes of
8 bulk plus 32 metadata operations each, with headroom for maintenance and
the held index. It is a fixture transport limit, not SDK concurrency evidence.
Baseline and loaded traffic use the same listener. Durable transport evidence
is bounded to 204,704 rows and 512 MiB, matching the existing complete-window
header row ceiling. Overflow retains one explicit marker and refuses further
dispatch. `transport-status` exposes actual transport counters and retained
row/byte totals, including capacity refusals; none are provider effect counts.
The controller requires no evidence overflow or capacity refusal before or
after the held case. Independent captures still establish complete responses.
Only the held original is further restricted to 64 KiB. Responses stream
without accumulation. The private socket admits bounded canonical commands.

## Controlled gates and remaining runtime scope

`_hub-direct-stale-index-listener-tests.mjs` exercises an actual loopback TLS
listener and private socket with a controlled upstream. It checks exact body
and header preservation, release sequencing, unselected transport, admission
refusal, actual UTC expiry and retained unknown close. It does not execute
Worker HMAC verification or provider SDKs.

`_hub-direct-stale-index-tests.py` uses actual local process lifetimes and raw
environment files, controlled SQL/guest boundaries and the existing public
placement helper. It proves source interface/custody behavior, not genuine
Native auth, SQL execution, Worker dispatch or a stale index runtime result.
Those acceptance claims require the later matching immutable Native/Worker
tuple, installed main hook, actual public control API and independent captures.
