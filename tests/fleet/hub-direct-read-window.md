# Called signed-corpus read and cache window

`_hub-direct-read-window.py` provides two confined callbacks. They use the
selected ordinary CLI and actual guest HTTP/cache transports; they do not start
companions, change initial configuration, mint permissions or infer provider
qualification. Fleet owns the initial corpus, process lifecycle and main call.

## Normal selected companion publication

Call `setup_selected_companion(client, tools=..., selection=..., controls=...,
setup_registry=..., configure_route=..., refresh_token=..., retain=...)` while
the actual selected companion is alive. Its closed selection is:

```json
{
  "version": 1,
  "mode": "native_only",
  "origin": "https://selected-companion.example.test:8453",
  "registrySlug": "managed-<32hex-run>/containers",
  "source": {
    "sourceCommit": "<actual 64hex signed commit>",
    "surfaceRoot": "<retained client surface>",
    "finalized": {
      "release": "<actual finalized release file>",
      "layout": "<actual finalized OCI layout directory>",
      "signature_input": "<actual finalized signature input file>",
      "index_digest": "sha256:<actual root digest>"
    }
  },
  "coordinates": {
    "runId": "<same 32hex-run>",
    "clientRoot": "<fresh private per-mode client root>",
    "workerOrigin": "https://selected-companion.example.test:8453"
  }
}
```

`source` and `coordinates` may retain the ordinary producer's additional facts.
`setup_registry(controls, selection)` must execute the normal current org,
binding, registry and placement plans and return its actual registry/placement.
`configure_route(controls, setup, selection)` must perform the normal endpoint
and route controller exchange. Fleet installs the genuine independent probe
signer in that companion's initial configuration before startup and supplies
actual listener/process evidence to the route callback. The adapter checks the
actual route result's healthy state and canonical origin; those checks do not
manufacture a listener, probe signature or authority result.

The client runs the normal container CLI with the same finalized release,
layout, signature input and root digest: stage-only, then normal registry upload
of the exact signed surface, then final verified publication after the actual
`GetRegistry` reaches the same fresh signed commit. The adapter never recreates
an APR release or resigns the corpus. Both Distribution and Hub control origins
and credentials are explicit. It inherits HOME and CA and selects the ordinary
source-built Git/OpenSSH/Nix subprocess tools. `tools` supplies `python`, `aos`,
`git`, `opensshBin` and `nixBin` from the selected fixture closure.

Create the owner-private `clientRoot` before the route callback. A new
`signed-publication` child retains the immutable original, bounded graph control
hashes, exact command arguments, intent and private stdout/stderr. Large layer
bodies stay on the client; the ordinary CLI verifies and streams the complete
graph. It checks retained control bytes again after each command. Timeout or
failure retains unknown/partial evidence, gives no verified result and does not
automatically replay an earlier command or replace its journal.

## Live read-window callback

Call `run_direct_read_window(client, native, worker, tools=..., context=...,
index_readers=..., retain=...)` immediately after the genuine three publications
and before companion stop. `index_readers` has exactly `hybrid`, `native_only`
and `worker_only`, each an actual current SELECT-only database callback. The
Managed Hybrid reader must target its actual database, never a default database.

The closed `context` has these fields:

| Field | Actual selected input |
| --- | --- |
| `version` | `1` |
| `registrySlug`, `sourceCommit`, `packageName` | Same published public registry, 64hex commit and package |
| `origins` | Distinct `hybrid`, `native_only`, `worker_only` HTTPS origins |
| `objects` | Exactly `git`, `package`, `metadata`, `document`, `container` |
| `privateRegistrySlug` | Same-org private registry with the same genuine signed documentation |
| `credentials` | Client-private `bearerHeaderFile` and `cookieHeaderFile`, actual valid headers |
| `cache` | Actual Worker-local `socketFile` and independently selected `identity` |
| `curlArgv` | Source-built curl and only explicit CA/resolve/no-proxy value pairs |
| `evidenceRoot` | Absolute owner-private, create-new Worker evidence directory |
| `processes` | Four actual runtime pins described below |
| `workerConfigurationFile`, `workerConfigurationSha256` | Actual private initial Managed runner configuration |
| `parityModuleFile`, `parityModuleSha256` | Installed selected `_hub-direct-read-parity.py` and actual digest |
| `indexModuleFile`, `indexModuleSha256` | Installed selected `_hub-index-parity.py` and actual digest |

Each object row is exactly `{relativePath, file, sha256, byteSize}` with a
retained client file from the signed publication. The existing fixed helper
checks route grammar and exact bytes; select small genuine objects up to 4 MiB,
including a real documented package and a complete container graph's actual
blob. The cache document is at most 256 KiB. This is separate from the main
large-object upload measurement, which keeps its original geometry.

`processes` is exactly `hybrid_native`, `hybrid_worker`, `native_only` and
`worker_only`. Each value is `{machine, pin}`. The Native roles select `native`
and Worker roles select `worker`; pins require actual `pid`, `startTicks`,
`ownerUid`, `executableSha256`, optionally actual `commandLineSha256` and
canonical decimal `commandLineBytes`. The Hybrid Worker pin is the real cache
socket runner, matching its independent `runnerPid`/`runnerStartTicks` facts.
The observer does not substitute the root observer UID for a service UID.

The initial runner must already contain the exact `publicDocumentCacheCase`
(`registrySlug`, `documentSha256`, `bodyBytes`, `assetVersion`) and installed
`publicDocumentCacheObserverPath`. The selected independent cache identity is
the existing helper's closed installation contract, including actual process,
configuration, observer, Miniflare implementation, shim and cache key hashes.
The adapter verifies actual configuration and source hashes and pins runtimes
before and after the window. A returned socket identity cannot retroactively
select or authorize another cache entry.

The fixed SQL projector reads all three authoritative indexes and compares
complete projections. One client reference at a time is then copied privately
to the Worker, with size/hash checks before and after transfer. These bounded
reference transfers are fixture inputs, never a serving or object-read fallback.
All HTTP reads use the Worker guest's real strict-TLS curl; all cache controls
use its actual private runner socket. There is no host HTTP path. The cache
case runs first so public parity reads cannot erase its genuine cold baseline.
Actual fill/hit/credential bypass/private positive/expiry/eviction/rebuild are
followed by fixed full/HEAD/range object reads and complete browse JSON parity.

Requests are individually bounded by the existing helper. Guest commands are
at most 8 MiB and replies at most 6 MiB, below the actual 16 MiB agent frame
limit. Reference inputs are at most five times 4 MiB, copied sequentially.
The fixed window retains fewer than 384 files and 512 MiB; overflow refuses a
positive result. Private input/capture files and partial outcomes remain in the
guest evidence directory. `retain` receives the authoritative private snapshots
and final value-free/hash-oriented capture report through the normal controller.
It must preserve those actual guest files in the selected fleet evidence corpus.

Controlled source tests do not establish installed HTTP/cache/SDK execution.
The callback always leaves `nativeBulkBytes` unknown. Independent actual byte,
provider, source, actor/purpose and process captures remain mandatory for final
qualification, alongside ordinary final-source packages and all five VMs.
