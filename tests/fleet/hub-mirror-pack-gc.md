# Separate mirror, pack and managed physical guard qualification

`_hub-mirror-pack-gc.py` runs the actual Native controller, compiled Rust Worker,
workerd Durable Objects and retained SQLite object-store façade. It is separate
from the five-machine direct upload workload. It does not install configuration,
write acceptance KV records, sign review evidence or mutate cloud resources.

Run it with an explicitly selected AOS-built Python:

```text
<aos-python>/bin/python3 tests/fleet/_hub-mirror-pack-gc.py configuration.json
```

The closed version-one configuration requires:

- `sourceRoot` and `sourceRevision`: the reviewed public source assembly and
  its original Git revision. Overlay source bytes are pinned separately.
- `sourceFiles`: exact SHA-256 commitments for every path in the driver's
  `SOURCE_FILES` tuple, including the driver and connected runtime fixtures.
- `sourceAssemblyManifest` and `sourceAssemblyManifestSha256`: the exact base
  commit, eleven allowed fixture overlays, every unchanged crate file and the
  production contract files matched against the compiled Worker's source.
- `workerArtifactReceipt` and `workerArtifactReceiptSha256`: the independently
  retained do-e2e build receipt joining that immutable source and compiled bytes.
- `workerDist`, `workerWasmSha256`, `workerShimSha256`, `workerSourceSha256`:
  the compatible compiled Worker and its independently retained source receipt.
  A historical Worker remains historical; a newer test source does not rename it.
- `nix`, `devShell`, `node`, `workerd`: explicit source-built store paths. The
  driver runs Cargo through that pinned dev shell and never selects host tools.
- `targetDir` and `evidenceDir`: absolute paths. The evidence directory must be
  new; ambiguous effects and failure logs are retained without an automatic retry.
- Optional `purposeInput`: the path to a closed operator-supplied document
  described below. Its absence leaves purpose qualification unknown.

Compile the Native test executable before obtaining a fresh protected challenge
if purpose inputs are supplied. Discovery retains its original thirty-second
cutoff. The purpose input contains only these absolute file references:

```json
{
  "directArtifact": "/private/review/direct.json",
  "mirrorArtifact": "/private/review/mirror.json",
  "packArtifact": "/private/review/pack.json",
  "directPublicKey": "/private/trust/direct-public.hex",
  "mirrorPublicKey": "/private/trust/mirror-public.hex",
  "deploymentGuardKey": "/private/operator/guard-key",
  "originalChallenge": "/private/observation/challenge.json",
  "deploymentReply": "/private/observation/reply.json",
  "deploymentReplySignature": "/private/observation/reply-signature"
}
```

The guard key must be a bounded regular file with private permissions. Its bytes
and commitment never enter reports. The verifier authenticates the exact original
challenge and deployment reply, checks independently trusted direct and mirror
signatures, and joins the full signed ordinary mirror artifact to the separate
pack purpose using shared production validators and exact acceptance keys.
Controlled artifacts cannot satisfy production-purpose validation. No fixture
creates hosted measurements or reviewer signatures.

Separate processes and evidence directories exercise managed guard deletion and
the mirror corpus. A failure in either retains its own effects and logs; the
driver writes each scope's outcome before returning failure. A completed GC
scope never turns an incomplete mirror publication into a pass.

The controlled mirror runtime exercises none/zstd publication, exact SQL commit
and lost-ACK restart recovery, full pack membership and durable cache faults. Its
managed deletion cases retain the selected writer revision and generation, actual
provider effects and read-only physical guard observations:

1. A foreign upload version refuses without a delete or changed incarnation.
2. An exact version deletes once, records its original receipt and observes absence.
3. Replaying that receipt preserves a newer writer at the same physical key.
4. A lost positive delete acknowledgement retains an unknown pending claim.
5. Restart, exact replay, guarded HEAD and a new writer refuse without clearing
   or redispatching that claim, even when independent provider readback is absent.

The Native test uses the existing `test-support` observational result adapter.
GC requests use the production plan builder and result validator with a separate
fixture-only signed HTTPS transport pinned to the isolated listener's CA. The
production client's controlled-TLS authority restriction remains unchanged;
this does not qualify its production `execute` transport.

`qualification.json` commits the original reports, tool paths and source/artifact
identities. Controlled managed guard success never qualifies hosted R2 or S3
conditional DELETE. SQL GC accounting, production-purpose dispatch, whole-worker
memory and whole-worker CPU remain unknown. A verified signed prerequisite chain
is reported independently from actual production admission, which this driver
does not execute. Raw process accounting is retained without inferring isolate
CPU or acceptance from it.
