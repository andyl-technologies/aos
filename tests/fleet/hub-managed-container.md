# Managed container producer

`_hub-managed-container.py` extracts the genuine APR/container producer used by
the fleet fixture into a callable helper for a fresh Managed pair. It uses the
selected source-built `aos`, `apr`, Git, OpenSSH, Nix and Python packages. It
does not create a Worker, install permission, configure delivery routes or
replace the main External throughput corpus.

## Caller contract

`prepare_managed_container_source(client, tools, coordinates)` requires:

- `client.agent.request`: the existing private guest command transport;
- `tools`: individual paths named `aos`, `apr`, `git`, `opensshBin`, `nixBin`,
  `helperStorePath`, `aosStorePath`, `containerPublicationInputs`, and `python`;
- `coordinates`: a fresh 32-lowercase-hex `runId`, a fresh absolute `clientRoot`
  such as `/var/lib/hybrid-client/managed-<run>`, and the exact HTTPS
  `workerOrigin` such as `https://localhost:4643`.

The selected fixture publication inputs define the actual release identity.
The helper signs the real signature input with a newly generated APR key and
requires `verified-external-sshsig` from actual signature finalization. It
returns `trustKey`, the initial APR `sourceCommit`, `surfaceRoot`,
`publisherHome`, `registryRoot`, `privateEnvironmentPath`, `helperSha256`, and
the actual `finalized` CLI result, including `release`, `layout`,
`signature_input`, `release_identity` and `index_digest`.

The guest's HOME is inherited. APR state uses fresh supported XDG directories;
the initial APR commit gets command-local author identity, and later Git
configuration is clone-local. The private environment file retains only the
publisher's selected HOME/PATH/XDG/Git/Nix settings. Guest TLS trust remains
enabled and must already trust the pair's local certificate.

The Fleet hook creates and independently observes the actual registry and
Managed write placement, configures the `aos` OCI repository route at the
selected origin, and passes `registry = {"slug": "managed-<run>/containers"}`.
These preparations are prerequisites; the helper does not infer them from
configuration or a caller-supplied acceptance flag.

## Publication sequence

`publish_managed_container(client, tools, controls, coordinates, registry,
source, refresh_token)` performs:

1. Ordinary `aos container publish --stage-only` with the finalized release
   paths. Its exact root must match the signed index and `tag_updated` must be
   false. No `--direct-required` flag is supplied.
2. Real `apr publish` of the selected `aosStorePath` as package `aos` version
   `0.1.0`, then `apr release` with the real container sidecar/signature input
   and selected helper store path. `apr verify` must succeed.
3. Ordinary `aos hub registry publish upload` of that actual signed surface.
   Its actual publication must be `ready`.
4. Actual `RegistryService/GetRegistry` observations until `indexState` is
   `fresh` at the exact new signed APR source commit.
5. Non-stage `aos container publish` with a separate fresh idempotency key.
   Its actual result must contain the same root, `verification = verified`,
   publication ID and resource version.

The return value separates `stage`, `signedSource`, `registryUpload`,
`indexObservations` and `containerPublication`. Staging alone is never the
final publication result. The helper refreshes the actual bearer before each
long authenticated phase and does not retry a failed or ambiguous mutation.
Exclusive command directories retain arguments, stdout, stderr and terminal
exit status. An interrupted attempt remains retained and is not reused.

## GC source and root mutation callbacks

After actual final publication, `upload_managed_unrooted_blob(client, tools,
coordinates, registry, refresh_token)` retains a newly generated random
256-byte body and uses normal Distribution POST/PATCH/PUT completion. It
requires actual 202/202/201 replies, exact same-origin Locations, contiguous
`Content-Range: 0-255`, and the actual returned digest equal to the retained
body digest. It never inserts bytes directly into Miniflare storage.

`root_mutation(client, tools, coordinates, registry, source, refresh_token)`
rehashes the retained signed root index and PUTs its actual OCI document to a
fresh `gc-root-<run>` tag. It requires the actual 201 and matching returned
digest. The Fleet hook owns the retention review, timing of this callback,
current SQL/provider/guard observations and GC decision assertions. This
callback alone proves no GC race or safe deletion outcome.

For the separate GC negative that makes a reviewed unrooted candidate live,
`prepare_unrooted_root(client, tools, coordinates, registry, source,
refresh_token)` loads and rehashes the actual finalized OCI index. It preserves
all of its real child manifest descriptors and adds the valid annotation
`org.aos.fixture.gc-candidate = <run>`, producing a distinct index digest. A
normal digest-only manifest PUT must return 201 and that exact digest. A
normal GET by digest must then return 200, the expected media type/digest,
and the exact retained bytes. No tag is written during this preparation.

The returned candidate has `version`, `helperSha256`, `registrySlug`, `runId`,
`sourceIndexDigest`, `digest`, `bytes`, `mediaType`, `bodyPath`, `admission` and
`readback`. The annotations distinguish this valid ordinary OCI index from
the already rooted signed release index; the new candidate is not represented
as a new signed release. The Fleet/Native GC adapter must independently find
this digest in actual inventory, candidate and frozen review/action records
before calling `root_candidate(client, tools, coordinates, registry,
candidate, refresh_token)`.

That callback requires the exact retained candidate record and unchanged body
hash/size, then tags those same bytes as `gc-candidate-<run>` with a normal
manifest PUT. It returns `tag`, `digest`, `bodyBytes` and the actual `receipt`.
The GC adapter owns the later refusal assertion and the fresh inventory/root
observations. This callback never labels the earlier review safe or complete.
The older `root_mutation` callback remains an already-rooted-index mutation;
it is not evidence that a reviewed candidate became reachable. The random
256-byte blob remains a separate positive GC source, produced after the
negative case and followed by a fresh inventory/review.

All Distribution request/reply bodies and headers stay in private guest
evidence directories, separate from publication commands. Redirects and
cross-origin upload Locations refuse. Failures retain actual responses;
neither a status code nor these source checks establishes provider acceptance
or Native bulk-byte totals.

## Source checks

Run the focused suite with the selected AOS Python:

```text
<aos-python>/bin/python3 tests/fleet/_hub-managed-container-tests.py
```

Tests exercise ordering, exact-index refusal, command arguments, source drift,
HOME/XDG behavior, same-origin/header validation, Distribution body/digest
construction, retained index hash checks, distinct digest-only candidate
admission/readback and exact candidate tag mutation with controlled
command/HTTP boundaries. They execute no real publication or provider mutation. Actual
Managed pair/runtime qualification remains a separate measured run from the
accepted common release tuple and the reviewed Fleet hook.
