# Real-browser qualification client

This test client drives the existing AOS console through Chrome DevTools
Protocol. It uses the source-built AOS Node 22 built-in WebSocket; it has no npm
dependencies. Chrome is an explicitly selected external test client. It is not
an AOS package, compiler or build dependency.

The caller must independently bind the actual installed application tuple to
its browser result. Local tests cover client mechanisms; they do not qualify
hosted AOS behavior or provider effects.

## Execution surface

```text
<selected AOS Node22> _hub-direct-browser-cdp.mjs --selection <private JSON file>
```

The closed selection has these fields:

```json
{
  "version": 1,
  "scope": "hosted_aos_browser",
  "runId": "<32 lowercase hexadecimal characters>",
  "outputDirectory": "/tmp/aos-direct-browser-run-<runId>",
  "deadlineUnixMillis": 0,
  "origin": "https://<actual approved origin>",
  "window": { "file": "<actual window.json>", "sha256": "<64 hex>", "byteSize": "<decimal>" },
  "credentialsFile": "<owner-private email/password JSON file>",
  "cases": [{ "kind": "login", "privatePath": "<actual private route>" }]
}
```

The illustrative deadline above must be replaced by an actual future deadline
no more than ten minutes away. Hosted execution checks the exact retained
45-minute owner window and finishes before its cleanup-at-30-minutes boundary,
with a 60-second cleanup margin. The selection grants no window or provider
authority. Hosted execution requires an independently authorized window,
installed runtime and access to the selected origin. The client does not arm a
window, install secrets or grant origin access.

Inputs live in owner-private directories under `/tmp`; file references are
`{file,sha256,byteSize}` with a decimal string count. References are reopened
without following symlinks, measured, and checked before launch and file
selection. Credentials are read only from the explicit private input. They are
never printed or copied into receipts. The login action necessarily sends them
to the selected HTTPS AOS login form and holds them briefly in process memory.

An initial `login` is required. Other closed case shapes are:

| Case | Additional fields | Actual check |
| --- | --- | --- |
| `login` | `privatePath` | Existing password form, then authenticated private UI |
| `private_page` | `path` | Exact private route, CSRF/version meta and mounted `.app-shell` |
| `cache_read` | `path`, `expectedSha256`, integer `expectedBytes` | Two actual bounded reads, exact hash/count and readable stable ETag |
| `cache_pause_resume` | `pagePath`, `objectPath`, `source`, `changedSource` | Actual original and its server-observed part; Pause, reload, check original, reject changed file, same-original completion |
| `cache_abort_new_run` | `pagePath`, `objectPath`, `source` | Actual aborted original and unchanged retired history; distinct nonce and server session for a new run, then abort that run |
| `registry_publication` | `pagePath`, `manifest`, `objects:[{path,source}]` | Complete selected declaration and inventory match the retained Begin across reload, original publication owner and declared Direct object checkpoints; no automatic visibility commit |
| `logout` | `privatePath` | Existing logout confirmation followed by login redirect for the private route |

Sources and cache reads are at most 32 MiB. Pause and abort sources exceed the
actual 8 MiB part geometry. A registry manifest is at most 64 KiB with one to
four declared files. There are at most eight cases. A fast upload can complete
before Pause is reached: that run refuses the pause case rather than inventing
a paused original or changing the application/network. The caller must select
actual existing cache/registry pages and fresh original object paths.

The selected registry declaration explicitly names registry, generation and
the expected parent (empty only when the actual retained parent is empty).
Refs digest, default commit and omitted string defaults are compared exactly.
The client's finite observation projection hashes the existing Rust canonical
sorted object tuples: path, SHA, byte count, kind and media type. It compares
that digest and count to the actual retained Begin. All selected file hashes
and sizes must match every declared inventory entry. Reusing an older
same-generation admission after a refused changed Begin therefore fails;
before/after agreement with that older admission cannot make it valid.

## Source-derived checks and result scope

Selectors follow the actual console sources: `app.rs`, `cache_objects.rs`,
`cache_objects/direct/{driver,model,checkpoint,lifecycle}.rs`,
`registry_publication.rs`, `registry_publication/{direct,direct_model}.rs`,
`transport.rs`, and the Core login/logout HTML and management bootstrap.

The client reads the actual `aos-direct-upload-resume-v1` IndexedDB store in
read-only transactions. It emits bounded hashes and source geometry, never
raw checkpoints, actors, delegated URLs, credentials or opaque grant values.
Part observations are associated with their exact saved scope/run. Admission
metadata and upload heads are distinct. It does not seed or overwrite AOS
checkpoint state. Missing Direct checkpoints fail Direct cases even if a
legacy upload otherwise succeeds.

Actual WhoAmI 200 is required for Direct cases. Network summaries retain method,
status, byte counts, cache flags, hashed path/request IDs/ETags and CORS failure
facts. Authorization/Cookie headers, bodies, URL queries, fragments, console
arguments and exception text are discarded. Screenshots and raw CDP logging
are disabled. Report files are exclusive 0600 and bounded to 2 MiB; event count
is bounded to 4096. Browser stdout/stderr are drained but only counts are kept.

The direct pinned Chrome ELF is used because its shell launcher writes XDG
files even for `--version`. Fresh private profile/XDG directories are created;
existing browser profiles are never selected. HOME is preserved if present,
never reassigned. No sandbox, certificate, TLS or CORS bypass flags exist.
The client owns a detached browser group, pins PID/start/UID/executable/argv and
observable mount/network/PID/user namespaces,
attempts Browser.close, and signals only matching live owned identities. Its
receipt measures that group's empty state. Detached process drain remains
unknown; it is not a provider or whole-machine drain claim.

`complete` means the selected UI cases and owned browser-group cleanup finished.
Two matching reads alone do not prove a cache hit; actual CDP cache flags remain
separate. Provider CORS/ETag observations remain separate from SQL acceptance,
provider settlement and code identity. `nativeBulkBytes`, Native consumed-byte
qualification and remote provider settlement remain null; full Direct
qualification is false. Existing Native/provider/window collectors must make
their own joins. Registry visibility is deliberately not committed by this
client.

## Tests and qualification scope

The local test scope has passed three syntax checks, eleven pure companion
regressions and one real loopback Chrome harness. The pure tests cover closed
selection, sanitization, process identity, checkpoint association, canonical
registry inventory and distinct new sessions. They launch no browser and make
no network connection.

Use the selected source-built AOS Node 22 and AOS Coreutils timeout executables
for these commands. Their identities must match the client's pinned tools;
`AOS_NODE` and `AOS_TIMEOUT` below name those explicit executable paths.
Chrome is selected by its pinned vendor ELF, without its shell launcher.

```sh
"$AOS_NODE" --check tests/fleet/_hub-direct-browser-cdp.mjs
"$AOS_NODE" --check tests/fleet/_hub-direct-browser-cdp.test.mjs
"$AOS_NODE" --check tests/fleet/_hub-direct-browser-harness.mjs
"$AOS_NODE" --test tests/fleet/_hub-direct-browser-cdp.test.mjs
"$AOS_TIMEOUT" --signal=TERM --kill-after=5s 55s \
  "$AOS_NODE" tests/fleet/_hub-direct-browser-harness.mjs \
  --run-local-browser-harness
```

The harness owns two ephemeral loopback servers, a fresh profile, a 20-byte
file, one actual file input/PUT, allowed and refused CORS reads with exposed
ETag, an actual AbortController read cancellation, and a separate harness
IndexedDB database persisted across reload. It does not simulate AOS routes,
login, checkpoints or success.

Its absolute lifetime deadline is 55 seconds from initial setup, reserving the
final 15 seconds for browser cleanup. Browser.close is bounded to one second;
later cleanup waits share the same deadline. Both servers and the owned browser
group must close. The timeout wrapper signals at 55 seconds and kills at
60 seconds if needed. A forced wrapper kill fails the gate; detached or global
process drain remains unknown.

Node's bundled static OpenSSL is part of the pinned AOS Node ELF, rather than a
host library selection. The tested Node has `node_shared_openssl=false` and
reports OpenSSL 3.5.6 at runtime. Each browser receipt retains the actually
running version. Chrome's vendor TLS implementation remains part of the
external client ELF.

Hosted AOS login, cache and registry behavior remains unqualified by these
local tests. Minimal hosted route smoke selects login/private-page/logout
only after runtime installation and window/origin prerequisites are satisfied.
Cache and registry cases additionally require genuine configured Direct
placements, source files and independent Native/provider evidence. Browser
results do not establish full managed-R2/S3 qualification.

The local commands collect no hosted credentials, request no provider resource
and arm no lifecycle. Chrome sandbox startup may refuse in an environment.
Such a refusal fails the gate; the client must not add `--no-sandbox` or disable
TLS/CORS to obtain a pass.
