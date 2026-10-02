# Same-source OCI profile audience refusal

This fixture tests an installed OCI-only artifact for origin A against a
separately observed origin B running the same selected Worker source and Wasm.
It does not test a source revision mismatch, establish Hosted readiness, or
create a provider permission. Existing controlled unequal-source assessments
remain separate.

## Initial selection and transport

Select the following observation before the Managed Worker starts:

```json
{"version":1,"capture_id":"32-lowercase-hex","placement_prefix":"actual-placement-prefix","document_digest":"sha256:actual-index-digest"}
```

The `HUB_OCI_PROFILE_LOAD_OBSERVER` value is observational. It selects the
actual retained graph descriptor and placement prefix, not a predicted upload
UUID. The do-e2e-only Worker opens a bounded console bracket after existing
MAC, source, physical-key and journal checks, while holding the physical key
gate. It records actual provider-capacity counters, installed artifact bytes,
shared verifier facts and the unchanged loader result. Ordinary Worker builds
exclude this bracket. Four complete records are required; cancellation,
overflow, malformed records or missing terminal state remain unknown.

Install the source-built listener on the Worker VM before initial observations.
The existing Worker TLS proxy sends only the exact
`/_internal/storage/oci-document-projection` location to HTTP loopback 4649,
after its normal raw request capture. The listener forwards to A on 4645 while
unarmed and sends exactly one held original to B on 4647 after release. Native
retains its normal strict TLS origin at `https://localhost:4643`; B is separately
observed at `https://localhost:4648` using the proper selected TLS leaf.
Headers, original body and role MAC are preserved. The listener does not
authenticate them. Maximum transport concurrency is 128; complete retained
rows are limited to 204704 and 512 MiB. Incoming controls are at most 16 KiB;
responses are streamed with a 4 MiB + 64 KiB ceiling. Only the selected response
is additionally retained as bounded raw bytes. Overflow fails the observation.

## Called interfaces

The installed controller is `_hub-oci-profile-mismatch.py`; it imports the
installed `_hub-oci-profile-process.py` through the selected AOS Python tool.
Fleet owns the called main/Nix/proxy hooks.

1. `prepare_profile_listener(worker, tools, prepared)` freezes a fresh private
   root/config and returns the source-built Node argv.
2. Fleet launches that argv with its actual process helper before Clock capture.
   `await_profile_listener(worker, tools, listener, process)` joins bound
   readiness to the real private socket peer and process lifetime.
3. After positive OCI installation/business, call
   `select_profile_context(worker, tools=..., prepared=..., processes=...,
   namespace_file=..., artifact_sha256=..., source_identity_file=...,
   listener=...)`. The identity file is produced by the existing authenticated
   Clock verifier. The utility reads private actual config/namespace files and
   complete accepted loader records. It selects the profile digest from the
   shared Rust verifier's recorded event; Python never reconstructs that digest.
4. `run_profile_origin_mismatch` receives the selected context, the ordinary
   producer `root_mutation`, a read-only SQL original observer, real B/A
   TLS/Clock/namespace observer, epoch callback and evidence retention callback.
   The exact current upload/chunk/placement/binding rows must match the emitted
   original before A can stop. A caller approval Boolean is not accepted.

The lifecycle holds an actual fresh signed lookup before stopping A, then
stops both pinned Node and workerd lifetimes through pidfds. It launches B with
unchanged source, Wasm, persistence, roles, namespace and artifact. Only its
local port, public-origin bindings and private control socket differ. B receives
the byte-exact original once within its immutable conservative cutoff. A
complete actual refused bracket must show the same artifact/source/profile,
current origin B and artifact origin A, a live artifact window, the exact
shared audience error, and unchanged unsaturated dispatch counters with no
active capacity in that bracket. This conclusion covers only the authenticated
physical-key loader interval, not isolate-global or provider-global activity.

The callback transitions are `before-A-stop`, `B-started`, `before-B-stop` and
`A-restored`. The outer collector closes A while it is still live and resumes
only after restored A readiness. B's distinct log/process/config and exact
forwarded original/reply stay in a separate negative subwindow. They must not
be relabeled as A's normal business or SDK epoch.

Original raw argv/environment/config are privately retained before stopping A.
The environment is inherited byte-exactly, including HOME. Restored A appends
to its original captured stdout inode and returns a new actual process pin.
B must exit before A can resume. A pending producer or unknown B spawn prevents
A restoration. Exit, timeout, Future cancellation and attempted native stream
cancellation do not establish SDK/provider drain.

## Evidence limits

Node transports and Python process/assessment tests use controlled loopback
servers and owned harmless child processes. Worker verifier tests use the real
shared signed-artifact codec with test fixtures. Default/do-e2e Wasm checks
establish compilation only. None establishes installed Native/workerd business
qualification. Actual cold startup may exceed the original thirty-second
lookup, or A shutdown may cancel its caller; those outcomes remain unknown and
are not replayed with a renewed original. Final same-source installed
qualification still requires authentic process/config/Clock/namespace/artifact,
current SQL and full request/body/header joins.
