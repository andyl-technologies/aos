# Independently packaged observation tools

`_hub-observation-tools.nix` requires a selected runtime source, actual Git
archive, six-field runtime provenance, source commit/tree, and the actual Native
and Worker artifacts from that source's package set. It has no runtime default.
Every invocation must match the explicitly selected build tuple; helper source
changes do not claim a new deployed runtime.

The preparation derivation verifies the archive commitment and commit, linked
production crate and reader bytes, Native executable commitment, Worker package
source commitment, and actual console assets. It extracts the real manifest-page
serializer and browser template, refusing unsupported extraction shapes. The
existing codec crate supplies shared canonical control/storage decoding and its
unchanged default modes. `native-bodies` adds the bounded observational report.
This mode requires the explicit `native-bodies` Cargo feature and the selected
runtime pins supplied only by the observation-tools recipe. The ordinary codec
recipe builds without that feature or pins and refuses the unavailable mode.

The output provides `aos-native-body-observer`, `aos-native-body-auth`, and
`aos-hosted-byte-assessment`. The selected observer reference for Python inputs
is the underlying codec ELF from `helper-build-provenance.json`, whose native
mode is explicit. The public observer wrapper and underlying ELF have separate
commitments. Python code and package metadata have immutable Nix custody;
captures, manifests, static auth sidecars and logs retain their original private
owner, permissions, no-follow, inode and hash checks.

Runtime provenance keeps its existing six fields. The observer keeps its eight
report fields and authentication labels. The auth reader separately reports
source-checked authentication and missing raw compact custody, never independent
MAC verification. The adapter retains `nativeBulkBytes: null`, incomplete hosted
acceptance, unknown full inventory and receiver deployment/window authority.

The current installer marks SDK/client application-ledger producers unavailable.
Their expected commitments are absent; supplied producer records refuse rather
than adopting arbitrary log declarations. The capture producer is also absent.
No SDK event becomes a provider HTTP row or a billed-wire measurement. Adding an
actually installed producer requires a separately reviewed selected source and
artifact correspondence.

This package installs no acceptance, profiles, queues, captures or provider state.
The fixture data contains synthetic bodies and a recorded runtime tuple; it is
not a deployment selection, authentication receipt or default runtime. Fixtures
exercise that selected tuple only. The process fixture uses the measured build
provenance rather than a fixed executable locator. A new runtime requires its
own source/artifact verification, supported fixtures and affected checks.

`render_private_wrapper.py` consumes an explicitly hash-selected immutable
helper build record and writes a create-only owned0600 wrapper under an
owned0700 directory. It invokes the measured canonical package Python and
installed adapter, preserving selection arguments, process group and inherited
descriptors. The invoking supervisor still owns cleanup. This mapping installs
no capture producer, acceptance, runtime flag or credentials.

## Native inbound inventory selection

The optional assessment `nativeInventory` slot contains exactly `policy` and
`sidecar`, each an existing private `{file, sha256, byteSize}` reference. The
policy image must use the selected producer's exact four-field encoding. The
sidecar retains the existing runtime, process, log and authentication context
schema; selecting it does not establish an authenticated metadata projection.

The reader hashes the actual raw member JSON bytes and checks begin/end,
ordinals, settled counts, trailers, unread frames and source commitments. It
projects only exact source-embedded public assets independently matched to their
route, constructor and offered bytes. Dynamic instance pages, setup forms,
publication/control bodies and current SQL/original/authentication projections
remain unresolved. Producer `requiredProjection` labels are requirements, not
completed evidence. Missing provider instance or log-window custody stays
incomplete; no host process facts are invented for provider-managed instances.

The inbound result covers consumed request and offered response data frames in
one selected Native policy window. It does not prove delivered responses,
Native outbound coverage, or overlap with a workload controller's monotonic
window. An actual local UTC bridge and measured cross-machine clock uncertainty
remain required. `nativeBulkBytes` remains null and hosted acceptance remains
incomplete, including when finite asset projections account for this inbound
window. The fixture export is test-only and describes a synthetic window.

### Immutable dynamic value matches

An optional `immutableProjection` selector on a native-body capture can select
one manifest Append original plus its retained chunk row, or one Native Direct
Admission envelope plus the exact public BeginBatch and retained admission rows.
The Rust observer uses production DTOs, canonical encoders and the actual
manifest page serializer. It reports matched immutable values and positive
request/reply control-byte costs. Selected SQL values are not measured reader,
current-state or authentication authority: `objectPayloadBytes` remains null.
Changing statuses, Commit/Complete phases, Get/List/WhoAmI and browser slots are
unsupported by this projection slice.

The inbound inventory reader accepts an optional actual codec report from its
caller and matches unique member ownership, route/phase, frames and constructor
source. Current installed assessment wiring must pass its actual successful
source-pinned codec report; a selected JSON file alone is not a codec invocation.
SQL reader custody/current fences and actual logical or ingress authentication
remain separate missing joins. No projection label grants whole Native zero.
