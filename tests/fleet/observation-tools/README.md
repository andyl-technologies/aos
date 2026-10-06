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
