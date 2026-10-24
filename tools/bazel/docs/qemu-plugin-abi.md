# QEMU plugin compiler inputs

`pkgs/build-support/_bazel/qemu-plugin-abi.nix` builds a declared-input bundle
against the matching AOS-built `qemu-crucible`. Its `plugin.env` exports the
QEMU build identity, atomic patch hash, and generated shared-memory header hash
used by the Rust plugin's admission checks. `identity.json` records those
identities, the two Rust declaration digests, and the checked ABI versions.

The Cargo plugin builder and this bundle share
`pkgs/emulation/_crucible-qemu-plugin-abi.nix`. Before exporting the identities,
it checks the required QEMU entry points, matches both ABI versions, and compiles
a C probe against the real packaged headers with the AOS compiler and GLib.
The probe checks the register-read, replay-cursor, and preemption function
signatures. A missing declaration, header, symbol, incompatible signature, or
version mismatch fails the derivation.

Run the matching-header and version-drift checks with:

```text
nix-build -A checks.build.bazel.qemu-plugin-abi --no-out-link
```

The bundle prepares compiler inputs for the GPL plugin conversion. It does not
replace the production Cargo builder, qualify a Bazel plugin binary, or replace
the mandatory ABI, license-boundary, and live QEMU gates. The GPL-side tests that
currently link Apache host libraries still require process-based harnesses.
