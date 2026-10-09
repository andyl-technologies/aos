# Installed gem5 closed-profile qualification

The `gem5-closed-profile` package produces a source-owned qualification bundle
for `freestanding-o3-classic-ddr3-v1`. It builds both fixed guest ELFs from source,
installs the exact native controller/model scripts, and executes independent
native witnesses before writing its manifest. No raw process image or trace is
installed in the bundle or checked into this repository.

The package admits only the measured x86-64/AArch64 checksum programs using
modeled RAM, stdout descriptor 1, and exit. The realized model uses O3, classic
L1/L2 caches and DDR3, with a native tick of one picosecond. Installed model
scripts and each actual realized `config.ini` bind all defaults and connections.
No ingress, host-derived guest input, debug listener, arbitrary guest image,
or full-system device configuration is included in this profile.

## Actual mechanism checks

Each architecture executes the following against the source-built native
emulator and source-built DMTCP/helper/auditor:

- Zero-event exclusive stops and unchanged observations.
- Full-position stops before the first reaction, and exactly one native
  callback at a one-event budget ceiling.
- Original immutable operation retries and original receipt recovery.
- A 5,000-event cut and non-draining opaque process capture at the unchanged
  native boundary.
- Independent complete capture closure authentication from original native
  map, thread-context, descriptor and file-mapping ledgers, raw image bodies,
  kernel resource census, immutable source assets, and private file custody.
- Actual guest stdout publication birth inside the native callback, with
  native tick, global event ordinal, tick ordinal, and original bytes.
- Source process exit and deletion of the original owned resource root before
  two concurrent fresh reconstructions, each with new control identity.
- New captures in each restored owner's private image directory, independently
  authenticated against its own native map, thread, descriptor and resource
  ledgers without changing the historical image or advancing a native event.
- Unchanged captured boundaries and identical native continuation publication
  suffixes, native checksums, and image contents in both private branches.
- Actual termination, reaping and empty live kernel census of all three
  native/helper process groups.

Opaque capture completeness does not relabel the partial typed CPU/cache/device
inspection as complete. The manifest retains
`modeled_diagnostics_complete: false` and
`full_system_device_parity_qualified: false`. Runtime capture authority still
requires the private provider certificate and installed-profile verifier;
parsing a manifest or accepting operator-supplied hashes cannot mint it.

## Local source-build result

An independent installed check of the earlier `7mh` bundle refused fresh
captures in both architectures: the restored owner retained the original
native capture-custody root, so its new supplementary checkpoint files were
missing. The earlier `p592` bundle used the same controller and custody helper.
Their builder-only successes could not establish the required resource-root
lifecycle in other supported host namespaces.

The corrected owner validates its actual restored private root, updates the
Python binding and native libc environment, and verifies native readback before
readiness or any modeled callback. The builder now uses fresh private `/tmp`
witness trees, which exercise the resource namespace that exposed the defect.
Independent host checks for both architectures then passed original capture,
source death and absence, two fresh recaptures with actual supplementary files,
unchanged continuation and group reaping. The independently checked private
controller copies have the same SHA-256 as the corrected installed bundle.
No missing-file or image-body check was relaxed.

Command, executed on this machine with remote builders disabled:

```text
aos-dev --release build package gem5-closed-profile --no-out-link \
  --builders ''
```

The passing output is
`/nix/store/05fw6c809l3j12yp37ip9bld71byk353-gem5-closed-profile-1`.
Its installed `share/crucible/gem5/closed-profile.json` is 12,230 bytes with SHA-256
`ada655580bb5262f09c4abb710eab6bb3c2a6be35ff3aaad383b60dff88435a9`.
All 25 installed artifact bindings were independently remeasured after package
fixup and scrubbing; every SHA-256 and byte length matched.

The actual native gem5 executable is 157,944,088 bytes with SHA-256
`20217c64e0f7a4e19008e7ad0c218c81377b8ccf4bcd38b1a18d9507653b69f3`.
The source manifest binds revision
`f5c5a6e390f55dd5984977815bf9d0bd05da6945`, its build recipe and the complete
ordered applied patch list. The bundle also retains upstream gem5/DMTCP source
archives, recipes and patch sources, installed tools, controller/model bytes,
known guest artifacts, and the native host ABI scope.

Both real checks passed. The source-exit reconstruction image commitments were:

| Guest ISA | Image SHA-256 | Final native tick (ps) |
| --- | --- | --- |
| x86-64 | `a05f9f2c2e1bfad20f191c36259606ced5ac3ddaa9a63a0ccad39ceef5c91719` | 700677000 |
| AArch64 | `0d876aa16095ae813a768e93e2b2ed57f8de87b5209a3fa64a7b24c0a5fbdff3` | 641023000 |

These commitments identify particular native captures, not a portable process
ABI or a fidelity certificate. The checked native host ABI was x86-64 Linux
6.18.54, little-endian, with 4,096-byte pages.

The trusted integration path is a compile-time
`CRUCIBLE_GEM5_CLOSED_PROFILE_MANIFEST` binding to the source-built installed
package. Development builds without that binding refuse exact admission.
Scenario/operator configuration cannot override the trust root or extend the
fixed guest, model, device, or syscall scope.
