# GPL QEMU component conversion

The `qemu-gpl-production` dependency profile compiles the complete plugin
`cdylib` and debugger gateway library and executable. Its 35 upstream source
crates use reviewed permissive licenses. The production license checks reject
Apache host dependencies in either GPL component. The plugin receives its
[checked QEMU identities](qemu-plugin-abi.md) through declared compiler inputs.

Run the current qualification checks with:

```text
nix-build -A checks.build.bazel.qemu-gpl.build --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.parity --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.developer-build --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.format --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.installed-inspection --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.gateway-tests.all --no-out-link
```

`parity` builds an independent offline Cargo release baseline and retains three
reports. `features.json` compares all four first-party packages and their
upstream feature selections. `compiler.json` reconstructs five first-party
compiler invocations from digest-checked Bazel wrapper inputs and compares
their cfg and edition arguments. It retains other options without claiming
complete compiler semantic equivalence.

`elf.json` compares both artifacts' ELF identities, dynamic dependency names,
and executable interpreters. It checks the plugin's exported symbol names and
kinds, its QEMU version object's size, and the three embedded admission
identities. It also executes both gateways with four invalid argument sets and
compares exit status and output using the same public command name. Runtime
search paths are retained for inspection; they are not required to be identical.

The AOS GCC toolchain provides a `libgcc_s.so` linker script that selects its
static support archive. These targets put that directory before the Bazel C
toolchain's shared C++ runtime search path, matching the ordinary AOS compiler's
selection. This preserves the C toolchain's runtime support while avoiding an
additional shared `libgcc_s` dependency in the GPL artifacts.

The `compiler_artifact` packages retain the compiled files for inspection.
The `installed.plugin` and `installed.gateway` derivations apply normal AOS
stripping, RPATH cleanup, and reference scrubbing. The plugin preserves its
relative QEMU plugin symlink, checked build identities, and GPL/MIT license
scope. Its build metadata identifies Bazel and its locked source repositories.
The gateway preserves its GPL/MIT license files and executable layout.

`installed-inspection` checks both artifacts after fixup, compares their ELF
properties and gateway rejection behavior with Cargo, and resolves their native
libraries with the AOS loader. It verifies the symlink, license bytes, and build
metadata, and requires the metadata installer to reject a different QEMU
package, shared-memory version, or embedded build identity before publishing
metadata. This qualifies the install layout and runtime resolution; complete
closure equivalence and the suite's matching corresponding-source retention
policy still require their separate release gates.

The live white-box gate runs unchanged against `installed.plugin`:

```text
nix-build -A checks.build.bazel.qemu-gpl.live-whitebox --no-out-link
```

It boots an AOS VM and performs nine plugin-launch scenarios with the matching
patched QEMU. They cover setup and orderly shutdown, x86 white-box mode
inertness and repeated fingerprints, AArch64 guest markers and exact adjacent
ticks, application-random replies and branch reconstruction, and reserved-port
collision rejection. This executes the native x86 plugin with both x86 and
AArch64 guests; it does not qualify an AArch64 host/plugin build. Its host test
drivers still use the existing source-built Cargo harness.

The gateway's `gateway-tests` checks compare all 36 Cargo and Bazel cases:
six library unit tests, 26 executable unit tests, and four lifecycle tests.
The lifecycle fixtures and assertions remain GPL-side. An independently linked
Apache helper owns the real `DebugGatewayProcess` client and executes its public
operations. Test executables exchange bounded, versioned protocol frames over a
private inherited Unix socket pair, with no filesystem rendezvous or polling.
The helper and gateway are immutable declared test inputs;
each test owns and reaps its processes. No host cache service is involved.

The `qemu-test-oracle-host` and `qemu-gpl-tests` profiles keep host and GPL
compiler graphs separate. Their parity reports compare first-party and upstream
feature selections with independent offline Cargo builds. Compiler reports
compare cfg and edition arguments and retain remaining differences for review.
GPL license-closure checks also cover the test executables. A separate protocol
target runs 48 unit tests, including seven framing and malformed-input cases;
both graphs have Clippy and format checks. The installed helper declares its
SQLite and compiler runtime dependencies so reference scrubbing preserves them.
The artifact contract permits exactly this feature-gated helper, requires empty
default features, disables binary auto-discovery and test/benchmark harnesses,
and rejects missing restrictions or additional commands. Other library and
plugin output restrictions remain enforced.

Production consumers continue to use their existing builders. The ordinary
Cargo gateway checks also launch the separately built helper. The plugin's
engine-backed tests still need a process oracle; Apache engine or server
libraries must not be linked into a GPL test target.
The mandatory ABI, license-boundary, remaining live QEMU, complete closure, and
release gates remain independent requirements before production migration.
