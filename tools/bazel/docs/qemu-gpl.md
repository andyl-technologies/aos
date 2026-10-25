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
nix-build -A checks.build.bazel.qemu-gpl.runtime-closure --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.gateway-tests.all --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.plugin-tests.all --no-out-link
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
metadata. This qualifies the install layout and runtime resolution.

`runtime-closure` compares each complete installed Bazel package closure with
its ordinary Cargo-built package. It removes only that package's own root and
requires every remaining Nix store path to match, including non-ELF references.
The [current default-toolchain qualification](../tests/evidence/master-qemu-gpl-qualification.json)
retains the exact dependency lists: 54 paths for the plugin and one for the
gateway. The aggregate `all` check requires this comparison. During coexistence,
the `cargoInstalled` parameter must select independent legacy packages if the
production selector changes; comparing a package with itself is not migration
evidence. Matching corresponding-source retention remains a separate release
requirement.

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
The helper's exec wrapper embeds its complete Nix runtime-closure manifest, so
test-cache identity also changes when a runtime library changes independently
of the helper executable's bytes.

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

The plugin's `plugin-tests` graph uses its own `qemu-gpl-plugin-tests` profile.
Its engine-backed fixtures keep their original GPL assertions and send bounded
requests to the Apache helper's engine mode. The helper executes real decision
streams, event-log appends, and simulation-double operations, returning explicit
owned projections. No engine implementation enters the GPL compiled graph.
The v2 test protocol rejects v1 frames and unknown operations or request fields;
engine requests also bound RNG advancement and simulation geometry.

The plugin graph includes its unit suite and the three existing source-audit
integration targets. Their repository inputs are declared runfiles rather than
implicit checkout access. Its independent Cargo comparison builds the same
helper and test artifacts, retains their compiler invocations, and compares
case names and results as well as resolved first-party and upstream features.
Clippy, format, and GPL license-closure checks cover all four test artifacts.
The comparison covers 579 unit cases and four integration cases, with no
ignored cases. Two unit cases add rejection and RNG-state checks for the new
oracle requests; the original plugin assertions remain in the GPL suite.

Production consumers continue to use their existing builders. The ordinary
Cargo gateway and plugin checks also launch the separately built helper.
Apache engine or server libraries must not be linked into a GPL test target.
The current-toolchain report also retains the precise production graph,
developer and format checks, all 36 gateway and 583 plugin cases, installed ELF
inspection, live white-box results, negative license-boundary analysis, and the
plugin ABI bundle. Production source selection may omit unselected test sources;
explicit lifecycle-test source labels defer their existence checks until that
test is analyzed. The conservative and precise production graphs both pass.

The normative ABI/license gates, suite release/source retention, supported
foreign-host execution, complete compiler/linker semantic equivalence, and
repeated performance acceptance remain requirements before production migration.
