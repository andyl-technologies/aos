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
nix-build -A checks.build.bazel.qemu-gpl.cargo-execution-inspection --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.developer-build --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.format --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.installed-inspection --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.runtime-closure --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.gateway-tests.all --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.plugin-tests.all --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.suite-release-manifest --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.suite-source-retention --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.suite-publication --no-out-link
```

`parity` builds an independent offline Cargo release baseline and retains three
reports. `features.json` compares all four first-party packages and their
upstream feature selections. `compiler.json` reconstructs five first-party
compiler invocations from digest-checked Bazel wrapper inputs and compares
their cfg and edition arguments. It retains other options without claiming
complete compiler semantic equivalence.

`cargo-execution-inspection` builds a separate Cargo oracle under the
source-built `strace` inside the Nix sandbox. Its parser reassembles concurrent
exec calls, rejects incomplete or abbreviated records, and requires every
requested compiler invocation to reach the declared unwrapped Rust compiler.
Only direct compiler version queries may appear in addition to those requests.
The check retains actual GCC/linker commands, tool executable hashes, and the
realized toolchain closure. It omits environment values and does not expand
native linker response files or establish compiler-default equivalence.
The [execution qualification](../tests/evidence/master-gpl-execution-qualification.json)
records 58 requested invocations, seven direct version queries, five
first-party compilation units, and 36 native compiler/linker executions. All
six parser and negative-control tests pass in the sandbox.

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

The reusable build recipe lives in
[`pkgs/emulation/_crucible-qemu-bazel.nix`](../../../pkgs/emulation/_crucible-qemu-bazel.nix),
with its installer in the adjacent `_crucible-qemu-bazel-installed.nix`.
Both take explicit package dependencies. Qualification checks and the exported
corresponding-source entry point use these recipes; package selection does not
need to import the comparison oracles.
The [extraction comparison](../tests/evidence/package-owned-gpl-recipes.json)
evaluates the old and new recipes against the same package set and source root:
the compiled build and both installed derivations retain exactly their previous
identities and realized outputs.

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

The `suite` qualification package selects both installed Bazel components in
the ordinary Crucible aggregate. Its explicit `debugGatewayPackage` parameter
keeps the legacy gateway available as `passthru.cargoDebugGateway` for independent
comparisons. The release-manifest check runs the existing suite assertions.
The source-retention check authenticates the realized aggregate's direct
references, selected component paths, matching QEMU/source identity, and retained
Bazel build inputs. The source export includes the root module, lock, native
inputs, and third-party source specifications; qualification reports and Python
bytecode are excluded because they are generated outputs.

`suite-publication` invokes the installed Bazel-built `apr` against a private
local registry and a Nix database populated from the actual realized closure.
Publication preview must accept the aggregate and reject raw QEMU, a raw plugin,
an unmarked wrapper, and an aggregate paired with the wrong source identity.
Every preview must leave the fixture registry unchanged. This exercises the
production validator without publishing artifacts or starting a service.
The merged-master qualification currently fails before that validator: ordinary
publication rejects the fixture's manual metadata flags. The fixture must be
updated for evaluated inventory publication before this check can qualify the
suite; the existing preview contract is not evidence of a passing run.

Run the canonical named ABI and license gates with the selected suite,
controller, plugin, and gateway:

```text
nix-build tools/bazel/tests/gpl-gates.nix -A all --no-out-link
```

This entry point requests the existing green-before-advance wrappers and their
prerequisites, preserving the canonical ABI owner counts and zero-match guards.
The [selected-component gate run](../tests/evidence/selected-gpl-normative-gates.json)
passed the named license wrapper and its 18 owner cases. The ABI chain failed
in the production VM-flight prerequisite: reference and hostile runs differed
at timer 5 by two retired instructions. The rootfs derivation directly selects
the Bazel plugin. This remains unresolved, and the ABI gate is unqualified.
Its output retains both gate outputs and `selections.json` with the exact
component identities. The existing gate drivers still invoke Cargo; migrating
those drivers remains a separate requirement. System fixtures created through
`mkSystem` retain their ordinary package selection, so this comparison does not
claim every prerequisite VM uses a migrated component.

To execute a distinct uncached build using only an exported source tree:

```text
nix-build tools/bazel/tests/corresponding-source.nix \
  --argstr sourceArtifact /nix/store/<qemu-crucible-source-output> \
  -A installed.plugin -A installed.gateway --no-out-link
```

The source-built toolchain and fixed-output source dependencies must already be
available for offline use. This entry point imports the exported repository,
uses a separate build derivation, and disables shared action caching. It does
not replace the named normative ABI and license gates or foreign-host tests.
An optional `--argstr trial NAME` creates a separate Nix derivation for a fresh
qualification execution. Reusing an existing trial or omitting it may reuse an
already realized output when the precise compilation inputs are unchanged.

The [merged bounded-XZ offline rebuild](../tests/evidence/master-bounded-xz-gpl-offline-source-rebuild.json)
executes 107 actions in `linux-sandbox`, with zero action-cache hits and no
shared disk cache. Both installed binaries match the qualified checkout build
byte for byte. This uses previously realized toolchain and source dependencies;
it does not claim a cold bootstrap or qualify another host architecture.

The live white-box gate runs unchanged against `installed.plugin`:

```text
nix-build -A checks.build.bazel.qemu-gpl.live-whitebox --no-out-link
nix-build -A checks.build.bazel.qemu-gpl.production-plugin-flight --no-out-link
```

It boots an AOS VM and performs nine plugin-launch scenarios with the matching
patched QEMU. They cover setup and orderly shutdown, x86 white-box mode
inertness and repeated fingerprints, AArch64 guest markers and exact adjacent
ticks, application-random replies and branch reconstruction, and reserved-port
collision rejection. This executes the native x86 plugin with both x86 and
AArch64 guests; it does not qualify an AArch64 host/plugin build. Its host test
drivers still use the existing source-built Cargo harness.

`production-plugin-flight` selects the Bazel plugin in the unchanged diskless
reference/preemption comparison and block-recovery VM flight. Its exact timer,
idle/wake, and state-fingerprint comparisons remain enforced. A failure is a
migration gate; the white-box scenarios alone do not replace this flight.
The retained execution qualification records a passing selected-plugin flight,
including exact idle/wake evidence, block recovery, and parallel lifecycle
checks. This single success does not diagnose the earlier two-instruction timer
failure recorded in the boundary-gate evidence; the named normative gates and
their intermittent behavior still need qualification.

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
