# tests/crucible/_fleet-runner.nix — the shared Crucible VM/fleet check substrate.
#
# T-PKG-15 ([PKG-29], [PKG-30], spec §26.8) wires `gate:e2e-determinism` as an
# AOS VM/fleet check that builds the *entire* Crucible closure hermetically and
# runs the representative multi-VM, fault-injected scenario end to end. This file
# is the reusable runner behind that check (and behind the real-VM performance
# checks that ride the same substrate): it assembles the whole Crucible closure
# — the patched QEMU (`qemu-crucible`), its co-packaged plugin
# (`crucible-qemu-plugin`), the `crucible` CLI, the stock fixture kernel
# (`linux-crucible`), and the root-image fixtures (`crucible-fixtures`) — as
# hermetic build inputs ([PKG-1]), then executes the built `crucible` CLI binary
# under TCG.
#
# The two load-bearing constraints of [PKG-30] are enforced structurally here so
# every caller inherits them and no caller can forget them:
#
#   * The derivation NEVER sets `requiredSystemFeatures = [ "kvm" ]`. Crucible's
#     determinism forbids KVM ([G-1]); the whole point of this check class is
#     that it runs TCG-only on any CI runner without nested virtualization.
#   * The emitted `$out/result` records `tcg_only=true`,
#     `required_system_features=none`, and `kvm_required=false`, which the
#     CI-wiring guard ([PKG-27], `checks.crucible.phase7.crucibleGateCiWiring`)
#     and the fleet-store guard needle.
#
# The runner is parameterized so a performance-measurement check reuses the exact
# same hermetic-closure + TCG-only substrate and supplies only its own CLI
# invocation and result lines:
#
#   mkCrucibleFleetCheck {
#     name;                 # fleet check attr name, e.g. "crucible-e2e-determinism"
#     checkPath ? ...;      # result identity when the canonical check lives
#                           #   outside checks.fleet and is aliased there.
#     runPhaseScript;       # bash executed with the whole closure on-hand; the
#                           #   built CLI is $CRUCIBLE/bin/crucible and the closure
#                           #   members are exported as env vars (see below).
#     extraClosure ? [];    # additional AOS packages pulled into the hermetic
#                           #   closure beyond crucible + kernel + fixtures.
#     gateResults ? [];     # phase7 gate result directories to assert `PASS` on.
#     resultLines ? [];     # extra `key=value` lines appended to $out/result.
#   }
#
# The `runPhaseScript` runs with these environment variables bound to the built
# store paths of the closure members:
#
#   CRUCIBLE           the crucible CLI package output ($CRUCIBLE/bin/crucible)
#   CRUCIBLE_QEMU      the patched qemu-crucible binary
#   CRUCIBLE_PLUGIN    the crucible-qemu-plugin cdylib
#   LINUX_CRUCIBLE     the stock fixture guest kernel package output
#   CRUCIBLE_FIXTURES  the root-image fixtures package output
#   FLEET_WORKDIR      a writable scratch directory (under $TMPDIR)
#   CRUCIBLE_SCRATCH   alias of FLEET_WORKDIR; a writable scratch directory a
#                      caller can redirect CLI stdout/stderr into for parsing
#   FLEET_STORE        a writable content-addressed store root for the CLI
#   FLEET_ARTIFACTS    a writable reproduction-artifact directory for the CLI
#   CRUCIBLE_RUN_STATE_ROOT
#                      writable durable process-recovery state for live QEMU
#
# Discovery note: the CLI resolves `qemu-crucible` + plugin through the
# compile-time `CRUCIBLE_AOS_QEMU` / `CRUCIBLE_AOS_PLUGIN` hints baked into
# `pkgs.crucible`; exporting `CRUCIBLE_QEMU` / `CRUCIBLE_PLUGIN` here lets a
# caller pin them explicitly and documents the matched pair in the closure.
{
  pkgs,
  lib,
  testing ? null,
}: let
  crucible = pkgs.crucible;
  qemuCrucible = pkgs.qemu-crucible;
  cruciblePlugin = pkgs.crucible-qemu-plugin;
  linuxCrucible = pkgs.linux-crucible;
  crucibleFixtures = pkgs.crucible-fixtures;
  e2eNativeRunnerPackage = pkgs.writeTextFile {
    name = "crucible-e2e-determinism-native-runner";
    text = builtins.readFile ./_e2e-determinism-native-runner.sh;
    destination = "/share/crucible/e2e-determinism-native-runner.sh";
  };
  e2eNativeRunner = "${e2eNativeRunnerPackage}/share/crucible/e2e-determinism-native-runner.sh";

  qemuBinary = "${qemuCrucible}/bin/qemu-system-x86_64";
  pluginLibrary = "${cruciblePlugin}/lib/libcrucible_qemu_plugin.so";
  kernelImage = "${linuxCrucible}/boot/vmlinuz-${linuxCrucible.version}";
  rootImage = "${crucibleFixtures}/share/crucible/fixtures/root/aos-minimal-root.ext4";

  mkCrucibleFleetCheck = {
    name,
    runPhaseScript,
    checkPath ? "checks.fleet.${name}",
    extraClosure ? [],
    gateResults ? [],
    resultLines ? [],
    campaignComposition ? null,
    gateName ? null,
    authoritativeAttr ? checkPath,
    executionFamily ? "fleet-runtime",
  }: let
    extraResultText =
      lib.concatMapStrings (line: "            ${line}\n") resultLines;
    gateAssertions =
      lib.concatMapStrings (
        gate: ''
          grep -q '^PASS$' "${gate}/result"
        ''
      )
      gateResults;
    runtimeInputs = [
      pkgs.bash
      pkgs.coreutils
      pkgs.grep
      pkgs.sed
      pkgs.util-linux
    ];
    runtimeClosures =
      [
        crucible
        qemuCrucible
        cruciblePlugin
        linuxCrucible
        crucibleFixtures
        e2eNativeRunnerPackage
      ]
      ++ extraClosure ++ gateResults;
    runtimeEnvironment = {
      CRUCIBLE = crucible;
      CRUCIBLE_QEMU = qemuBinary;
      CRUCIBLE_PLUGIN = pluginLibrary;
      CRUCIBLE_KERNEL = kernelImage;
      CRUCIBLE_ROOT_IMAGE = rootImage;
      CRUCIBLE_KERNEL_CMDLINE = "${linuxCrucible.passthru.crucibleFixtureKernelCmdline} init=/init";
      LINUX_CRUCIBLE = linuxCrucible;
      CRUCIBLE_FIXTURES = crucibleFixtures;
      CRUCIBLE_E2E_NATIVE_RUNNER = e2eNativeRunner;
    };
    executionScript = ''
      set -eu

      FLEET_WORKDIR="$TMPDIR/crucible-fleet-workdir"
      CRUCIBLE_SCRATCH="$FLEET_WORKDIR"
      FLEET_STORE="$FLEET_WORKDIR/store"
      FLEET_ARTIFACTS="$FLEET_WORKDIR/artifacts"
      CRUCIBLE_RUN_STATE_ROOT="$FLEET_WORKDIR/run-state"
      mkdir -p "$FLEET_STORE" "$FLEET_ARTIFACTS" "$CRUCIBLE_RUN_STATE_ROOT"
      export FLEET_WORKDIR CRUCIBLE_SCRATCH FLEET_STORE FLEET_ARTIFACTS CRUCIBLE_RUN_STATE_ROOT

      test -x "$CRUCIBLE/bin/crucible"
      test -x "$CRUCIBLE_QEMU"
      test -e "$CRUCIBLE_PLUGIN"
      test -e "$CRUCIBLE_KERNEL"
      test -e "$CRUCIBLE_ROOT_IMAGE"
      test -e "$LINUX_CRUCIBLE"
      test -e "$CRUCIBLE_FIXTURES"
      test -f "$CRUCIBLE_E2E_NATIVE_RUNNER"

      ${gateAssertions}
      ${runPhaseScript}

      mkdir -p "$out"
      cat > "$out/result" <<RESULT
      PASS
      check=${checkPath}
      fleet_check_surface=checks.fleet.${name}
      vm_runner=tcg-only
      tcg_only=true
      required_system_features=none
      kvm_required=false
      hermetic_closure=crucible,qemu-crucible,crucible-qemu-plugin,linux-crucible,crucible-fixtures
      crucible_cli=${crucible}/bin/crucible
      qemu_crucible=${qemuBinary}
      crucible_plugin=${pluginLibrary}
      linux_crucible=${linuxCrucible}
      crucible_fixtures=${crucibleFixtures}
      durable_process_recovery_state=$CRUCIBLE_RUN_STATE_ROOT
      ${extraResultText}RESULT
    '';
  in
    if campaignComposition != null
    then
      assert testing != null;
      assert gateName != null;
        import ./phase9-campaign-mode-system-gate.nix {
          inherit pkgs lib testing runtimeInputs runtimeClosures runtimeEnvironment;
          inherit (campaignComposition) mode system;
          runtimeScript = executionScript;
          name = "fleet-${name}";
          inherit gateName authoritativeAttr executionFamily;
          timeout = 10800;
          memoryMiB = 8192;
          varSizeMiB = 16384;
        }
    else
      pkgs.mkDerivation {
        pname = name;
        version = "0";
        src = null;

        # The whole Crucible closure is a hermetic build input ([PKG-1], [PKG-29]).
        # `crucible` carries qemu-crucible + crucible-qemu-plugin through its
        # runtimeDeps, so listing it pulls the patched QEMU + plugin into the
        # closure; the kernel and fixtures are added explicitly.
        buildDeps = runtimeInputs ++ runtimeClosures;

        # DELIBERATELY no `requiredSystemFeatures = [ "kvm" ]`: [PKG-30] mandates
        # TCG-only so this runs on any CI runner without nested virtualization.

        phases = [
          {
            name = "run-crucible-fleet-scenario";
            script = ''
              ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: value: "export ${name}=${lib.escapeShellArg (toString value)}") runtimeEnvironment)}
              ${executionScript}
            '';
          }
        ];
      };
in {
  inherit mkCrucibleFleetCheck e2eNativeRunner;
}
