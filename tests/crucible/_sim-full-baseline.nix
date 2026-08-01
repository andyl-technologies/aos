# Shared sim-mode determinism baseline for the fully-patched qemu-crucible:
# boots the full binary twice under the diskless sim workload and asserts the
# two runs are byte-identical (the hard-assert side of the drop-one behavioral
# discriminator -- the full series is deterministic, the same claim the inert
# and fingerprint gates make). Emits the deterministic fingerprint for the
# per-patch variant-divergence probes to compare against.
{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  attrPath ? "checks.crucible.phase2.gates.patchMicrotests.dropOne.simFullBaseline",
}: let
  workload = import ./_sim-workload.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-sim-full-baseline";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.gawk pkgs.grep qemuPackage];
    FULL_QEMU = "${qemuPackage}/bin/qemu-system-x86_64";
    FIRMWARE = "${qemuPackage}/share/qemu";
    phases = [
      {
        name = "sim-full-baseline";
        script = ''
          set -eu
          export LC_ALL=C
          export SIM_DEBUG_OBSERVABLES=1
          mkdir -p "$out"
          ${workload.probeLib}
          f1=$(sim_fingerprint "$FULL_QEMU" "$FIRMWARE")
          f2=$(sim_fingerprint "$FULL_QEMU" "$FIRMWARE")
          test -n "$f1" || { echo "FAIL: full sim boot produced no fingerprint (run 1)" >&2; exit 1; }
          if [ "$f1" != "$f2" ]; then
            echo "FAIL: fully-patched qemu-crucible is NOT deterministic under sim: $f1 != $f2" >&2
            exit 1
          fi
          printf '%s\n' "$f1" > "$out/fingerprint"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:patch-microtests
          full_series_sim_boot_deterministic=true
          full_series_sim_fingerprint=$f1
          RESULT
        '';
      }
    ];
  }
