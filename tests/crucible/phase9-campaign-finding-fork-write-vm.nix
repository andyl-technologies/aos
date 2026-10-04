# Independent copied-bundle QEMU fork with one noncanonical debugger write.
{
  pkgs,
  lib,
}: let
  flight = import ./phase4-packaged-campaign-vm.nix {
    inherit pkgs lib;
    findingForkWrite = true;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-finding-fork-write-vm";
    version = "0";

    buildDeps = [pkgs.coreutils pkgs.grep flight];

    phases = [
      {
        name = "retain-finding-fork-evidence";
        script = ''
          set -eu
          serial=${flight}/serial.log
          test -f "$serial"

          require_serial_line() {
            line="$1"
            test "$(grep -Fxc "$line" "$serial" || true)" -eq 1
          }

          require_serial_line gate=gate:campaign-finding-fork-write
          require_serial_line finding_bundle_fork_source_owner_absent=true
          require_serial_line finding_bundle_two_live_packaged_qemu=true
          require_serial_line finding_bundle_noncanonical_register_write=true
          require_serial_line finding_bundle_canonical_checkpoint_and_bundle_unchanged=true
          require_serial_line finding_bundle_fork_qemu_teardown=true
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$serial"

          mkdir -p "$out/evidence"
          cp "$serial" "$out/evidence/finding-fork-write-vm.output"
          sha256sum "$out/evidence/finding-fork-write-vm.output" > "$out/evidence.sha256"
          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-finding-fork-write
          finding_bundle_fork_source_owner_absent=true
          finding_bundle_two_live_packaged_qemu=true
          finding_bundle_noncanonical_register_write=true
          finding_bundle_canonical_checkpoint_and_bundle_unchanged=true
          finding_bundle_fork_qemu_teardown=true
          RESULT
        '';
      }
    ];

    passthru = {
      rawFlight = flight;
    };
  }
