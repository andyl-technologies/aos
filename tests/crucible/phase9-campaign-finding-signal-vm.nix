# A copied exact finding retains a committed QEMU fault and later guest response.
{
  pkgs,
  lib,
}: let
  flight = import ./phase4-packaged-campaign-vm.nix {
    inherit pkgs lib;
    findingSignalBundle = true;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-finding-signal-vm";
    version = "0";

    buildDeps = [pkgs.coreutils pkgs.grep flight];

    phases = [
      {
        name = "retain-finding-signal-evidence";
        script = ''
          set -eu
          serial=${flight}/serial.log
          test -f "$serial"

          require_serial_line() {
            line="$1"
            test "$(grep -Fxc "$line" "$serial" || true)" -eq 1
          }

          require_serial_line gate=gate:campaign-finding-signal-bundle
          require_serial_line finding_bundle_selected_fault_and_guest_response=true
          require_serial_line finding_bundle_signal_archive_unchanged=true
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$serial"

          mkdir -p "$out/evidence"
          cp "$serial" "$out/evidence/finding-signal-vm.output"
          sha256sum "$out/evidence/finding-signal-vm.output" > "$out/evidence.sha256"
          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-finding-signal-bundle
          finding_bundle_selected_fault_and_guest_response=true
          finding_bundle_signal_archive_unchanged=true
          RESULT
        '';
      }
    ];

    passthru = {
      rawFlight = flight;
    };
  }
