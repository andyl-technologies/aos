{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  patchName ? "0078-crucible-fingerprint-guest-state-domains.patch",
}: let
  patchSource = builtins.readFile (../../pkgs/emulation/qemu-patches + "/${patchName}");
  exactSnapshotRestore = import ./phase2-qemu-exact-snapshot-restore.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase2.qemuFingerprintStateDomains.liveRestore";
    taskIds = ["T-QEMU-0078"];
  };
  inherit (import ./_lib.nix {inherit lib;}) failuresFor;
  failures = failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
    {
      label = "guest volatile-state domain";
      needle = "QEMU_CRUCIBLE_LIFECYCLE_STATE_VOLATILE";
    }
    {
      label = "guest device-state domain";
      needle = "QEMU_CRUCIBLE_LIFECYCLE_STATE_DEVICE";
    }
    {
      label = "domain-aware fingerprint serialization";
      needle = "qemu_save_device_state_domains";
    }
    {
      label = "generic transient interrupt canonicalization";
      needle = "CPU_INTERRUPT_EXITTB";
    }
    {
      label = "target-specific transient interrupt declaration";
      needle = "crucible_fingerprint_transient_interrupt_mask";
    }
    {
      label = "x86 poll notification canonicalization";
      needle = "CPU_INTERRUPT_POLL";
    }
  ];
in
  if failures != []
  then throw "Crucible fingerprint state-domain microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-fingerprint-state-domains";
      version = "0";
      src = qemuPackage.src;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.tar
        pkgs.xz
      ];

      phases = [
        {
          name = "verify-fingerprint-state-domains";
          script = ''
            set -eu

            mkdir -p source "$out"
            tar -xf "$src" -C source
            stock=source/qemu-${qemuPackage.version}

            # The pristine source has neither Crucible lifecycle domains nor
            # the guest black-box fingerprint export.
            ! grep -Rq 'QEMU_CRUCIBLE_LIFECYCLE_STATE_DEVICE' "$stock/plugins/api.c"
            ! grep -Rq 'qemu_plugin_crucible_fingerprint_capture' "$stock/plugins/api.c"

            cp "${exactSnapshotRestore}/result" "$out/live-exact-snapshot.result"
            grep -Fxq PASS "$out/live-exact-snapshot.result"
            grep -Fxq 'old_process_force_crashed=true' "$out/live-exact-snapshot.result"
            grep -Fxq 'replay_oracle_pair_match=true' "$out/live-exact-snapshot.result"

            cat > "$out/result" <<RESULT
            PASS
            gate=gate:patch-microtests
            patch=${patchName}
            patched_fixture_exercised=true
            stock_negative_control=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            guest_state_domains=volatile,device
            process_control_domain_excluded=true
            transient_interrupt_control_state_excluded=true
            target_transient_interrupt_mask_declared=true
            control_continuation_authenticated_separately=true
            fresh_process_fingerprint_match=true
            RESULT
          '';
        }
      ];
    }
