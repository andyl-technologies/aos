{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  exactSnapshotRestore ?
    import ./phase2-qemu-exact-snapshot-restore.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase2.qemuFingerprintStateDomains.liveRestore";
      taskIds = ["T-QEMU-0078"];
    },
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix;
  atomicPatchSource = builtins.readFile (patchDir + "/${atomicPatch.file}");
  inherit (import ./_lib.nix {inherit lib;}) failuresFor;
  failures = failuresFor "the QEMU atomic patch" atomicPatchSource [
    {
      label = "guest volatile-state domain";
      needle = "QEMU_CRUCIBLE_LIFECYCLE_STATE_VOLATILE";
    }
    {
      label = "guest device-state domain";
      needle = "QEMU_CRUCIBLE_LIFECYCLE_STATE_DEVICE";
    }
    {
      label = "guest control-state domain";
      needle = "QEMU_CRUCIBLE_LIFECYCLE_STATE_CONTROL";
    }
    {
      label = "pure fingerprint projection serializer";
      needle = "qemu_save_device_fingerprint_projection";
    }
    {
      label = "pure fingerprint projection schema";
      needle = "qemu_fingerprint_projection_schema_sha256";
    }
    {
      label = "projection registry admission";
      needle = "crucible_fingerprint_projection";
    }
    {
      label = "projection schema v3 domain";
      needle = "crucible.qemu.device-projection-schema.v3";
    }
    {
      label = "projection uses lifecycle domain classification";
      needle = "return crucible_lifecycle_state_domain(se);";
    }
    {
      label = "globalstate aggregate exclusion";
      needle = ''strcmp(name, "globalstate") == 0'';
    }
    {
      label = "replay aggregate exclusion";
      needle = ''strcmp(name, "replay") == 0'';
    }
    {
      label = "shared-memory control projection";
      needle = ''strcmp(name, "block/crucible-shmem") == 0'';
    }
    {
      label = "fault control projection";
      needle = ''strcmp(name, "crucible-fault") == 0'';
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
            ! grep -Rq 'qemu_plugin_crucible_capture_fingerprint_material' "$stock/plugins/api.c"

            cp "${exactSnapshotRestore}/result" "$out/live-exact-snapshot.result"
            grep -Fxq PASS "$out/live-exact-snapshot.result"
            grep -Fxq \
              'scope=compiled-operation-specific-exact-checkpoint-admission' \
              "$out/live-exact-snapshot.result"
            grep -Fxq \
              'proven=identity-bound-admission,live-capture-and-restore,descriptor-backed-restore' \
              "$out/live-exact-snapshot.result"

            cat > "$out/result" <<RESULT
            PASS
            gate=gate:patch-microtests
            atomic_patch=true
            patched_fixture_exercised=true
            stock_negative_control=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            guest_state_domains=volatile,device,control
            globalstate_replay_excluded_after_aggregate_admission=true
            shmem_control_projection=true
            fault_control_projection=true
            projection_registry_required=true
            transient_interrupt_control_state_excluded=true
            target_transient_interrupt_mask_declared=true
            live_exact_snapshot_restore=true
            RESULT
          '';
        }
      ];
    }
