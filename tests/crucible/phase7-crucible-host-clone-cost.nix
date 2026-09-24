# Certifies host continuation sharing, private child ledgers, and native QEMU pairing.
{
  pkgs,
  attrPath ? "checks.crucible.phase7.gates.hostCloneCost.rawGate",
  taskIds ? [],
  nativeScaling,
}: let
  taskList = builtins.concatStringsSep "," taskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase7-host-clone-cost";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.sed nativeScaling];
    phases = [
      {
        name = "certify-host-clone-cost";
        script = ''
          set -eu
          grep -Fxq PASS ${nativeScaling}/result
          mkdir -p "$out/evidence"
          sed 's/\r$//' ${nativeScaling}/serial.log \
            > "$out/evidence/native-scaling.serial.log"
          evidence="$out/evidence/native-scaling.serial.log"
          grep -Fxq 'gate=gate:hot-fork-scaling' "$evidence"

          # Libtest joins a test's first printed metric to its status prefix.
          require_exact_metric() {
            test_name="$1"
            metric="$2"
            standalone_count=$(grep -Fxc "$metric" "$evidence" || true)
            prefixed_count=$(grep -Fxc \
              "test $test_name ... $metric" "$evidence" || true)
            [ "$((standalone_count + prefixed_count))" -eq 1 ]
          }
          require_exact_metric \
            vm_lifecycle::hot_fork::tests::host_continuation_clone_cost_is_bounded_across_siblings \
            host_continuation_siblings=64
          require_exact_metric \
            production_fault_runtime::checkpoint_codec::tests::fault_checkpoint_clone_cost_keeps_mutable_ledgers_private \
            fault_checkpoint_siblings=64
          for line in \
            host_immutable_object_bytes=33554432 \
            host_shared_backing_copies=1 \
            host_clone_private_growth_limit_kib=65536 \
            qemu_authentication_map_copies=1 \
            child_private_ledgers=network-adapter,pending-qemu-events \
            qemu_child_pairing=exact_source_boundary \
            production_whole_world_lifecycles=10000; do
            grep -Fxq "$line" "$evidence"
          done
          grep -Eq '^host_clone_private_growth_kib=[0-9]+$' "$evidence"
          grep -Eq '^host_clone_elapsed_micros=[0-9]+$' "$evidence"

          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:host-clone-cost
          tasks=${taskList}
          host_continuation_siblings=64
          host_immutable_object_bytes=33554432
          host_shared_backing_copies=1
          host_clone_private_growth_limit_kib=65536
          fault_checkpoint_siblings=64
          qemu_authentication_map_copies=1
          child_private_ledgers=network-adapter,pending-qemu-events
          qemu_child_pairing=exact_source_boundary
          RESULT
        '';
      }
    ];
  }
