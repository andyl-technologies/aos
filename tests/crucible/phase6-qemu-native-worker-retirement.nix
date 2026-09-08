# Certifies actual native child I/O and the worker-retirement rejection paths.
# This is not a production coordinator or whole-world child-handoff certificate.
{
  pkgs,
  qemuPackage ? pkgs.qemu-crucible,
  attrPath ? "checks.crucible.phase6.qemuNativeWorkerRetirement",
  taskIds ? [],
}:
pkgs.mkDerivation {
  pname = "crucible-phase6-qemu-native-worker-retirement";
  version = "0";
  src = null;
  buildDeps = [pkgs.coreutils pkgs.grep];

  phases = [
    {
      name = "certify-native-worker-retirement";
      script = ''
        set -eu
        mkdir -p "$out"
        transcript="${qemuPackage}/share/aos/crucible/block-backend-tests.tap"
        for case in unowned_writable_source pending_native_worker \
          native_worker_retirement_rejections native_io_after_worker_retirement; do
          grep -Eq "^ok [0-9]+ /block-backend/hot_fork_$case$" "$transcript"
        done
        if grep -Eq '^(not ok|Bail out!)|# SKIP' "$transcript"; then
          echo "Native worker evidence contains a failure or skipped case" >&2
          exit 1
        fi
        cp "$transcript" "$out/block-backend-tests.tap"
        cp "${qemuPackage}/share/aos/crucible/qemu-build-identity.env" "$out/"
        cat > "$out/result" <<'RESULT'
        PASS
        check=${attrPath}
        tasks=${builtins.concatStringsSep "," taskIds}
        patch=0198-crucible-retire-native-workers-before-hot-fork.patch
        inherited_native_workers_negative_control=true
        native_child_source_read=true
        durable_child_private_overlay_write=true
        parent_source_unchanged=true
        pending_work_and_foreign_contexts_rejected=true
        held_barrier_rejected_without_wait=true
        unowned_writable_nodes_rejected=true
        whole_world_child_handoff=false
        RESULT
      '';
    }
  ];
}
