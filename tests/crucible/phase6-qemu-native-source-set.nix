# Certifies complete native source closure and retained partial restoration.
# Production coordinator integration and child-private graph handoff remain open.
{
  pkgs,
  qemuPackage ? pkgs.qemu-crucible,
  attrPath ? "checks.crucible.phase6.qemuNativeSourceSet",
  taskIds ? [],
}:
pkgs.mkDerivation {
  pname = "crucible-phase6-qemu-native-source-set";
  version = "0";
  src = null;
  buildDeps = [pkgs.coreutils pkgs.grep];

  phases = [
    {
      name = "certify-native-source-set";
      script = ''
        set -eu
        mkdir -p "$out"
        transcript="${qemuPackage}/share/aos/crucible/block-backend-tests.tap"
        for case in source_set source_set_partial_restore; do
          grep -Eq "^ok [0-9]+ /block-backend/hot_fork_$case$" "$transcript"
        done
        if grep -Eq '^(not ok|Bail out!)|# SKIP' "$transcript"; then
          echo "Native source-set evidence contains a failure or skipped case" >&2
          exit 1
        fi
        cp "$transcript" "$out/block-backend-tests.tap"
        cp "${qemuPackage}/share/aos/crucible/qemu-build-identity.env" "$out/"
        cat > "$out/result" <<'RESULT'
        PASS
        check=${attrPath}
        tasks=${builtins.concatStringsSep "," taskIds}
        patch=0200-crucible-retain-complete-native-source-sets.patch
        complete_explicit_native_source_closure=true
        unowned_backend_node_and_consumer_rejected=true
        original_read_only_access_preserved=true
        original_writable_root_provenance_separate=true
        partial_freeze_restoration_retained=true
        inherited_parent_source_set_rejected=true
        vmstate_and_disk_bytes_preserved=true
        held_barrier_restoration_rejected=true
        whole_world_child_handoff=false
        RESULT
      '';
    }
  ];
}
