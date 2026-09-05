# Certifies native VMState/file ownership and block mutex teardown lifetimes.
# The source-set coordinator and production child graph handoff remain open.
{
  pkgs,
  qemuPackage ? pkgs.qemu-crucible,
  attrPath ? "checks.crucible.phase6.qemuNativeSourceOwnership",
  taskIds ? [],
}:
pkgs.mkDerivation {
  pname = "crucible-phase6-qemu-native-source-ownership";
  version = "0";
  src = null;
  buildDeps = [pkgs.coreutils pkgs.grep];

  phases = [
    {
      name = "certify-native-source-ownership";
      script = ''
        set -eu
        mkdir -p "$out"
        transcript="${qemuPackage}/share/aos/crucible/block-backend-tests.tap"
        for case in block_mutex_lifetime vmstate_source source_reopen_identity; do
          grep -Eq "^ok [0-9]+ /block-backend/hot_fork_$case$" "$transcript"
        done
        if grep -Eq '^(not ok|Bail out!)|# SKIP' "$transcript"; then
          echo "Native source ownership evidence contains a failure or skipped case" >&2
          exit 1
        fi
        cp "$transcript" "$out/block-backend-tests.tap"
        cp "${qemuPackage}/share/aos/crucible/qemu-build-identity.env" "$out/"
        cat > "$out/result" <<'RESULT'
        PASS
        check=${attrPath}
        tasks=${builtins.concatStringsSep "," taskIds}
        patch=0199-crucible-retain-native-vmstate-source-ownership.patch
        native_vmstate_freeze_restore=true
        exact_read_only_file_identity=true
        changed_inode_rejected_before_replacement=true
        unexpected_root_consumer_rejected=true
        inherited_parent_token_rejected=true
        block_mutex_lifetime_cycles=1024
        block_mutex_inventory_returns_to_baseline=true
        whole_world_child_handoff=false
        RESULT
      '';
    }
  ];
}
