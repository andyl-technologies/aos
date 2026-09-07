# Certifies the named native block fixtures retained by the QEMU package.
# This is deliberately not a whole-world fork or child-I/O certificate.
{
  pkgs,
  qemuPackage ? pkgs.qemu-crucible,
  attrPath ? "checks.crucible.phase6.qemuReadOnlyBlockSource",
  taskIds ? [],
}:
pkgs.mkDerivation {
  pname = "crucible-phase6-qemu-read-only-block-source";
  version = "0";
  src = null;
  buildDeps = [pkgs.coreutils pkgs.grep];

  phases = [
    {
      name = "certify-native-block-source";
      script = ''
        set -eu
        mkdir -p "$out"
        transcript="${qemuPackage}/share/aos/crucible/block-backend-tests.tap"
        grep -Eq '^ok [0-9]+ /block-backend/hot_fork_snapshot_binding$' "$transcript"
        grep -Eq '^ok [0-9]+ /block-backend/hot_fork_source_writable_file$' "$transcript"
        if grep -Eq '^(not ok|Bail out!)|# SKIP' "$transcript"; then
          echo "Native block-source evidence contains a failure or skipped case" >&2
          exit 1
        fi
        cp "$transcript" "$out/block-backend-tests.tap"
        cp "${qemuPackage}/share/aos/crucible/qemu-build-identity.env" "$out/"
        cat > "$out/result" <<'RESULT'
        PASS
        check=${attrPath}
        tasks=${builtins.concatStringsSep "," taskIds}
        patch=0197-crucible-retain-read-only-block-sources.patch
        native_source_freeze_restore=true
        writable_descendant_rejected_and_restored=true
        inherited_parent_token_rejected=true
        whole_world_child_handoff=false
        RESULT
      '';
    }
  ];
}
