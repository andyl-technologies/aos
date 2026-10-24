# Dedicated native helper evidence. This artifact is deliberately outside gate
# auto-discovery and does not qualify complete cache admission or cancellation.
{
  pkgs,
  lib,
  sourceGateWithInputs,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  image =
    sourceGateWithInputs {
      preserveArtifactBytes = true;
      extraBuildDeps = [pkgs.binutils];
      runtimeDeps = [pkgs.rust pkgs.rust.dev] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
    } "host-quota-proof-image" ''
      cd crates
      cargo test --frozen --offline -p terrane-linux --lib \
        --test host_quota_protocol --test host_quota_native \
        --no-run --message-format=json > "$TMPDIR/host-quota-build.jsonl"
      cargo test --frozen --offline -p aos-terrane-integration --lib --test host_quota_config \
        --no-run --message-format=json >> "$TMPDIR/host-quota-build.jsonl"
      cargo metadata --frozen --offline --no-deps --format-version=1 \
        > "$TMPDIR/host-quota-packages.json"
      rustc --print target-libdir > "$TMPDIR/host-quota-rust-libdir"
      python3 ${../../crates/terrane/integration/aos-terrane-integration/src/host/proof_image.py} ${./.}
    '';
  native = testing.mkVMTest {
    name = "terrane-host-quota-helper-ext4";
    memory = 1024;
    rootfsDeps = [image pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs];
    testScript = ''
      set -eu
      mount -o remount,rw /
      mkdir -p /var/lib/terrane-host-quota-proof /mnt/terrane-host-quota
      truncate -s 96M /var/lib/terrane-host-quota-proof/quota.img
      mkfs.ext4 -F -O project,quota,verity -E quotatype=prjquota /var/lib/terrane-host-quota-proof/quota.img
      mount -t ext4 -o loop,prjquota /var/lib/terrane-host-quota-proof/quota.img /mnt/terrane-host-quota
      trap 'umount /mnt/terrane-host-quota; rm -f /var/lib/terrane-host-quota-proof/quota.img; rmdir /mnt/terrane-host-quota /var/lib/terrane-host-quota-proof' EXIT
      export TERRANE_HOST_QUOTA_VM=1
      export TERRANE_HOST_QUOTA_ROOT=/mnt/terrane-host-quota/owner
      (cd ${image} && sha256sum --check share/elf-sha256sum)
      export LD_LIBRARY_PATH="$(cat ${image}/share/runtime-library-path)"
      ${image}/bin/host_quota_native --exact host_quota_native_privilege_and_helper_vm --ignored --nocapture
      # An unsupported unprivileged user namespace fails this proof; it is
      # never reported as an executed negative witness.
      export TERRANE_HOST_QUOTA_ROLE=userns
      setpriv --reuid 840 --regid 840 --clear-groups \
        unshare --user --map-root-user \
        ${image}/bin/host_quota_native --exact host_quota_vm_role --ignored --nocapture
      rmdir /mnt/terrane-host-quota/owner
      export TERRANE_HOST_QUOTA_ADMIN_ROOT=/mnt/terrane-host-quota
      setpriv --bounding-set=-all,+sys_admin,+dac_read_search,+fowner,+chown,+fsetid \
        --clear-groups --inh-caps=-all --ambient-caps=-all \
        ${image}/bin/host_quota_config --exact host_quota_admin_ledger_preserves_domain_and_project_vm --ignored --nocapture
      setpriv --bounding-set=-all,+sys_admin,+dac_read_search,+fowner,+chown,+fsetid \
        --clear-groups --inh-caps=-all --ambient-caps=-all \
        ${image}/bin/aos_terrane_integration --exact host::claims::tests::host_global_claims_preserve_crash_custody_vm --ignored --nocapture
      setpriv --bounding-set=-all,+sys_admin,+dac_read_search,+fowner,+chown,+fsetid \
        --clear-groups --inh-caps=-all --ambient-caps=-all \
        ${image}/bin/aos_terrane_integration --exact host::claims::provision_tests::host_global_provision_kill_restart_and_broker_vm --ignored --nocapture
    '';
  };
in {
  inherit image native;
}
