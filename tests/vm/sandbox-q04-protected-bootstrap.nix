# Real protected-owner bootstrap prerequisite; no accepted Create or V8 authority.
{
  lib,
  testing,
  pkgs,
}: let
  probe = pkgs.mkCargoPackage {
    pname = "aos-sandbox-q04-bootstrap-vm-probe";
    version = "0.0.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoFlags = "-p aos-sandbox-service-journal-probe --bin aos-sandbox-q04-bootstrap-vm-probe --bin aos-sandbox-cache-physical-join-vm-probe";
    doCheck = false;
    buildDeps = [pkgs.protobuf];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    runtimeDeps = [];
  };
in
  testing.mkVMTest {
    name = "sandbox-q04-protected-bootstrap";
    rootfsDeps = [probe pkgs.bash pkgs.coreutils pkgs.e2fsprogs pkgs.util-linux];
    memory = 512;
    testScript = ''
      set -eu
      exec > /dev/ttyS0 2>&1
      set -x
      unset LD_LIBRARY_PATH

      mkdir -p /var/lib/aos/sandbox /var/lib/aos/sandboxd/cache-residency-authority /run/aos
      chmod 0755 /run /var/lib/aos /var/lib/aos/sandbox /run/aos
      chmod 0700 /var/lib/aos/sandboxd /var/lib/aos/sandboxd/cache-residency-authority
      chown 811:811 /var/lib/aos/sandboxd /var/lib/aos/sandboxd/cache-residency-authority

      truncate -s 128M /tmp/q04-bootstrap.img
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -q -b 4096 -O verity /tmp/q04-bootstrap.img
      mount -o loop,nosuid,nodev /tmp/q04-bootstrap.img /var/lib/aos/sandbox
      trap 'umount /var/lib/aos/sandbox' EXIT

      mkdir -m 0700 \
        /var/lib/aos/sandbox/source-domains \
        /var/lib/aos/sandbox/cache-residency-journals \
        /var/lib/aos/sandbox/cache-residency-objects \
        /var/lib/aos/sandbox/policy-compiler
      chown 811:811 \
        /var/lib/aos/sandbox/source-domains \
        /var/lib/aos/sandbox/cache-residency-journals \
        /var/lib/aos/sandbox/cache-residency-objects
      controller_probe() {
        ${pkgs.coreutils}/bin/chroot --userspec=+811:+811 --groups= / \
          ${probe}/bin/aos-sandbox-q04-bootstrap-vm-probe "$1"
      }
      controller_probe controller-bootstrap
      ${pkgs.coreutils}/bin/chroot --userspec=+811:+811 --groups= / \
        ${probe}/bin/aos-sandbox-cache-physical-join-vm-probe bootstrap-only
      ${probe}/bin/aos-sandbox-q04-bootstrap-vm-probe root-bootstrap
      ${probe}/bin/aos-sandbox-q04-bootstrap-vm-probe credentials-bootstrap

      chown -R 813:813 /run/credentials/aos-sandbox-cache-signerd.service
      chown -R 814:814 /run/credentials/aos-sandbox-source-signerd.service
      chown -R 811:811 /run/credentials/aos-sandboxd.service
      for service in aos-sandbox-cache-signerd aos-sandbox-source-signerd aos-sandboxd aos-sandbox-policy-authorityd; do
        test "$(stat -c '%a' "/run/credentials/$service.service")" = 700
      done
      for credential in \
        /run/credentials/aos-sandbox-cache-signerd.service/* \
        /run/credentials/aos-sandbox-source-signerd.service/* \
        /run/credentials/aos-sandboxd.service/* \
        /run/credentials/aos-sandbox-policy-authorityd.service/*; do
        test "$(stat -c '%a:%h' "$credential")" = 600:1
      done

      source=/var/lib/aos/sandbox/source-domains
      cache=/var/lib/aos/sandbox/cache-residency-journals
      objects=/var/lib/aos/sandbox/cache-residency-objects
      source_view=/run/aos/sandbox-source-signer-journal
      cache_view=/run/aos/sandbox-cache-signer-journals
      object_view=/run/aos/sandbox-cache-signer-objects
      root_view=/run/aos/sandbox-policy-cache-journals
      for view in "$source_view" "$cache_view" "$object_view" "$root_view"; do
        mkdir -m 0700 "$view"
      done
      mount_views() {
        ${pkgs.util-linux}/bin/mount --bind \
          --map-users 811:814:1 --map-groups 811:814:1 \
          --options ro,nosuid,nodev,noexec,nosymfollow "$source" "$source_view"
        ${pkgs.util-linux}/bin/mount --bind \
          --map-users 811:0:1 --map-groups 811:0:1 \
          --options ro,nosuid,nodev,noexec,nosymfollow "$cache" "$root_view"
        ${pkgs.util-linux}/bin/mount --bind \
          --map-users 811:813:1 --map-groups 811:813:1 \
          --options ro,nosuid,nodev,noexec,nosymfollow "$cache" "$cache_view"
        ${pkgs.util-linux}/bin/mount --bind \
          --map-users 811:813:1 --map-groups 811:813:1 \
          --options ro,nosuid,nodev,noexec,nosymfollow "$objects" "$object_view"
      }
      unmount_views() {
        for view in "$object_view" "$cache_view" "$root_view" "$source_view"; do
          ${pkgs.util-linux}/bin/umount --no-canonicalize "$view"
        done
      }
      mount_views
      trap 'unmount_views; umount /var/lib/aos/sandbox' EXIT

      for name in source-domains-v1.journal source-domains-v1.journal.lock; do
        test "$(stat -c '%d:%i' "$source/$name")" = "$(stat -c '%d:%i' "$source_view/$name")"
      done
      for journal in state authority clock policy-hold; do
        for suffix in journal journal.lock; do
          name="$journal.$suffix"
          test "$(stat -c '%d:%i' "$cache/$name")" = "$(stat -c '%d:%i' "$cache_view/$name")"
          test "$(stat -c '%d:%i' "$cache/$name")" = "$(stat -c '%d:%i' "$root_view/$name")"
        done
      done
      for name in owner-state .owner.lock; do
        test "$(stat -c '%d:%i' "$objects/$name")" = "$(stat -c '%d:%i' "$object_view/$name")"
      done

      signer_probe() {
        ${pkgs.util-linux}/bin/setpriv --reuid "$1" --regid "$1" --clear-groups \
          --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
          ${probe}/bin/aos-sandbox-q04-bootstrap-vm-probe "$2"
      }
      signer_probe 813 cache-signer-readback
      ${probe}/bin/aos-sandbox-q04-bootstrap-vm-probe root-cache-verify
      signer_probe 814 source-signer-reject-unheld
      root_credentials=/run/credentials/aos-sandbox-policy-authorityd.service
      mv "$root_credentials/cache-owner-readback-public-key" \
        "$root_credentials/cache-owner-readback-public-key.saved"
      cp "$root_credentials/source-hold-public-key" \
        "$root_credentials/cache-owner-readback-public-key"
      if ${probe}/bin/aos-sandbox-q04-bootstrap-vm-probe root-cache-verify; then
        exit 1
      fi
      mv "$root_credentials/cache-owner-readback-public-key.saved" \
        "$root_credentials/cache-owner-readback-public-key"
      if ${pkgs.util-linux}/bin/setpriv --reuid 814 --regid 814 --clear-groups \
        ${pkgs.coreutils}/bin/cat /run/credentials/aos-sandbox-cache-signerd.service/cache-signer-v2-seed >/dev/null 2>&1; then
        exit 1
      fi

      # Reopen every owner after a view teardown, then require the signer and
      # root-side Cache verification to work against the new live mounts.
      unmount_views
      mv "$source/source-domains-v1.journal" "$source/source-domains-v1.journal.away"
      if controller_probe controller-replay; then
        exit 1
      fi
      mv "$source/source-domains-v1.journal.away" "$source/source-domains-v1.journal"
      mv /var/lib/aos/sandbox/policy-compiler/state.journal \
        /var/lib/aos/sandbox/policy-compiler/state.journal.away
      if ${probe}/bin/aos-sandbox-q04-bootstrap-vm-probe root-replay; then
        exit 1
      fi
      mv /var/lib/aos/sandbox/policy-compiler/state.journal.away \
        /var/lib/aos/sandbox/policy-compiler/state.journal
      controller_probe controller-replay
      ${probe}/bin/aos-sandbox-q04-bootstrap-vm-probe root-replay
      ${probe}/bin/aos-sandbox-q04-bootstrap-vm-probe credentials-replay
      mount_views
      signer_probe 813 cache-signer-readback
      ${probe}/bin/aos-sandbox-q04-bootstrap-vm-probe root-cache-verify
      signer_probe 814 source-signer-reject-unheld

      unmount_views
      umount /var/lib/aos/sandbox
      trap - EXIT
    '';
  }
