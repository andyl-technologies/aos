# Live nonauthorizing replay of initialized Cache journals through the root-only view.
{
  lib,
  testing,
  pkgs,
}: let
  probe = pkgs.mkCargoPackage {
    pname = "aos-sandbox-cache-readonly-vm-probe";
    version = "0.0.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-service-journal-probe --bin aos-sandbox-cache-readonly-vm-probe";
    doCheck = false;
    buildDeps = [pkgs.protobuf];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    runtimeDeps = [];
  };
in
  testing.mkVMTest {
    name = "sandbox-cache-journal-readonly-replay";
    rootfsDeps = [probe pkgs.bash pkgs.coreutils pkgs.util-linux];
    memory = 512;
    testScript = ''
      set -eu
      exec > /dev/ttyS0 2>&1
      set -x
      unset LD_LIBRARY_PATH

      source=/var/lib/aos/sandbox/cache-residency-journals
      controller=/var/lib/aos/sandboxd/cache-residency-authority
      view=/run/aos/sandbox-policy-cache-journals
      mkdir -p /var/lib/aos/sandbox /var/lib/aos/sandboxd /run/aos
      # The minimal VM rootfs creates /run as 1777; protected ancestry requires
      # the root-owned non-writable /run used by the installed system.
      chmod 0755 /run /var/lib/aos /var/lib/aos/sandbox /var/lib/aos/sandboxd /run/aos
      mkdir -m 0700 "$source" "$controller" "$view"
      chown 811:811 "$source" "$controller"

      ${pkgs.coreutils}/bin/chroot --userspec=+811:+811 --groups= / \
        ${probe}/bin/aos-sandbox-cache-readonly-vm-probe initialize

      for name in state.journal authority.journal clock.journal; do
        ${pkgs.coreutils}/bin/stat -c '%n:%s:%u:%g:%a' "$source/$name"
        test -f "$source/$name"
        test -f "$source/$name.lock"
        test "$(stat -c '%u:%g:%a' "$source/$name")" = 811:811:600
      done
      test -s "$source/authority.journal"
      test -s "$source/clock.journal"

      ${pkgs.util-linux}/bin/mount --bind \
        --map-users 811:0:1 --map-groups 811:0:1 \
        --options ro,nosuid,nodev,noexec,nosymfollow \
        "$source" "$view"
      trap '${pkgs.util-linux}/bin/umount --no-canonicalize /run/aos/sandbox-policy-cache-journals' EXIT
      test "$(stat -c '%u:%g:%a' /run)" = 0:0:755
      test "$(stat -c '%u:%g:%a' "$view")" = 0:0:700
      for name in state.journal authority.journal clock.journal; do
        test "$(stat -c '%u:%g:%a' "$view/$name")" = 0:0:600
        test "$(stat -c '%u:%g:%a' "$view/$name.lock")" = 0:0:600
      done

      snapshot() {
        ${pkgs.coreutils}/bin/ls -A "$source"
        ${pkgs.coreutils}/bin/stat -c '%n:%d:%i:%s:%Y:%Z:%a:%u:%g' "$source"/*
        ${pkgs.coreutils}/bin/sha256sum "$source"/*
      }
      read_as_root_without_capabilities() {
        ${pkgs.util-linux}/bin/setpriv \
          --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
          ${probe}/bin/aos-sandbox-cache-readonly-vm-probe read
      }

      before="$(snapshot)"
      read_as_root_without_capabilities
      test "$(snapshot)" = "$before"

      for name in state.journal authority.journal clock.journal; do
        ${pkgs.coreutils}/bin/mv "$source/$name" "$source/$name.away"
        before="$(snapshot)"
        if read_as_root_without_capabilities; then
          exit 1
        fi
        test ! -e "$source/$name"
        test "$(snapshot)" = "$before"
        ${pkgs.coreutils}/bin/mv "$source/$name.away" "$source/$name"
      done

      before="$(snapshot)"
      read_as_root_without_capabilities
      test "$(snapshot)" = "$before"

      ${pkgs.util-linux}/bin/umount --no-canonicalize "$view"
      trap - EXIT
    '';
  }
