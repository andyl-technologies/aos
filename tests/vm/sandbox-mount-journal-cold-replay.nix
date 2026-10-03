# Real UID-0 protected Mount journal commit and cold structural replay.
{
  lib,
  testing,
  pkgs,
}: let
  probe = pkgs.mkCargoPackage {
    pname = "aos-sandbox-mount-journal-vm-probe";
    version = "0.0.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-sandbox-service-journal-probe --bin aos-sandbox-mount-journal-vm-probe";
    doCheck = false;
    buildDeps = [pkgs.protobuf];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    runtimeDeps = [];
  };
in
  testing.mkVMTest {
    name = "sandbox-mount-journal-cold-replay";
    rootfsDeps = [probe pkgs.coreutils];
    memory = 256;
    testScript = ''
      set -eu
      exec > /dev/ttyS0 2>&1
      set -x
      unset LD_LIBRARY_PATH

      root=/var/lib/aos/sandbox-mount
      journal="$root/mount.journal"
      probe=${probe}/bin/aos-sandbox-mount-journal-vm-probe
      mkdir -p "$root"
      chmod 0755 /var /var/lib /var/lib/aos
      chmod 0700 "$root"
      test "$(${pkgs.coreutils}/bin/id -u)" = 0

      "$probe" commit
      test "$(stat -c '%u:%g:%a' "$root")" = 0:0:700
      test "$(stat -c '%u:%g:%a' "$journal")" = 0:0:600
      test "$(stat -c '%u:%g:%a' "$journal.lock")" = 0:0:600
      "$probe" replay
      ${pkgs.coreutils}/bin/chroot --userspec=+811:+811 --groups= / \
        "$probe" deny-open

      # A process exit during an incomplete append leaves only the committed
      # prefix authoritative. Reopen must truncate the partial tail exactly.
      before="$(${pkgs.coreutils}/bin/stat -c %s "$journal")"
      ${pkgs.coreutils}/bin/printf 'partial-frame' >> "$journal"
      "$probe" replay-partial-tail
      test "$(${pkgs.coreutils}/bin/stat -c %s "$journal")" = "$before"
      "$probe" replay

      chmod 0644 "$journal"
      "$probe" deny-open
      chmod 0600 "$journal"
      "$probe" replay
    '';
  }
