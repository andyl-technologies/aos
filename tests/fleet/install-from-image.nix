# tests/fleet/install-from-image.nix - The installation guide, as a test.
#
# RFC-0003: the de-facto AOS install flow, end to end, using only what a
# new user has — the published raw image, an Ignition config, and apm:
#
#   1. INSTALL  — boot the stock raw image under OVMF (UEFI → sd-boot →
#                 UKI → initrd → ignition). The fw_cfg-delivered config
#                 partitions the disk: grow root-a, create root-b, swap
#                 and var (the A/B layout from docs/boot/qemu-uefi.md,
#                 sized down for CI), format the filesystems.
#   2. BOOT     — first boot reaches multi-user.target; the layout and
#                 the aos-growfs filesystem growth are asserted. This is
#                 the first CI exercise of the sd-boot/UKI path, the
#                 qemu/fw_cfg ignition platform, and the disks stage.
#   3. UPDATE   — `apm registry add` + `apm update` against a registry
#                 peer over the fleet L2.
#   4. INSTALL  — `apm install bc` downloads a package off the wire
#                 (bc is deliberately NOT in the image's closure).
#   5. UPGRADE  — `apm upgrade --system` pulls the server-2 generation
#                 from the registry's static cache, switches live, then
#                 the machine REBOOTS through UEFI and must come back on
#                 the new generation.
#
# The target machine boots the production server image fully stock; only
# the package set carries the test agent that lets the harness drive the
# machine. The agent is delivered by the bundled aos-test-agent role
# (modules/roles/aos-test-agent.nix), which the fleet harness activates
# automatically on every non-baked machine (lib/testing/fleet.nix).
#
# Machines (lexicographic order: registry=192.168.50.10, target=.11):
#   registry: kernel-boot peer publishing the registry + static cache
#             (same shape as apm-registry-upgrade.nix), with the
#             server-2 toplevel and bc pre-staged in its store.
#   target:   image-boot (bootMode = "image"), no metadata ISO, ignition
#             config over fw_cfg with the FULL profile (storage.disks).
{
  lib,
  pkgs,
  systems,
}: let
  server2Top = systems.server-2.config.system.build.toplevel;

  # Partition sizes (MiB). The docs' production layout is 16 GiB per
  # root; CI uses a smaller A/B layout — same shape, same labels.
  rootSizeMiB = 6144;
  swapSizeMiB = 1024;
  diskSizeMiB = 16384;
in {
  name = "install-from-image";
  # First boot does real partitioning + mkfs; the publish step
  # zstd-compresses the full server-2 closure; the upgrade pulls the
  # generation delta over the L2; then a full UEFI reboot. Budgeted
  # like apm-registry-upgrade plus the reboot.
  timeout = 2400;

  machines = {
    registry = {
      system = systems.server;
      roles = ["aos-registry-server" "test-http-server"];
      extraClosures = [server2Top pkgs.bc];
      # Static cache of the full closure lands under /var/lib. The server-2
      # closure has grown past the old 1536 MiB margin (the zstd cache now
      # overflows it mid-generation: "No space left on device"), so give
      # /var more room.
      varSizeMiB = 3072;
    };

    target = {
      system = systems.server;
      bootMode = "image";
      imageDiskMiB = diskSizeMiB;
      instanceMetadata = {
        format = "ignition";
        config = {
          storage = {
            disks = [
              {
                device = "/dev/vda";
                wipeTable = false;
                partitions = [
                  {
                    number = 2;
                    label = "root-a";
                    sizeMiB = rootSizeMiB;
                    resize = true;
                    typeGuid = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
                  }
                  {
                    number = 3;
                    label = "root-b";
                    sizeMiB = rootSizeMiB;
                    typeGuid = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
                  }
                  {
                    number = 4;
                    label = "swap";
                    sizeMiB = swapSizeMiB;
                    typeGuid = "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F";
                  }
                  {
                    number = 5;
                    label = "var";
                    sizeMiB = 0; # rest of the disk
                  }
                ];
              }
            ];
            filesystems = [
              {
                device = "/dev/disk/by-partlabel/root-b";
                format = "ext4";
                label = "aos-root-b";
                wipeFilesystem = false;
              }
              {
                device = "/dev/disk/by-partlabel/var";
                format = "ext4";
                label = "aos-var";
                wipeFilesystem = false;
              }
            ];
          };
        };
      };
    };
  };

  testScript =
    # python
    ''
      import textwrap

      # ════ 1+2. INSTALL + BOOT ═════════════════════════════════════════
      # Reaching this point already proves a lot: the driver's agent
      # handshake + system-ready gate ran against a machine that booted
      # the stock raw image via OVMF/sd-boot/UKI, whose ignition (qemu
      # platform, fw_cfg channel) partitioned and formatted the disk and
      # merged the aos-test-agent role fragment at first boot.
      target.succeed("systemctl is-active multi-user.target")

      # The declared install layout exists.
      for label in ("root-a", "root-b", "swap", "var"):
          target.succeed(f"test -e /dev/disk/by-partlabel/{label}")

      # ignition-disks grew root-a (vda2) to exactly ${toString rootSizeMiB} MiB.
      sectors = int(target.succeed("cat /sys/class/block/vda2/size").strip())
      expected = ${toString rootSizeMiB} * 2048  # MiB -> 512-byte sectors
      assert sectors == expected, (
          f"root-a is {sectors} sectors, expected {expected}"
      )

      # aos-growfs grew the root ext4 into the resized partition: the
      # filesystem must report close to the partition size, far above
      # the image's sized-to-fit original.
      blocks, bsize = map(int, target.succeed(
          "stat -f -c '%b %S' /"
      ).split())
      fs_bytes = blocks * bsize
      assert fs_bytes > ${toString (rootSizeMiB * 9 / 10)} * 1024 * 1024, (
          f"root fs is {fs_bytes} bytes; aos-growfs did not grow it"
      )

      # /var is the ignition-created partition, mounted by partlabel.
      var_dev = target.succeed(
          "readlink -f /dev/disk/by-partlabel/var"
      ).strip()
      mounts = target.succeed("cat /proc/mounts")
      assert f"{var_dev} /var " in mounts, (
          f"/var not mounted from {var_dev}:\n{mounts}"
      )

      # First boot seeded the system profile at gen-1.
      gen = target.succeed("readlink /var/lib/profiles/system/current").strip()
      assert gen == "gen-1", f"expected gen-1 after install, got {gen!r}"

      # ════ Producer: publish a package + the gen-2 system ══════════════
      # Same producer block as apm-registry-upgrade.nix, plus a regular
      # (non-sysroot) bc package for the `apm install` leg.
      registry.wait_for_unit("aos-registry-server-gitd.service", timeout=120)
      registry.wait_for_unit("test-http-server.service", timeout=120)
      registry.wait_until_succeeds(
          "systemctl is-active aos-nix-db.service", timeout=120
      )
      registry.succeed(textwrap.dedent("""
          set -eu
          export HOME=/tmp
          export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test
          export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/nix-conf
          mkdir -p "$NIX_CONF_DIR"
          printf 'experimental-features = nix-command\\nsandbox = false\\n' \\
            > "$NIX_CONF_DIR/nix.conf"

          ${pkgs.aos}/bin/apr create sysreg
          REG_DIR=$HOME/.local/share/apm/registries/sysreg
          DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
          ORIGIN=/var/lib/aos-registry-server/registries/sysreg
          git init --bare --object-format=sha256 "$ORIGIN"
          git -C "$ORIGIN" symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
          git -C "$REG_DIR" remote add origin "$ORIGIN"

          ${pkgs.aos}/bin/apr publish '${pkgs.bc}' \\
            --name bc \\
            --version 1.0.0 \\
            --description 'install-from-image package fixture' \\
            --license BSD-3-Clause \\
            --maintainer test \\
            --registry sysreg \\
            --no-commit

          ${pkgs.aos}/bin/apr publish '${server2Top}' \\
            --name aos \\
            --version test-2 \\
            --description 'install-from-image system fixture' \\
            --license MIT \\
            --maintainer test \\
            --sysroot \\
            --registry sysreg \\
            --no-commit
          ${pkgs.aos}/bin/apr verify --registry sysreg

          ${pkgs.aos}/bin/apr cache generate \\
            --registry sysreg \\
            --output /var/lib/sysreg-cache \\
            --cache-url http://registry:8000/sysreg-cache \\
            --priority 46 \\
            --no-commit
          chmod -R a+rX /var/lib/sysreg-cache

          git -C "$REG_DIR" add -A
          git -C "$REG_DIR" commit -m 'release: install fixtures'
          git -C "$REG_DIR" tag v1.0.0
          git -C "$REG_DIR" push origin "$DEFAULT_BRANCH" --tags
          chown -R aos-gitd:aos-gitd "$ORIGIN"
          echo "$DEFAULT_BRANCH" > /tmp/sysreg-branch
      """), timeout=1200)

      branch = registry.succeed("cat /tmp/sysreg-branch").strip()

      # The image has no merged /usr/bin — host tools are reached by
      # store path (the agent only carries coreutils/bash/systemd on
      # its PATH).
      target.wait_until_succeeds(
          "${pkgs.curl}/bin/curl -sf --max-time 5 "
          "http://registry:8000/sysreg-cache/nix-cache-info",
          timeout=60,
      )

      # ════ 3. UPDATE — registry add + metadata sync, pure porcelain ════
      target.succeed(
          f"HOME=/tmp USER=root PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH ${pkgs.aos}/bin/apm registry add --no-verify "
          f"git://registry:9418/sysreg --name sysreg --branch {branch} 2>&1",
          timeout=120,
      )
      target.succeed(
          "HOME=/tmp USER=root PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH ${pkgs.aos}/bin/apm update 2>&1", timeout=120
      )
      out = target.succeed(
          "HOME=/tmp USER=root PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH ${pkgs.aos}/bin/apm search bc 2>&1",
          timeout=60,
      )
      assert "bc" in out, f"apm search did not surface bc: {out!r}"

      # ════ 4. INSTALL a package — closure must come off the wire ═══════
      target.fail("${pkgs.nix}/bin/nix-store --check-validity '${pkgs.bc}'")
      out = target.succeed(
          "HOME=/tmp USER=root PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH ${pkgs.aos}/bin/apm install bc "
          "--registry sysreg --yes 2>&1",
          timeout=600,
      )
      assert "Downloading" in out, (
          f"apm install did not download anything: {out!r}"
      )
      out = target.succeed(
          "HOME=/tmp USER=root PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH ${pkgs.aos}/bin/apm list --installed 2>&1"
      )
      assert "bc" in out, f"bc missing from apm list: {out!r}"
      target.succeed(
          "/var/lib/profiles/per-user/root/current/bin/bc --version"
      )

      # ════ 5. UPGRADE the system, then reboot into it ══════════════════
      # System scope: /etc/apm/registries.d config + git clone into
      # /var/lib/apm/registries (`apm update` has no --system flag; this
      # is the documented system-scope sync, same as
      # tests/vm/apm/e2e.nix's e2e-system-lifecycle).
      target.succeed(textwrap.dedent("""
          set -eu
          mkdir -p /etc/apm/registries.d /var/lib/apm/registries \\
            /var/lib/apm/remote /var/lib/apm/cache
          cat > /etc/apm/registries.d/sysreg.toml <<'EOF'
          [registry]
          name = "sysreg"
          url = "git://registry:9418/sysreg"
          priority = 500
          enabled = true

          [registry.signing]
          required = false
          EOF
          ${pkgs.git}/bin/git clone git://registry:9418/sysreg \\
            /var/lib/apm/registries/sysreg
          ln -sfn /var/lib/apm/registries/sysreg /var/lib/apm/remote/sysreg
      """), timeout=120)

      out = target.succeed(
          "HOME=/tmp PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH ${pkgs.aos}/bin/apm upgrade --system --dry-run 2>&1",
          timeout=120,
      )
      assert "test-2" in out, f"dry-run did not surface test-2: {out!r}"

      out = target.succeed(
          "HOME=/tmp PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH ${pkgs.aos}/bin/apm upgrade --system --yes 2>&1",
          timeout=900,
      )
      print("=== apm upgrade --system output ===\n" + out)
      assert "Downloading" in out, (
          f"system upgrade did not download the generation delta: {out!r}"
      )

      gen = target.succeed("readlink /var/lib/profiles/system/current").strip()
      assert gen == "gen-2", f"expected gen-2 after upgrade, got {gen!r}"
      osrel = target.succeed("cat /etc/os-release")
      assert "VERSION_ID=test-2" in osrel, osrel


      # Reboot through the full UEFI path. The upgraded generation and
      # the user-installed package live on /var and must survive.
      target.reboot()
      target.succeed("systemctl is-active multi-user.target")

      gen = target.succeed("readlink /var/lib/profiles/system/current").strip()
      assert gen == "gen-2", f"generation reverted across reboot: {gen!r}"
      osrel = target.succeed("cat /etc/os-release")
      assert "VERSION_ID=test-2" in osrel, (
          f"booted system is not the upgraded generation:\n{osrel}"
      )
      target.succeed(
          "/var/lib/profiles/per-user/root/current/bin/bc --version"
      )
      failed = target.succeed("systemctl --failed --no-legend").strip()
      assert not failed, f"failed units after reboot: {failed!r}"
    '';
}
