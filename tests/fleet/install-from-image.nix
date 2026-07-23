# tests/fleet/install-from-image.nix - The installation guide, as a test.
#
# The AOS install flow, end to end, using only
# what a new user has — the published raw image and apm:
#
#   1. INSTALL  — boot the stock raw image under OVMF (UEFI → sd-boot →
#                 UKI → systemd initrd). There is no runtime provisioning
#                 Ignition: systemd-repart carves swap and var (taking the
#                 rest) in the trailing free space of the grown per-run disk.
#                 root-a (the read-only erofs base) ships in the image
#                 sized-to-fit and is never resized.
#   2. BOOT     — first boot reaches multi-user.target; the layout is
#                 asserted: the root is mounted read-only erofs (immutable,
#                 not grown) and /var filled the disk. This is the first CI
#                 exercise of the sd-boot/UKI path and the systemd-repart
#                 substrate carving a real disk.
#   3. UPDATE   — `apm registry add` + `apm update` against a registry
#                 peer over the fleet L2.
#   4. INSTALL  — `apm install bc` downloads a package off the wire
#                 (bc is deliberately NOT in the image's closure).
#   5. UPGRADE  — `apm upgrade --system` pulls the server-2 generation
#                 from the registry's static cache, switches live, then
#                 the machine REBOOTS through UEFI and must come back on
#                 the new generation.
#
# The target machine is the production server image plus the bundled
# aos-test-agent package — the boot and provisioning path is fully stock;
# only the package set carries the test agent that lets the harness drive
# the machine.
#
# Machines (lexicographic order: registry=192.168.50.10, target=.11):
#   registry: kernel-boot peer publishing the registry + static cache
#             (same shape as apm-registry-upgrade.nix), with the
#             server-2 toplevel and bc pre-staged in its store.
#   target:   image boot with no metadata channel; identity is baked
#             into /etc, systemd-repart carves swap/var.
{
  lib,
  mkSystem,
  pkgs,
  systems,
}: let
  server2Top = systems.server-2.config.system.build.toplevel;

  # The server profile keeps the test fixtures and guest agent out of the
  # production image (bundle = mkDefault false; modules/profiles/server.nix).
  # Re-bundle per machine: the registry serves the fixtures, and the
  # image-boot target needs the agent payload in its raw image so the
  # harness can deliver it via ignition (lib/testing/fleet.nix).
  # server-test bundles the guest agent and the registry-workflow CLI tools
  # (git for the registry seed, curl/git for the target's clone + cache probe)
  # that image slimming dropped from the server profile. The registry machine
  # additionally re-bundles its fixtures; the image-boot target is plain
  # server-test (systems.server-test).
  serverWithRegistry = mkSystem [
    ../../systems/server-test.nix
    {
      aos.packages =
        lib.genAttrs
        ["aos-registry-server" "test-static-cache-server"]
        (_: {bundle = true;});
    }
  ];

  # Partition sizes (MiB). The root is a read-only erofs image (~200 MiB),
  # so the A/B root slots only need headroom for the base image — not the
  # whole disk. The freed space goes to /var, which holds the writable Nix
  # store overlay and all mutable state. CI uses a smaller A/B layout —
  # same shape, same labels.
  rootSizeMiB = 1024;
  swapSizeMiB = 1024;
  diskSizeMiB = 16384;
in {
  name = "install-from-image";
  # First boot does real partitioning + mkfs; the publish step
  # zstd-compresses the full server-2 closure; the upgrade pulls the
  # generation delta over the L2; then a full UEFI reboot. Budgeted
  # like apm-registry-upgrade plus the reboot.
  timeout = 3000;

  machines = {
    registry = {
      system = serverWithRegistry;
      # Kernel boot with baked /var matches apm-registry-upgrade.
      packages = ["aos-registry-server" "test-static-cache-server"];
      extraClosures = [server2Top pkgs.bc];
      # Static cache of the full closure lands under /var/lib/sysreg-cache, and
      # publish/cache generation stages rewritten store paths in the /nix
      # overlay upper on /var. Keep this aligned with apm-registry-upgrade's
      # producer headroom as the server closure grows.
      varSizeMiB = 4096;
      # `apr cache generate` zstd-compresses the full server-2 + bc closure
      # (~1.5 GiB) while the image-boot target hammers the same host with UEFI
      # partitioning/mkfs. At the 2 GiB default the producer's working set
      # (closure + OS) thrashes page cache and the publish overruns the 1200 s
      # agent deadline; 6 GiB keeps the closure resident. This is the one
      # machine in the fleet that genuinely needs more than the default — every
      # other VM runs at 2 GiB (see lib/testing/fleet-spec.nix `memoryMiB`).
      memoryMiB = 6144;
    };

    target = {
      system = systems.server-test;
      bootMode = "image";
      # systemd-repart carves swap and var (and
      # the reserved root-b slot) in the trailing free space of the grown
      # per-run image disk; per-VM identity + the guest agent are baked into
      # the image /etc via extendModules (lib/testing/fleet.nix).
      imageDiskMiB = diskSizeMiB;
      packages = ["aos-test-agent"];
      # The upgrade leg imports the gen-2 closure delta (NAR decompress + nix
      # import) into the /nix overlay on /var; extra RAM keeps that working set
      # in page cache so it finishes within the deadline on a loaded builder.
      memoryMiB = 4096;
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
      # activated the aos-test-agent package at first boot.
      target.succeed("systemctl is-active multi-user.target")

      # The install layout exists: root-a ships in the image, systemd-repart
      # carved swap + var in the trailing free space (no ignition-disks). (A
      # reserved root-b slot is future A/B work — see modules/services/repart.nix.)
      for label in ("root-a", "swap", "var"):
          target.succeed(f"test -e /dev/disk/by-partlabel/{label}")

      # The root is a read-only erofs image — the immutable base. It ships
      # sized-to-fit in the image and is NEVER resized (repart only adds/grows
      # the trailing partitions); all mutable state lives on /var. Confirm it
      # is mounted read-only erofs and stayed small.
      import re

      mounts = target.succeed("cat /proc/mounts")
      assert re.search(r"^\S+ / erofs ro\b", mounts, re.M), (
          f"root not mounted as read-only erofs:\n{mounts}"
      )
      blocks, bsize = map(int, target.succeed(
          "stat -f -c '%b %S' /"
      ).split())
      fs_bytes = blocks * bsize
      assert fs_bytes < ${toString rootSizeMiB} * 1024 * 1024, (
          f"erofs root is {fs_bytes} bytes; expected the small immutable base"
      )

      # /var is the ignition-created partition, mounted by partlabel.
      var_dev = target.succeed(
          "readlink -f /dev/disk/by-partlabel/var"
      ).strip()
      assert f"{var_dev} /var " in mounts, (
          f"/var not mounted from {var_dev}:\n{mounts}"
      )

      # /var took the rest of the disk: with a small immutable erofs root,
      # the writable Nix store overlay + state get the freed space. The disk
      # is ${toString diskSizeMiB} MiB; /var must be the bulk of it.
      vblocks, vbsize = map(int, target.succeed(
          "stat -f -c '%b %S' /var"
      ).split())
      var_bytes = vblocks * vbsize
      assert var_bytes > 10 * 1024 * 1024 * 1024, (
          f"/var is {var_bytes} bytes; expected it to fill the disk"
      )

      # First boot seeded the system profile at gen-1.
      gen = target.succeed("readlink /var/lib/profiles/system/current").strip()
      assert gen == "gen-1", f"expected gen-1 after install, got {gen!r}"

      # ════ Producer: publish a package + the gen-2 system ══════════════
      # Same producer block as apm-registry-upgrade.nix, plus a regular
      # (non-sysroot) bc package for the `apm install` leg.
      registry.wait_for_unit("aos-registry-server-gitd.service", timeout=120)
      registry.wait_for_unit("aos-pkg-aos-registry-server-firewall.service", timeout=120)
      registry.wait_until_succeeds(
          "systemctl is-active aos-pkg-aos-registry-server.target", timeout=120
      )
      registry.wait_until_succeeds(
          "systemctl is-active aos-pkg-test-static-cache-server.target", timeout=120
      )
      registry.wait_until_succeeds(
          "systemctl is-active test-static-cache-server.socket", timeout=120
      )
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

      # Downloads + imports the gen-2 closure delta over the emulated L2 and
      # switches the system profile. The NARs download quickly; the CPU-bound
      # zstd decompress + nix import into the /nix overlay on /var then runs
      # long, so the deadline has generous headroom over the ~normal cost.
      out = target.succeed(
          "HOME=/tmp PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH ${pkgs.aos}/bin/apm upgrade --system --yes 2>&1",
          timeout=1800,
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
      target.wait_until_succeeds("systemctl is-active multi-user.target", timeout=120)

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
      if failed:
          print("--- failed units after reboot ---")
          print(failed)
          for line in failed.splitlines():
              fields = line.split()
              unit = fields[1] if fields and fields[0] == "*" else fields[0]
              print(f"--- journalctl -u {unit} -b ---")
              print(target.succeed(
                  f"journalctl -u {unit} -b --no-pager -n 120 2>&1 || true"
              ))
      assert not failed, f"failed units after reboot: {failed!r}"
    '';
}
