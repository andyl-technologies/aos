# Durable A/B lifecycle acceptance.
#
# This is the executable acceptance gate for the image lifecycle. It
# publishes a real measured, dm-verity-backed raw image through a registry,
# stages it through `apm upgrade --system` onto the inactive GPT slot, exhausts
# its real sd-boot boot count and observes automatic fallback, retries and
# blesses that exact image, proves boot-commit replay is idempotent, then
# exercises explicit rollback and transition-journal crash recovery.
{
  lib,
  mkSystem,
  pkgs,
  systems,
}: let
  testPackages = [
    pkgs.diffutils
    pkgs.git
    pkgs.jq
  ];

  failurePreStart = ''read -r cmdline < /proc/cmdline; case " $cmdline " in *" systemd.verity_root_data=/dev/disk/by-partlabel/root-b "*) if [ ! -e /var/lib/aos-test/allow-eval ]; then exit 1; fi ;; esac'';
  bootCommitCondition =
    "${pkgs.bash}/bin/bash -c ${lib.escapeShellArg "read -r cmdline < /proc/cmdline; case \" $cmdline \" in *\" systemd.verity_root_data=/dev/disk/by-partlabel/root-b \"*) test -e /var/lib/aos-test/allow-image-commit ;; esac"}";
  candidateAgentUnit = pkgs.writeTextFile {
    name = "aos-fleet-test-agent-runtime-unit";
    destination = "/aos-test-agent.service";
    text = ''
      [Unit]
      Description=AOS VM Test Guest Agent
      RefuseManualStop=true

      [Service]
      Type=simple
      ExecStart=${pkgs.aos-test-agent}/share/aos-test-agent/aos-test-agent
      Restart=on-failure
      RestartSec=1
      Environment=PATH=${pkgs.coreutils}/bin:${pkgs.bash}/bin:${pkgs.systemd}/bin:${pkgs.systemd}/sbin
    '';
  };
  initrdControlFallback = {
    aos.boot.initrd.extraPackages = [pkgs.aos-test-agent];
    boot.initrd.systemd.services.aos-test-agent-initrd-fallback = {
      description = "Expose test control for stalled initrd boots";
      requiredBy = ["initrd-fs.target"];
      before = ["initrd-fs.target"];
      unitConfig.DefaultDependencies = "no";
      environment.PATH = "${pkgs.coreutils}/bin:${pkgs.bash}/bin:${pkgs.systemd}/bin:${pkgs.systemd}/sbin";
      serviceConfig = {
        Type = "simple";
        Restart = "on-failure";
        RestartSec = "1s";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
      script = ''
        echo "starting initrd test control"
        exec ${pkgs.aos-test-agent}/share/aos-test-agent/aos-test-agent
      '';
    };
  };

  # The candidate deliberately changes only image identity. Keeping the module
  # ABI fixed makes the reboot test isolate image selection and first-boot
  # rebinding rather than cross-ABI migration.
  candidate = mkSystem [
    ../../systems/server-verity.nix
    initrdControlFallback
    {
      aos.system.version = "9999.0.0-rfc0011";
      # The fleet machine module bakes deterministic interface naming into the
      # initial UKI. Preserve that test-machine ABI in the independently built
      # candidate and seed its fleet address so first-boot evaluation can run
      # before the retained host configuration is rebound.
      aos.boot.kernelParams = ["net.ifnames=0"];
      aos.packages.aos-test-agent.bundle = true;
      environment.systemPackages = testPackages;
      environment.etc."systemd/network/10-fleet-eth0.network".text = ''
        [Match]
        MACAddress=52:54:00:12:00:02

        [Network]
        Address=192.168.50.11/24
      '';
      systemd.services.aos-test-agent = {
        description = "AOS VM Test Guest Agent";
        wantedBy = ["multi-user.target"];
        restartIfChanged = false;
        stopIfChanged = false;
        unitConfig.RefuseManualStop = true;
        serviceConfig = {
          Type = "simple";
          ExecStart = "${pkgs.aos-test-agent}/share/aos-test-agent/aos-test-agent";
          Restart = "on-failure";
          RestartSec = 1;
          Environment = "PATH=${pkgs.coreutils}/bin:${pkgs.bash}/bin:${pkgs.systemd}/bin:${pkgs.systemd}/sbin";
        };
      };
      systemd.services.aos-test-agent-bootstrap = {
        description = "Install the AOS VM test control channel";
        wantedBy = ["multi-user.target"];
        before = ["aos-eval.service"];
        stopOnRemoval = false;
        unitConfig.RefuseManualStop = true;
        serviceConfig.Type = "oneshot";
        script = ''
          ${pkgs.coreutils}/bin/mkdir -p /run/systemd/system
          ${pkgs.coreutils}/bin/ln -sfn ${candidateAgentUnit}/aos-test-agent.service \
            /run/systemd/system/aos-test-agent.service
          ${pkgs.systemd}/bin/systemctl daemon-reload
          ${pkgs.systemd}/bin/systemctl start aos-test-agent.service
        '';
      };
    }
  ];
  candidateTop = candidate.config.system.build.toplevel;
  candidateImage = candidate.config.system.build.image.raw;
  candidateUki = candidate.config.system.build.uki;

  # Image-mode machines boot the system image directly, so fleet
  # `extraClosures` do not populate their store. Include Git in the test
  # system itself because the driver seeds the authenticated registry clone
  # and inspects transition state before exercising the production image
  # transition path.
  targetSystem = mkSystem [
    ../../systems/server-verity.nix
    initrdControlFallback
    {
      environment.systemPackages = testPackages;
    }
  ];

  registrySystem = mkSystem [
    ../../systems/server-test.nix
    {
      aos.packages =
        lib.genAttrs
        ["aos-registry-server" "test-static-cache-server"]
        (_: {bundle = true;});
    }
  ];
in {
  name = "rfc-0011-image-rollback";
  timeout = 5400;
  bootTimeout = 600;

  machines = {
    registry = {
      system = registrySystem;
      packages = ["aos-registry-server" "test-static-cache-server"];
      # The publisher needs the candidate toplevel, its complete raw OTA
      # artifact, and the tools that derive signer/SBAT/PCR facts from both
      # slot-specific UKIs.
      extraClosures = [
        candidateTop
        candidateImage
        candidateUki
        pkgs.sbsigntools
        pkgs.binutils
        pkgs.git
        pkgs.systemd
      ];
      varSizeMiB = 12288;
      memoryMiB = 6144;
    };

    target = {
      system = targetSystem;
      bootMode = "image";
      # Staging retains both evaluator closures before overwriting a slot and
      # concurrently holds the downloaded raw-image NAR. Give the lifecycle
      # fixture enough durable workspace to exercise that safety property.
      imageDiskMiB = 49152;
      # Importing the multi-gigabyte raw image NAR runs the package client and
      # nix-store concurrently. Leave enough headroom for both decompression
      # pipelines so the acceptance test measures rollback behavior rather
      # than the VM's OOM policy.
      memoryMiB = 8192;
      tpm = true;
      packages = ["aos-test-agent"];
      # The same authenticated leaf is replayed after each image transition.
      # It keeps the fleet address stable after the candidate's base library
      # replaces the image-baked test identity.
      metadata."host.nix" = ''
        {
          aos.provisioning.storage.partitions.var.sizeMin = "24G";
          aos.networking.hostName = "target";
          aos.networking.useDHCP = false;
          aos.networking.interfaces.eth0.address = "192.168.50.11/24";
          aos.apm.desiredPackages = [ "aos-test-agent" ];

          environment.etc."hosts".text = "127.0.0.1 localhost\n192.168.50.10 registry\n192.168.50.11 target\n";
        }
      '';
    };
  };

  testScript =
    # python
    ''
      import json
      import re
      import textwrap

      APM = "${pkgs.aos}/bin/apm"
      APR = "${pkgs.aos}/bin/apr"
      JQ = "${pkgs.jq}/bin/jq"
      SB_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
      MOUNT = "${pkgs.util-linux}/bin/mount"
      BOOTCTL = "${pkgs.systemd}/bin/bootctl"
      SYNC = "${pkgs.coreutils}/bin/sync"
      CMP = "${pkgs.diffutils}/bin/cmp"
      IMAGE_STATE = "/var/lib/profiles/image/state.json"
      TRANSITION_INTENT = "/var/lib/profiles/image/.transition-intent.json"


      def image_state():
          return json.loads(target.succeed(f"cat {IMAGE_STATE}"))


      def generation(state, number):
          matches = [g for g in state["generations"] if g["number"] == number]
          assert len(matches) == 1, (number, state)
          return matches[0]


      def efivar_byte(name):
          path = f"/sys/firmware/efi/efivars/{name}-{SB_GUID}"
          out = target.succeed(f"od -An -tu1 -j4 -N1 {path}").strip()
          return int(out)


      def assert_boot_read_only():
          mounts = target.succeed("cat /proc/mounts")
          match = re.search(r"^\S+ /boot \S+ (\S+)", mounts, re.M)
          assert match, f"/boot is not mounted:\n{mounts}"
          options = match.group(1).split(",")
          assert "ro" in options and "rw" not in options, (
              f"/boot was not restored read-only: {match.group(0)!r}"
          )


      def counted_variant(recorded, tries_left, tries_done):
          prefix = recorded.rsplit("+", 1)[0]
          return f"{prefix}+{tries_left}-{tries_done}.efi"


      def assert_only_counted_variant(recorded, expected):
          prefix = recorded.rsplit("+", 1)[0]
          target.succeed(f"test -f /boot/{expected}")
          target.fail(f"test -e /boot/{prefix}.efi")
          target.succeed(
              f"set -- /boot/{prefix}+*.efi; "
              f'[ "$#" -eq 1 ] && [ -e "$1" ] '
              f'&& [ "$1" = "/boot/{expected}" ]'
          )


      def assert_switched_root():
          try:
              target.wait_until_succeeds(
                  "test ! -e /etc/initrd-release", timeout=60
              )
          except Exception:
              print(target.succeed("cat /proc/cmdline 2>&1 || true"))
              print(target.succeed("systemctl list-jobs --no-pager 2>&1 || true"))
              print(target.succeed("systemctl --failed --no-pager 2>&1 || true"))
              for unit in (
                  "mount-var.service",
                  "nix-overlay-setup.service",
                  "aos-seed-profiles.service",
                  "run-etc-setup.service",
                  "aos-machine-id.service",
                  "etc-overlay-setup.service",
                  "initrd-fs.target",
                  "initrd-switch-root.target",
              ):
                  print(target.succeed(
                      f"systemctl status {unit} --no-pager 2>&1 || true"
                  ))
                  print(target.succeed(
                      f"journalctl -b -u {unit} --no-pager 2>&1 || true"
                  ))
              raise


      def wait_for_failed_candidate_pipeline():
          target.wait_until_succeeds(
              "systemctl is-active --quiet multi-user.target", timeout=420
          )
          try:
              target.wait_until_succeeds(
                  "systemctl is-failed --quiet aos-eval.service", timeout=120
              )
          except Exception:
              print(target.succeed("cat /proc/cmdline"))
              print(target.succeed(
                  "${pkgs.findutils}/bin/find "
                  "/var/etc/systemd/system -maxdepth 3 -type f -print "
                  "-exec sed -n '1,120p' {} ';' 2>&1 || true"
              ))
              for unit in (
                  "aos-credential-recovery.service",
                  "aos-host-config-restore.service",
                  "aos-firstboot-reeval.service",
                  "aos-nix-db.service",
                  "systemd-pcrphase.service",
                  "aos-image-measurement-index.service",
                  "aos-seed-baked-packages.service",
                  "aos-eval.service",
              ):
                  print(target.succeed(
                      f"systemctl cat {unit} --no-pager 2>&1 || true"
                  ))
                  print(target.succeed(
                      f"systemctl status {unit} --no-pager 2>&1 || true"
                  ))
                  print(target.succeed(
                      f"journalctl -b -u {unit} --no-pager 2>&1 || true"
                  ))
              print(target.succeed("systemctl list-jobs --no-pager 2>&1 || true"))
              raise
          target.succeed("test ! -e /run/aos/manifest.json")
          target.succeed(
              "test \"$(systemctl show -p Result --value "
              "aos-graph-compile.service)\" = success"
          )
          target.succeed(
              "test \"$(systemctl show -p ActiveState --value "
              "aos-graph-compile.service)\" = inactive"
          )
          target.succeed(
              "test \"$(systemctl show -p ConditionResult --value "
              "aos-graph-compile.service)\" = no"
          )
          target.succeed(
              "test \"$(systemctl show -p Result --value "
              "aos-image-boot-commit.service)\" = success"
          )
          target.succeed(
              "test \"$(systemctl show -p ActiveState --value "
              "aos-image-boot-commit.service)\" = inactive"
          )


      # -- Initial stock image ------------------------------------------------
      try:
          target.wait_until_succeeds(
              "systemctl is-active --quiet aos-image-boot-commit.service", timeout=300
          )
      except Exception:
          for unit in (
              "network-online.target",
              "aos-eval.service",
              "aos-graph-compile.service",
              "aos-activate.service",
              "aos-image-boot-commit.service",
          ):
              print(target.succeed(
                  f"systemctl status {unit} --no-pager 2>&1 || true"
              ))
              print(target.succeed(
                  f"journalctl -b -u {unit} --no-pager 2>&1 || true"
              ))
          print(target.succeed("systemctl list-jobs --no-pager 2>&1 || true"))
          raise
      target.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=420
      )
      assert_boot_read_only()

      # Setup Mode intentionally uses a disposable plain /var. Enroll the
      # image's test keys and let the first enforcing boot replace it with the
      # durable TPM-sealed LUKS volume before exercising stateful transitions.
      assert efivar_byte("SetupMode") == 1
      assert efivar_byte("SecureBoot") == 0
      efi_update = (
          "PATH=${pkgs.util-linux}/bin:$PATH "
          "${pkgs.efitools}/bin/efi-updatevar"
      )
      keys = "${pkgs.secure-boot-test-keys}"
      for variable in ("db", "KEK", "PK"):
          target.succeed(
              f"{efi_update} -f {keys}/{variable}.auth {variable} 2>&1"
          )
      assert efivar_byte("SetupMode") == 0
      target.reboot(timeout=600)
      target.wait_until_succeeds(
          "systemctl is-active --quiet aos-image-boot-commit.service", timeout=420
      )
      target.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=420
      )
      assert efivar_byte("SecureBoot") == 1
      target.succeed(
          "${pkgs.cryptsetup}/sbin/cryptsetup isLuks "
          "/dev/disk/by-partlabel/var"
      )
      target.succeed(
          "source=; while read -r device mountpoint rest; do "
          "test \"$mountpoint\" != /var || source=$device; "
          "done < /proc/mounts; test \"$source\" = /dev/mapper/var"
      )
      assert_boot_read_only()

      initial = image_state()
      assert initial["running"] == 1, initial
      assert initial["default"] == 1, initial
      assert initial.get("pending") is None, initial
      old = generation(initial, 1)
      assert old["slot"] == "A", old

      # Keep fault injection outside host.nix: structural systemd units are
      # image-owned, while host.nix is deliberately restricted to operator-
      # owned settings. Persistent local drop-ins let the test prevent both
      # evaluation and boot blessing only while slot B is running.
      target.succeed(textwrap.dedent("""
          set -eu
          mkdir -p \
            /var/etc/systemd/system/aos-eval.service.d \
            /var/etc/systemd/system/aos-image-boot-commit.service.d \
            /var/etc/systemd/system/multi-user.target.wants
          cat > /var/etc/systemd/system/aos-test-agent.service <<'EOF'
          [Unit]
          Description=AOS VM Test Guest Agent
          RefuseManualStop=true

          [Service]
          Type=simple
          ExecStart=${pkgs.aos-test-agent}/share/aos-test-agent/aos-test-agent
          Restart=on-failure
          RestartSec=1
          Environment=PATH=${pkgs.coreutils}/bin:${pkgs.bash}/bin:${pkgs.systemd}/bin:${pkgs.systemd}/sbin
          EOF
          ln -sfn ../aos-test-agent.service \
            /var/etc/systemd/system/multi-user.target.wants/aos-test-agent.service
          cat > /var/etc/systemd/system/aos-eval.service.d/90-rollback-test.conf <<'EOF'
          [Service]
          ExecStartPre=${pkgs.bash}/bin/bash -c ${lib.escapeShellArg failurePreStart}
          EOF
          cat > /var/etc/systemd/system/aos-image-boot-commit.service.d/90-rollback-test.conf <<'EOF'
          [Service]
          ExecCondition=${bootCommitCondition}
          EOF
          ${pkgs.coreutils}/bin/sync
      """))

      # These are real udev links to block devices, not regular-file fixtures.
      # The production writer must follow the trusted by-partlabel link and
      # validate the opened descriptor before performing a destructive write.
      for label in ("root-a", "root-a-hash", "root-b", "root-b-hash"):
          target.succeed(f"test -L /dev/disk/by-partlabel/{label}")
          target.succeed(f"test -b $(readlink -f /dev/disk/by-partlabel/{label})")

      # -- Publish a catalog-backed A/B image ---------------------------------
      registry.wait_for_unit("aos-registry-server-gitd.service", timeout=180)
      registry.wait_until_succeeds(
          "systemctl is-active --quiet aos-pkg-test-static-cache-server.target",
          timeout=180,
      )
      registry.wait_until_succeeds(
          "systemctl is-active --quiet aos-nix-db.service", timeout=180
      )
      registry.succeed(textwrap.dedent("""
          set -eu
          export HOME=/tmp
          export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test
          export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/nix-conf
          export PATH="${pkgs.sbsigntools}/bin:${pkgs.binutils}/bin:${pkgs.systemd}/lib/systemd:$PATH"
          mkdir -p "$NIX_CONF_DIR"
          printf 'experimental-features = nix-command\\nsandbox = false\\nbuild-users-group =\\n' \\
            > "$NIX_CONF_DIR/nix.conf"

          ${pkgs.nix}/bin/nix-store --check-validity '${candidateTop}'
          ${pkgs.nix}/bin/nix-store --check-validity '${candidateImage}'

          ${pkgs.aos}/bin/apr create sysreg
          REG_DIR=$HOME/.local/share/apm/registries/sysreg
          DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
          ORIGIN=/var/lib/aos-registry-server/registries/sysreg
          git init --bare --object-format=sha256 "$ORIGIN"
          git -C "$ORIGIN" symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
          git -C "$REG_DIR" remote add origin "$ORIGIN"
          set -- '${candidateUki}'/*.efi
          test "$#" -eq 1
          CANDIDATE_UKI="$1"

          if ! ${pkgs.aos}/bin/apr --json publish '${candidateTop}' \\
            --name aos \\
            --version 9999.0.0-rfc0011 \\
            --description 'A/B lifecycle fixture' \\
            --license MIT \\
            --maintainer test \\
            --sysroot \\
            --image '${candidateImage}' --image-format raw \\
            --image-uki "$CANDIDATE_UKI" \\
            --no-ca \\
            --registry sysreg \\
            --no-commit > /tmp/publish.json; then
            cat /tmp/publish.json >&2
            exit 1
          fi
          echo "$DEFAULT_BRANCH" > /tmp/sysreg-branch
      """), timeout=1200)

      publication = json.loads(registry.succeed("cat /tmp/publish.json"))
      images = publication.get("images", [])
      assert len(images) == 1, images
      ukis = images[0].get("ukis", [])
      assert {u.get("slot") for u in ukis} == {"a", "b"}, ukis
      for uki in ukis:
          signer = uki.get("sb_signer_cert_sha256")
          expected = uki.get("expected_pcr11")
          assert signer and re.fullmatch(r"[0-9a-f]{64}", signer), uki
          assert expected and re.fullmatch(r"[0-9a-f]{64}", expected), uki
          assert uki.get("sbat"), uki
      candidate_b_pcr11 = next(
          u["expected_pcr11"] for u in ukis if u["slot"] == "b"
      )
      signers = sorted({u["sb_signer_cert_sha256"] for u in ukis})

      catalog_commands = "\n".join(
          f"{APR} sb-certs add aos-db-{index} --cert-sha256 {signer} "
          "--registry sysreg --no-commit"
          for index, signer in enumerate(signers)
      )
      registry.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp
          export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test
          export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/nix-conf
          REG_DIR=$HOME/.local/share/apm/registries/sysreg
          DEFAULT_BRANCH=$(cat /tmp/sysreg-branch)
          ORIGIN=/var/lib/aos-registry-server/registries/sysreg

          {catalog_commands}
          {APR} verify --registry sysreg
          {APR} cache generate \\
            --registry sysreg \\
            --output /var/lib/sysreg-cache \\
            --cache-url http://registry:8000/sysreg-cache \\
            --priority 46 \\
            --no-commit
          chmod -R a+rX /var/lib/sysreg-cache

          git -C "$REG_DIR" add -A
          git -C "$REG_DIR" commit -m 'release: A/B lifecycle fixture'
          git -C "$REG_DIR" tag v1.0.0
          git -C "$REG_DIR" push origin "$DEFAULT_BRANCH" --tags
          chown -R aos-gitd:aos-gitd "$ORIGIN"
      """), timeout=1800)
      branch = registry.succeed("cat /tmp/sysreg-branch").strip()

      target.succeed(textwrap.dedent(f"""
          set -eu
          mkdir -p /var/etc/apm/registries.d /var/lib/apm/registries \\
            /var/lib/apm/remote /var/lib/apm/cache
          cat > /var/etc/apm/registries.d/sysreg.toml <<'EOF'
          [registry]
          name = "sysreg"
          url = "git://registry:9418/sysreg"
          priority = 500
          enabled = true

          [registry.signing]
          required = false
          EOF
          ${pkgs.git}/bin/git clone --branch {branch} \\
            git://registry:9418/sysreg /var/lib/apm/registries/sysreg
          ln -sfn /var/lib/apm/registries/sysreg /var/lib/apm/remote/sysreg
      """), timeout=180)

      # -- Stage the actual inactive slot -------------------------------------
      out = target.succeed(
          "HOME=/tmp PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH "
          f"{APM} upgrade --system --yes 2>&1",
          timeout=1800,
      )
      print("=== stage candidate ===\n" + out)
      assert "Secure Boot catalog validation passed" in out, out
      assert "Staging inactive A/B image slot" in out, out
      # An exact LoaderEntryDefault would keep selecting the counted UKI even
      # after sd-boot marks it bad. Staging must leave selection to the
      # image-owned aos-*.efi pattern so exhaustion can fall back to slot A.
      target.fail(
          f"test -e /sys/firmware/efi/efivars/LoaderEntryDefault-{SB_GUID}"
      )
      assert_boot_read_only()

      staged = image_state()
      assert staged["running"] == 1, staged
      assert staged["default"] == 2, staged
      assert staged["pending"] == 2, staged
      candidate_record = generation(staged, 2)
      assert candidate_record["slot"] == "B", candidate_record
      assert candidate_record["registry"] == "sysreg", candidate_record
      assert candidate_record["expected_pcr11"] == candidate_b_pcr11, candidate_record
      assert candidate_record["expected_pcr11"] != old.get("expected_pcr11"), (
          old,
          candidate_record,
      )

      candidate_entry = candidate_record["uki_path"]
      assert "+" in candidate_entry and candidate_entry.endswith(".efi"), candidate_entry
      target.succeed(f"test -f /boot/{candidate_entry}")
      root_bytes = target.succeed(
          "stat -c %s '${candidateImage}/root.img'"
      ).strip()
      hash_bytes = target.succeed(
          "stat -c %s '${candidateImage}/root.verity'"
      ).strip()
      target.succeed(
          f"{CMP} -n {root_bytes} '${candidateImage}/root.img' "
          "/dev/disk/by-partlabel/root-b"
      )
      target.succeed(
          f"{CMP} -n {hash_bytes} '${candidateImage}/root.verity' "
          "/dev/disk/by-partlabel/root-b-hash"
      )
      target.succeed(
          f"{CMP} '${candidateImage}/uki-b.efi' /boot/{candidate_entry}"
      )

      # -- Exhaust the first candidate and prove automatic fallback ------------
      # Each launch is performed by sd-boot itself. Because the candidate's
      # controlled eval failure prevents boot assessment from being blessed,
      # the loader must atomically rename the UKI through every counted state.
      # No userspace command edits the candidate entry during this sequence.
      expected_counted = [
          counted_variant(candidate_entry, 2, 1),
          counted_variant(candidate_entry, 1, 2),
          counted_variant(candidate_entry, 0, 3),
      ]
      for attempt, expected_entry in enumerate(expected_counted, start=1):
          target.reboot(timeout=600)
          assert_switched_root()
          wait_for_failed_candidate_pipeline()
          attempted = image_state()
          assert attempted["running"] == 2, (attempt, attempted)
          assert attempted["default"] == 2, (attempt, attempted)
          assert attempted["pending"] == 2, (attempt, attempted)
          assert_only_counted_variant(candidate_entry, expected_entry)
          target.fail(f"test -e /boot/{candidate_entry}")
          assert_boot_read_only()

      candidate_exhausted = expected_counted[-1]
      target.reboot(timeout=600)
      try:
          target.wait_until_succeeds(
              "systemctl is-active --quiet aos-image-boot-commit.service", timeout=420
          )
      except Exception:
          print(target.succeed(f"cat {IMAGE_STATE} 2>&1 || true"))
          print(target.succeed(
              "test ! -e /run/aos/image-reeval-required || "
              "cat /run/aos/image-reeval-required"
          ))
          for unit in (
              "aos-firstboot-reeval.service",
              "aos-eval.service",
              "aos-graph-compile.service",
              "aos-activate.service",
              "aos-image-boot-commit.service",
          ):
              print(target.succeed(
                  f"systemctl cat {unit} --no-pager 2>&1 || true"
              ))
              print(target.succeed(
                  f"systemctl status {unit} --no-pager 2>&1 || true"
              ))
              print(target.succeed(
                  f"journalctl -b -u {unit} --no-pager 2>&1 || true"
              ))
          print(target.succeed("systemctl list-jobs --no-pager 2>&1 || true"))
          raise
      fallback = image_state()
      assert fallback["running"] == 1, fallback
      assert fallback["default"] == 1, fallback
      assert fallback.get("pending") is None, fallback
      failed_candidate = generation(fallback, 2)
      assert failed_candidate["registry"] == "sysreg", failed_candidate
      assert failed_candidate["expected_pcr11"] == candidate_b_pcr11, failed_candidate
      assert_only_counted_variant(candidate_entry, candidate_exhausted)
      assert_boot_read_only()

      # Retry the exact same authenticated image. A retry must re-arm the one
      # catalog identity rather than append another record with the same
      # immutable toplevel: initrd reconciliation intentionally rejects
      # ambiguous persisted identities.
      target.succeed(
          "mkdir -p /var/lib/aos-test && "
          "touch /var/lib/aos-test/allow-eval "
          "/var/lib/aos-test/allow-image-commit"
      )
      out = target.succeed(
          "HOME=/tmp PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH "
          f"{APM} upgrade --system --yes 2>&1",
          timeout=1800,
      )
      print("=== retry candidate ===\n" + out)
      retried = image_state()
      retried_number = retried["pending"]
      assert retried_number is not None, retried
      matching_toplevels = [
          g for g in retried["generations"]
          if g["toplevel"] == "${candidateTop}"
      ]
      assert len(matching_toplevels) == 1, (
          "retry created an ambiguous duplicate image identity",
          matching_toplevels,
      )
      retry_candidate = generation(retried, retried_number)
      assert retry_candidate["slot"] == "B", retry_candidate
      assert retry_candidate["registry"] == "sysreg", retry_candidate
      assert retry_candidate["expected_pcr11"] == candidate_b_pcr11, retry_candidate
      candidate_entry = retry_candidate["uki_path"]
      target.succeed(f"test -f /boot/{candidate_entry}")
      assert_boot_read_only()

      # -- Candidate boot and durable blessing --------------------------------
      target.reboot(timeout=600)
      target.wait_until_succeeds(
          "systemctl is-active --quiet aos-image-boot-commit.service", timeout=420
      )
      target.succeed("systemctl is-active --quiet aos-config.target")
      assert_boot_read_only()

      committed = image_state()
      assert committed["running"] == retried_number, committed
      assert committed["default"] == retried_number, committed
      assert committed.get("pending") is None, committed
      committed_candidate = generation(committed, retried_number)
      assert committed_candidate["registry"] == "sysreg", committed_candidate
      assert committed_candidate["expected_pcr11"] == candidate_b_pcr11, committed_candidate
      config_state = json.loads(
          target.succeed("cat /var/lib/profiles/system/state.json")
      )
      current_config = next(
          g for g in config_state["generations"]
          if g["number"] == config_state["current"]
      )
      assert current_config["image_gen_parent"] == retried_number, current_config

      stable_candidate = candidate_entry.split("+", 1)[0] + ".efi"
      target.succeed(f"test -f /boot/{stable_candidate}")
      target.fail(f"test -e /boot/{candidate_entry}")

      # Replay the exact crash-recovery shape: bootctl already renamed the
      # counted entry, but state publication did not clear `pending`. The unit
      # must accept the stable file as already blessed and converge again.
      target.succeed(f"""
          set -eu
          {JQ} '.pending = .running' {IMAGE_STATE} > {IMAGE_STATE}.new
          {SYNC} -f {IMAGE_STATE}.new
          mv {IMAGE_STATE}.new {IMAGE_STATE}
          {SYNC} -f /var/lib/profiles/image
          printf '%s\n' {retried_number} > /run/aos/image-reeval-required
          systemctl restart aos-image-boot-commit.service
      """)
      replayed = image_state()
      assert replayed["running"] == retried_number, replayed
      assert replayed["default"] == retried_number, replayed
      assert replayed.get("pending") is None, replayed
      assert_boot_read_only()

      # -- Explicit durable rollback to the known-good A image -----------------
      target.succeed(f"{APM} rollback --system --image --generation 1")
      selected = image_state()
      assert selected["running"] == retried_number, selected
      assert selected["default"] == 1, selected
      assert selected["pending"] == 1, selected
      assert_boot_read_only()

      target.reboot(timeout=600)
      target.wait_until_succeeds(
          "systemctl is-active --quiet aos-image-boot-commit.service", timeout=420
      )
      rolled_back = image_state()
      assert rolled_back["running"] == 1, rolled_back
      assert rolled_back["default"] == 1, rolled_back
      assert rolled_back.get("pending") is None, rolled_back
      old_entry = generation(rolled_back, 1)["uki_path"]
      old_stable = old_entry.split("+", 1)[0] + ".efi"
      target.succeed(f"test -f /boot/{old_stable}")
      assert_boot_read_only()

      # -- Recover a post-selection crash despite eval/graph failure -----------
      # Reproduce the durable crash window after pending state and the
      # bootloader default were selected, but before default-state publication
      # and journal removal. The early first-boot service must authenticate the
      # image that actually booted and clear the journal before the deliberately
      # failing candidate eval/graph pipeline can run. Otherwise the subsequent
      # operator rollback to generation 1 would be rejected as a conflicting
      # unfinished transition.
      target.succeed(f"""
          set -eu
          rm -f /var/lib/aos-test/allow-eval \
            /var/lib/aos-test/allow-image-commit
          {JQ} --argjson target {retried_number} \
            '.pending = $target | .default = 1' \
            {IMAGE_STATE} > {IMAGE_STATE}.new
          {SYNC} -f {IMAGE_STATE}.new
          mv {IMAGE_STATE}.new {IMAGE_STATE}
          {SYNC} -f /var/lib/profiles/image
          {JQ} -n --argjson target {retried_number} \
            --arg entry '{stable_candidate.split("/", 2)[-1]}' \
            '{{target: $target, prior_default: 1, entry_id: $entry}}' \
            > {TRANSITION_INTENT}.new
          {SYNC} -f {TRANSITION_INTENT}.new
          mv {TRANSITION_INTENT}.new {TRANSITION_INTENT}
          {SYNC} -f /var/lib/profiles/image
          {MOUNT} -o remount,rw /boot
          {BOOTCTL} set-default '{stable_candidate.split("/", 2)[-1]}'
          {MOUNT} -o remount,ro /boot
      """)
      assert_boot_read_only()

      target.reboot(timeout=600)
      wait_for_failed_candidate_pipeline()
      target.succeed("systemctl is-active --quiet aos-firstboot-reeval.service")
      target.fail(f"test -e {TRANSITION_INTENT}")
      crashed = image_state()
      assert crashed["running"] == retried_number, crashed
      assert crashed["default"] == retried_number, crashed
      assert crashed["pending"] == retried_number, crashed
      crashed_config = json.loads(
          target.succeed("cat /var/lib/profiles/system/state.json")
      )
      crashed_current = next(
          g for g in crashed_config["generations"]
          if g["number"] == crashed_config["current"]
      )
      assert crashed_current["image_gen_parent"] == 1, crashed_current
      assert_boot_read_only()

      target.succeed(f"{APM} rollback --system --image --generation 1")
      recovered_selection = image_state()
      assert recovered_selection["running"] == retried_number, recovered_selection
      assert recovered_selection["default"] == 1, recovered_selection
      assert recovered_selection["pending"] == 1, recovered_selection
      target.fail(f"test -e {TRANSITION_INTENT}")
      assert_boot_read_only()

      target.reboot(timeout=600)
      target.wait_until_succeeds(
          "systemctl is-active --quiet aos-image-boot-commit.service", timeout=420
      )
      recovered = image_state()
      assert recovered["running"] == 1, recovered
      assert recovered["default"] == 1, recovered
      assert recovered.get("pending") is None, recovered
      assert_boot_read_only()

      failed = target.succeed("systemctl --failed --no-legend").strip()
      assert not failed, f"failed units after A/B rollback: {failed!r}"
    '';
}
