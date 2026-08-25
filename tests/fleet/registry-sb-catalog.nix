# tests/fleet/registry-sb-catalog.nix — the registry as a Secure Boot
# validation catalog (RFC-0006 phase 4), end to end.
#
# The registry never signs boot material; it records *facts about* a
# published image (the signer's db-cert SHA-256, the SBAT generations, the
# predicted PCR 11) in a committed `sb-certs.toml` roster, and `apm`
# validates a downloaded sysroot against that roster BEFORE it creates a new
# generation — turning a boot-time Secure Boot brick into a clean,
# recoverable download-time refusal.
#
# This proves the whole producer→catalog→consumer loop with a real signed
# UKI (server-secureboot's), no TPM and no firmware enforcement required —
# the gate is pure apm policy over downloaded metadata:
#
#   1. PUBLISH — the registry publishes the signed server-measured-boot
#      toplevel as a sysroot package, attaching its signed UKI as an image.
#      `apr publish` derives the SB facts from the real binary (sbverify +
#      in-Rust PKCS#7 for the signer cert, objcopy for `.sbat`,
#      systemd-measure over the UKI's sections for PCR 11). Asserted from
#      the publish `--json`: a signer cert, a non-empty SBAT table, and a
#      PCR-11 digest that an INDEPENDENT objcopy+systemd-measure recompute
#      reproduces byte-for-byte (RFC-0006 #3: the recorded value is the
#      genuine sd-stub section measurement, not a stand-in).
#   2. REFUSE (unknown signer) — the catalog lists only a decoy db cert, so
#      the image's real signer is not active. `apm upgrade --system` must
#      download, then REFUSE without changing either generation axis.
#   3. REFUSE (SBAT floor) — the real signer is now active, but the SBAT
#      floor is raised one above the image's generation. `apm upgrade` must
#      REFUSE on the floor, again without changing either axis.
#   4. ACCEPT CATALOG — the floor is lowered to the image's generation. The
#      Secure Boot catalog validation passes and the consumer reaches the A/B
#      staging boundary. This kernel-boot policy fixture cannot mutate an A/B
#      disk, so both generation axes remain unchanged.
#
# Machines (lexicographic: registry=192.168.50.10, target=192.168.50.11):
#   registry: aos-registry-server (gitd :9418) + static-cache package (:8000),
#             with the signed measured-boot toplevel + its UKI staged in
#             store (extraClosures) and the publish-time SB toolchain
#             (sbsigntools/binutils/systemd) reachable by store path.
#   target:   plain server (kernel boot); the closure + catalog travel over
#             the fleet L2 and apm enforces the catalog locally. A /var big
#             enough for the NAR cache + imported store paths.
{
  lib,
  mkSystem,
  pkgs,
  systems,
}: let
  sbSystem = mkSystem [
    ../../systems/server-measured-boot.nix
    {
      # The consumer boots the default 0.1.0 fixture. A distinct release is
      # required for `apm upgrade --system` to evaluate the candidate policy
      # instead of correctly reporting that the system is already current.
      aos.system.version = "test-sb-catalog";
    }
  ];
  sbTop = sbSystem.config.system.build.toplevel;
  sbUki = sbSystem.config.system.build.uki;
  sbImage = sbSystem.config.system.build.image.raw;
  sbImageDisk = sbSystem.config.system.build.imageArtifacts.raw.disk;
  sbImageInfo = sbSystem.config.system.build.imageArtifacts.raw.info;
  publicationClosureInfo = import ../../lib/build/closure-info.nix {inherit lib pkgs;} {
    rootPaths = [
      sbTop
      sbUki
      sbImage
      sbImageDisk
      sbImageInfo
      pkgs.secure-boot-test-keys
      pkgs.sbsigntools
      pkgs.binutils
      pkgs.systemd
    ];
    pname = "registry-sb-publication-closure-info";
  };

  # server-test bundles the guest agent and the CLI tools the producer needs
  # (it hand-seeds + pushes the registry with git) that image slimming dropped
  # from the server profile. The registry additionally re-bundles its fixtures.
  serverWithRegistry = mkSystem [
    ../../systems/server-test.nix
    {
      aos.packages =
        lib.genAttrs
        ["aos-registry-server" "test-static-cache-server"]
        (_: {bundle = true;});
    }
  ];
in {
  name = "registry-sb-catalog";
  # Two boots + registry/static-cache package activation + full-closure
  # static cache + one full measured A/B image and closure transfer (the first
  # refused upgrade still downloads) + two further validation passes over the
  # cached closure + three catalog re-syncs. Budgeted like install-from-image.
  timeout = 5400;

  machines = {
    registry = {
      system = serverWithRegistry;
      packages = ["aos-registry-server" "test-static-cache-server"];
      # Match a release workstation: host-built publication inputs enter over
      # a read-only 9p store mount and are registered in-guest below.
      hostStoreMount = true;
      extraModules = [
        {
          aos.kernel.modules = ["9pnet_virtio" "9p"];
        }
      ];
      # `apr cache generate` writes a zstd static cache of the full
      # measured-boot closure plus the authenticated A/B image payload under
      # /var/lib/sysreg-cache, so size /var generously.
      varSizeMiB = 8192;
      memoryMiB = 8192;
    };

    target = {
      # server-test for the CLI tools the upgrade/verification steps run
      # in-guest (image slimming dropped them from the plain server PATH).
      system = systems.server-test;
      # The download lands twice on /var: the NAR cache under
      # /var/lib/apm/cache and the imported store paths (the /nix overlay
      # upper lives on the var partition) — the full sysroot closure.
      varSizeMiB = 8192;
      memoryMiB = 8192;
    };
  };

  testScript =
    # python
    ''
      import json
      import textwrap

      # ════ 0. Both machines up; registry packages active ═══════════════
      registry.wait_until_succeeds("test -S /run/dbus/system_bus_socket", timeout=120)
      target.wait_until_succeeds("test -S /run/dbus/system_bus_socket", timeout=120)
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

      # Target precondition: image generation 1 with its initial host-policy
      # generation committed, and the signed upgrade toplevel absent.
      target.wait_until_succeeds("systemctl is-active aos-nix-db.service", timeout=120)
      image_before = json.loads(
          target.succeed("cat /var/lib/profiles/image/state.json")
      )
      config_before = json.loads(
          target.succeed("cat /var/lib/profiles/system/state.json")
      )
      assert image_before["running"] == 1, image_before
      assert len(image_before["generations"]) == 1, image_before
      assert config_before["current"] == 1, config_before
      assert config_before["next"] == 2, config_before
      assert len(config_before["generations"]) == 1, config_before
      assert config_before["generations"][0]["image_gen_parent"] == 1, config_before
      target.succeed("test -e /var/lib/profiles/system/current")

      def assert_generation_axes_unchanged(label):
          image_after = json.loads(
              target.succeed("cat /var/lib/profiles/image/state.json")
          )
          config_after = json.loads(
              target.succeed("cat /var/lib/profiles/system/state.json")
          )
          assert image_after == image_before, (label, image_before, image_after)
          assert config_after == config_before, (label, config_before, config_after)
          target.succeed("test -e /var/lib/profiles/system/current")
      # The miss is intentional; keep nix-store's expected error off the
      # serial console so unexpected warnings remain visible.
      target.fail(
          "${pkgs.nix}/bin/nix-store --check-validity '${sbTop}' "
          "> /tmp/sbtop-validity-precheck.out 2>&1"
      )

      # ════ 1. PUBLISH the signed sysroot + UKI; derive SB facts ════════
      # `apr publish` shells out to sbverify (signer cert), objcopy (.sbat /
      # PCR sections), and systemd-measure (PCR 11) — all reached by store
      # path on PATH. The signed UKI rides along as an image so its facts
      # are cataloged on the sysroot entry.
      registry.succeed(textwrap.dedent("""
          set -eu
          export HOME=/var/lib/apr-operator
          export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test
          export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/nix-conf
          export PATH="${pkgs.sbsigntools}/bin:${pkgs.binutils}/bin:${pkgs.systemd}/lib/systemd:$PATH"
          mkdir -p "$HOME" "$NIX_CONF_DIR"
          printf 'experimental-features = nix-command\\nsandbox = false\\nbuild-users-group =\\n' \\
            > "$NIX_CONF_DIR/nix.conf"

          mkdir -p /run/aos-host-store
          ${pkgs.util-linux}/bin/mount -t 9p \
            -o trans=virtio,version=9p2000.L,msize=1048576,ro \
            aos-host-store /run/aos-host-store
          CLOSURE_INFO='${publicationClosureInfo}'
          test -r "/run/aos-host-store/$(basename "$CLOSURE_INFO")/registration"
          while IFS= read -r store_path; do
            if [ ! -e "$store_path" ]; then
              source_path="/run/aos-host-store/$(basename "$store_path")"
              if [ -L "$source_path" ]; then
                ln -s "$(readlink "$source_path")" "$store_path"
              elif [ -d "$source_path" ]; then
                mkdir "$store_path"
                ${pkgs.util-linux}/bin/mount --bind "$source_path" "$store_path"
              elif [ -f "$source_path" ]; then
                touch "$store_path"
                ${pkgs.util-linux}/bin/mount --bind "$source_path" "$store_path"
              else
                printf 'unsupported store object: %s\n' "$source_path" >&2
                exit 1
              fi
            fi
          done < "/run/aos-host-store/$(basename "$CLOSURE_INFO")/store-paths"
          ${pkgs.nix}/bin/nix-store --load-db \
            < "/run/aos-host-store/$(basename "$CLOSURE_INFO")/registration"
          ${pkgs.nix}/bin/nix-store --check-validity '${sbTop}'
          ${pkgs.nix}/bin/nix-store --check-validity '${sbImageDisk}'
          ${pkgs.nix}/bin/nix-store --check-validity '${sbImageInfo}'
          ${pkgs.util-linux}/bin/findmnt -rn -t 9p -o OPTIONS \
            /run/aos-host-store | grep -qw ro
          ! touch '${sbImageDisk}'/host-store-write-must-fail

          ${pkgs.aos}/bin/apr create sysreg
          REG_DIR=$HOME/.local/share/apm/registries/sysreg
          mkdir -p "$REG_DIR/sb-certs"
          cp ${pkgs.secure-boot-test-keys}/db.crt "$REG_DIR/sb-certs/db.pem"
          DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
          ORIGIN=/var/lib/aos-registry-server/registries/sysreg
          git init --bare --object-format=sha256 "$ORIGIN"
          git -C "$ORIGIN" symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
          git -C "$REG_DIR" remote add origin "$ORIGIN"
          set -- '${sbUki}'/*.efi
          SB_UKI="$1"

          # Publish the signed toplevel with its raw disk image. Its canonical
          # image-info.json binds the exact UKI used to derive SB facts.
          # Capture --json: it carries the derived facts verbatim.
          if ! ${pkgs.aos}/bin/apr --json publish '${sbTop}' \\
            --name aos \\
            --version test-sb-catalog \\
            --description 'secure-boot catalog fixture' \\
            --license MIT \\
            --maintainer test \\
            --sysroot \\
            --image-payload '${sbImage}' \\
            --image-disk '${sbImageDisk}' \\
            --image-info '${sbImageInfo}' --image-format raw \\
            --image-uki "$SB_UKI" \\
            --no-ca \\
            --registry sysreg \\
            --no-commit > "$HOME/publish.json"; then
            cat "$HOME/publish.json" >&2
            exit 1
          fi
          ${pkgs.aos}/bin/apr verify --registry sysreg

          ${pkgs.aos}/bin/apr cache generate \\
            --registry sysreg \\
            --output /var/lib/sysreg-cache \\
            --cache-url http://registry:8000/sysreg-cache \\
            --priority 46 \\
            --no-commit
          chmod -R a+rX /var/lib/sysreg-cache

          # First catalog state: a DECOY cert only — the file exists but does
          # not list the image's real signer (drives the refuse below). Then
          # commit the publish + catalog and push so the origin is non-empty
          # before the consumer clones it.
          DECOY=0000000000000000000000000000000000000000000000000000000000000000
          ${pkgs.aos}/bin/apr sb-certs add decoy \\
            --cert-sha256 "$DECOY" --registry sysreg --no-commit
          git -C "$REG_DIR" add -A
          git -C "$REG_DIR" commit -m 'release: secure-boot catalog fixture'
          git -C "$REG_DIR" tag v0.0.1
          git -C "$REG_DIR" push origin "$DEFAULT_BRANCH" --tags
          chown -R aos-gitd:aos-gitd "$ORIGIN"
          echo "$DEFAULT_BRANCH" > /tmp/sysreg-branch
      """), timeout=1200)

      branch = registry.succeed("cat /tmp/sysreg-branch").strip()
      initial_catalog = json.loads(
          registry.succeed(
              "HOME=/var/lib/apr-operator ${pkgs.aos}/bin/apr "
              "sb-certs list --registry sysreg --json"
          )
      )
      assert initial_catalog["active"] == [
          {
              "cert_sha256": "0" * 64,
              "id": "decoy",
          }
      ], initial_catalog
      assert initial_catalog["revoked"] == [], initial_catalog
      assert initial_catalog["sbat_floor"] == [], initial_catalog

      # The derived Secure Boot facts, straight from `apr publish --json`.
      pub = json.loads(
          registry.succeed("cat /var/lib/apr-operator/publish.json")
      )
      images = pub.get("images", [])
      assert len(images) == 1, f"expected one published image, got: {images!r}"
      img = images[0]
      signer = img.get("sb_signer_cert_sha256")
      sbat = img.get("sbat") or []
      pcr11 = img.get("expected_pcr11")
      print(f"signer={signer}\nsbat={sbat}\npcr11={pcr11}")

      assert signer and len(signer) == 64 and all(
          c in "0123456789abcdef" for c in signer
      ), f"signer cert sha256 missing/malformed: {signer!r}"
      assert sbat, "published UKI recorded no SBAT table (.sbat extraction failed)"
      sbat_component = sbat[0]["component"]
      sbat_generation = int(sbat[0]["generation"])
      assert pcr11 and len(pcr11) == 64 and all(
          c in "0123456789abcdef" for c in pcr11
      ), f"expected_pcr11 missing/malformed: {pcr11!r}"

      # ════ #3 — the recorded PCR 11 is the genuine section measurement ══
      # Recompute it INDEPENDENTLY of the Rust path: dump each UKI section
      # with objcopy and feed the present ones to systemd-measure, exactly
      # as sd-stub measures them. The two must agree byte-for-byte, proving
      # `apr` records the real sd-stub PCR-11 contribution (not the old
      # whole-UKI stand-in, and not a value drifting from the binary).
      recompute = registry.succeed(textwrap.dedent("""
          set -eu
          export PATH="${pkgs.binutils}/bin:${pkgs.systemd}/lib/systemd:$PATH"
          UKI=$(ls ${sbUki}/*.efi | head -1)
          WORK=$(mktemp -d)
          ARGS=""
          for s in .linux .osrel .cmdline .initrd .ucode .splash .dtb .uname .sbat .pcrpkey; do
            objcopy -O binary --only-section="$s" "$UKI" "$WORK/sec$s" 2>/dev/null || true
            if [ -s "$WORK/sec$s" ]; then
              ARGS="$ARGS --''${s#.}=$WORK/sec$s"
            fi
          done
          systemd-measure calculate --bank=sha256 $ARGS > "$WORK/measure.out"
          # systemd-measure prints one `11:sha256=` line per boot phase
          # (enter-initrd → …:ready). Mirror the Rust parser: retain the
          # final value, the stable ready phase quoted during activation.
          DIGEST=""
          while IFS= read -r line; do
            case "$line" in
              11:*) rest=''${line#11:}; DIGEST=''${rest##*=} ;;
            esac
          done < "$WORK/measure.out"
          printf '%s' "$DIGEST"
      """)).strip()
      print(f"recomputed pcr11={recompute}")
      assert recompute == pcr11, (
          f"recorded expected_pcr11 {pcr11!r} != independent "
          f"systemd-measure recompute {recompute!r}"
      )

      # ════ Consumer: stage the registry in SYSTEM scope ════════════════
      target.succeed(textwrap.dedent(f"""
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

      # Helper: (re)publish a catalog state on the registry and fast-forward
      # the target's system clone to it. The package/closure is published
      # once (above); each state only rewrites sb-certs.toml + retags.
      def push_catalog(tag, *sb_cert_cmds):
          script = "set -eu\n"
          script += "export HOME=/var/lib/apr-operator\n"
          script += "export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test\n"
          script += "export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test\n"
          # The origin was chown'd to aos-gitd (so gitd can serve it); root
          # pushing to that file-path remote trips git's dubious-ownership
          # guard, so allow it.
          script += "git config --global --add safe.directory '*'\n"
          script += "REG_DIR=$HOME/.local/share/apm/registries/sysreg\n"
          for cmd in sb_cert_cmds:
              script += f"{cmd}\n"
          script += 'git -C "$REG_DIR" add -A\n'
          script += f'git -C "$REG_DIR" commit -m "catalog: {tag}"\n'
          script += f'git -C "$REG_DIR" tag {tag}\n'
          script += f'git -C "$REG_DIR" push origin {branch} --tags\n'
          script += "ORIGIN=/var/lib/aos-registry-server/registries/sysreg\n"
          script += "chown -R aos-gitd:aos-gitd \"$ORIGIN\"\n"
          registry.succeed(textwrap.dedent(script), timeout=300)
          # Fast-forward the consumer's clone to the new catalog commit.
          target.succeed(
              "${pkgs.git}/bin/git -C /var/lib/apm/registries/sysreg fetch origin "
              f"&& ${pkgs.git}/bin/git -C /var/lib/apm/registries/sysreg reset "
              f"--hard origin/{branch}",
              timeout=120,
          )

      APR = "${pkgs.aos}/bin/apr"

      # ════ 2. REFUSE — signer not in the active db-cert set ════════════
      # The catalog (published above) lists only a decoy cert, so it cannot
      # vouch for the image's real signer. The upgrade downloads, then
      # refuses before creating a generation.
      out = target.fail(
          "HOME=/tmp PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH "
          "${pkgs.aos}/bin/apm upgrade --system --yes 2>&1",
          timeout=1800,
      )
      print("=== refuse (unknown signer) ===\n" + out)
      assert "active db-cert set" in out, (
          f"upgrade was not refused for an untrusted signer:\n{out}"
      )
      assert_generation_axes_unchanged("unknown signer")

      # ════ 3. REFUSE — SBAT generation below the revocation floor ══════
      # The real signer is active now, isolating the floor as the cause:
      # raise the floor one above the image's recorded generation.
      push_catalog(
          "v0.0.2",
          f"{APR} sb-certs add aos-db --cert-sha256 {signer} --registry sysreg --no-commit",
          f"{APR} sb-certs retire decoy --reason replaced-by-production-cert "
          "--registry sysreg --no-commit",
          f"{APR} sb-certs set-floor --component {sbat_component} "
          f"--generation {sbat_generation + 1} --registry sysreg --no-commit",
      )
      rotated_catalog = json.loads(
          registry.succeed(
              f"HOME=/var/lib/apr-operator {APR} "
              "sb-certs list --registry sysreg --json"
          )
      )
      active_ids = {entry["id"] for entry in rotated_catalog["active"]}
      assert active_ids == {"aos-db", "decoy"}, rotated_catalog
      assert rotated_catalog["revoked"] == [
          {
              "id": "decoy",
              "reason": "replaced-by-production-cert",
          }
      ], rotated_catalog
      assert rotated_catalog["sbat_floor"] == [
          {
              "component": sbat_component,
              "generation": sbat_generation + 1,
          }
      ], rotated_catalog
      out = target.fail(
          "HOME=/tmp PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH "
          "${pkgs.aos}/bin/apm upgrade --system --yes 2>&1",
          timeout=600,
      )
      print("=== refuse (sbat floor) ===\n" + out)
      assert "revocation floor" in out, (
          f"upgrade was not refused for a below-floor SBAT generation:\n{out}"
      )
      assert_generation_axes_unchanged("SBAT floor")

      # ════ 4. ACCEPT — signer active, no blocking floor ════════════════
      # `set-floor` only ever raises (a floor can't be walked back to
      # un-revoke a component), so reach the accepting state by rewriting
      # the catalog from scratch: a fresh sb-certs.toml listing just the
      # real signer, with no floor. (A legitimate operator edit of the
      # committed roster.)
      push_catalog(
          "v0.0.3",
          'rm -f "$REG_DIR/sb-certs.toml"',
          f"{APR} sb-certs add aos-db --cert-sha256 {signer} --registry sysreg --no-commit",
      )
      out = target.fail(
          "HOME=/tmp PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH "
          "${pkgs.aos}/bin/apm upgrade --system --yes 2>&1",
          timeout=600,
      )
      print("=== accept catalog, reject legacy payload ===\n" + out)
      assert "Secure Boot catalog validation passed" in out, (
          f"a valid catalog did not report SB validation:\n{out}"
      )
      assert "no authenticated raw OTA image" in out, (
          f"a legacy UKI-only payload passed the A/B image gate:\n{out}"
      )
      assert_generation_axes_unchanged("catalog accepted without raw OTA")
      target.succeed("${pkgs.nix}/bin/nix-store --check-validity '${sbTop}'")
      failed = target.succeed("systemctl --failed --no-legend").strip()
      assert not failed, f"failed units after accepted upgrade: {failed!r}"
    '';
}
