# Generation and image-axis acceptance.
#
# Exercises the production image publisher, A/B stage and boot path, first-boot
# evaluation, live configuration activation, and rollback porcelain.
{
  lib,
  mkSystem,
  pkgs,
  systems,
}: let
  candidate = mkSystem [
    ../../systems/server-verity.nix
    ../../systems/_server-test-packages.nix
    ../../systems/_fleet-transition-test.nix
    {
      aos.system.version = "9999.0.0-generation-axes-candidate";
      # The transition fixture exercises evaluator and image compatibility;
      # its retained configuration already supplies every selected package.
      # Keep the candidate image focused on that contract instead of baking
      # unused optional host-policy closures into the OTA payload.
      aos.image.hostConfigClosures = lib.mkForce [];
      # Both targets must reach the authenticated registry before installing
      # the candidate's retained native image artifacts.
      aos.networking.interfaces.fleet-target = {
        matchMACAddress = "52:54:00:12:00:03";
        address = "192.168.50.12/24";
      };
    }
  ];
  candidateTop = candidate.config.system.build.toplevel;
  candidateImage = candidate.config.system.build.image.raw;
  candidateImageDisk = candidate.config.system.build.imageArtifacts.raw.disk;
  candidateImageInfo = candidate.config.system.build.imageArtifacts.raw.info;

  # Image-mode machines do not consume fleet `extraClosures`. The test driver
  # clones the authenticated registry in each guest, so make the AOS-built Git
  # package part of the test images themselves.
  targetBase = mkSystem [
    ../../systems/server-verity.nix
    ../../systems/_server-test-packages.nix
    ../../systems/_fleet-transition-test.nix
    {
      # Git is image-bundled fixture tooling for cloning the authenticated
      # registry. Seeding that profile uses the AOS binutils helper in the
      # initrd. Declare both fixture roots so their interpreter and development
      # dependencies remain covered by the test-only artifact allowance.
      # The corresponding EROFS fixture root measures 670 MiB.
      aos.image.budgets.maxRootMiB = 704;
      # Full Git, its interpreters, and the test agent bring this fixture's
      # runtime closure to 1,015 MiB; production images keep their own limits.
      aos.image.budgets.maxRuntimeClosureMiB = 3072;
      # The signed A/B fixture compresses to 836 MiB with those test tools.
      aos.image.budgets.maxDownloadMiB = 864;
      aos.image.testArtifactRoots = [pkgs.binutils pkgs.git];
      environment.systemPackages = [pkgs.git];
      # This acceptance test runs three guests while generating and serving a
      # full closure. Give evaluation enough wall time on shared CI builders;
      # production systems retain the normal service limit.
      aos.services."control-plane.aos-activate".lifecycle.start_timeout_millis = lib.mkForce 600000;
      # A resolver blocked in the synthetic multicast network can remain in
      # uninterruptible I/O while systemd tears the guest down. Do not spend
      # the production-wide stop timeout on that unrelated test transport
      # artifact before exercising the next boot.
      systemd.services."systemd-resolved".serviceConfig.TimeoutStopSec =
        lib.mkForce "10s";
    }
  ];
  registrySystem = mkSystem [
    ../../systems/server-test.nix
    {
      aos.packages =
        lib.genAttrs
        ["aos-registry-server" "test-static-cache-server"]
        (name: {
          package = pkgs.${name};
          bundle = true;
        });
      # The static server binds this directory before publication fills it.
      environment.etc."tmpfiles.d/fleet-registry-cache.conf".text = ''
        d /var/lib/sysreg-cache 0755 root root - -
      '';
    }
  ];
in {
  name = "config-image-generation-axes";
  timeout = 5400;
  # Three concurrent Secure Boot guests can spend several minutes in firmware
  # when a KVM builder is under I/O pressure. Keep the initial readiness budget
  # separate from the tighter per-transition reboot assertions below.
  bootTimeout = 1200;
  systemReadyTimeout = 300;

  machines = {
    registry = {
      system = registrySystem;
      packages = ["aos-registry-server" "test-static-cache-server"];
      metadata."host.nix" = ''
        {
          aos.networking.hostName = "registry";
          aos.apm.desiredPackages = ["aos-registry-server" "test-static-cache-server"];
          "aos-registry-server".enable = true;
          "test-static-cache-server".enable = true;
        }
      '';
      extraClosures = [
        pkgs.aos.apr
        candidateTop
        candidateImage
        candidateImageDisk
        candidateImageInfo
        pkgs.secure-boot-test-keys
        pkgs.sbsigntools
        pkgs.binutils
        pkgs.git
        pkgs.openssh
        pkgs.systemd
        pkgs.e2fsprogs
        pkgs.util-linux
      ];
      varSizeMiB = 12288;
      # Cache publication writes several GiB of NARs before the target imports
      # them. Use a fresh sparse disk so staging does not amplify writes through
      # the registry VM's reflinked system disk.
      extraDisks = [
        {
          interface = "scsi";
          sizeMiB = 8192;
          serial = "aos-cache";
        }
      ];
      memoryMiB = 6144;
    };

    target = {
      system = targetBase;
      bootMode = "image";
      imageDiskMiB = 24576;
      # Importing the complete authenticated system closure briefly runs APM,
      # nix-store, and the boot evaluator together. Avoid swapping core system
      # services while the test immediately exercises a real reboot.
      memoryMiB = 8192;
      tpm = true;
      metadata."host.nix" = import ./_native-runtime-source.nix {
        inherit pkgs;
        hostname = "axis-one";
        value = "one";
        filePath = "config-generation-axis";
        fileContent = "one\n";
      };
    };
  };

  testScript =
    # python
    ''
      import base64
      import json
      import re
      import textwrap

      APM = "${pkgs.aos.apm}/bin/apm"
      APR = "${pkgs.aos.apr}/bin/apr"
      JQ = "${pkgs.jq}/bin/jq"
      RUNTIME = "${pkgs.aos.packageRuntime}/bin/aos-package-runtime"
      PROFILE = "/var/lib/profiles/system"
      IMAGE_STATE = "/var/lib/profiles/image/state.json"


      def image_state(machine):
          return json.loads(machine.succeed(f"cat {IMAGE_STATE}"))


      def current_config(machine):
          number = json.loads(machine.succeed(
              f"{RUNTIME} deployment-current --profile {PROFILE} --committed-during-recovery"
          ))["generation"]
          assert isinstance(number, int) and number > 0, number
          marker = json.loads(machine.succeed(f"cat {PROFILE}/gen-{number}/native-deployment.json"))
          descriptor = json.loads(machine.succeed(f"cat {PROFILE}/gen-{number}/evaluation.json"))
          assert marker["profile_generation"] == number, marker
          assert descriptor["schema"] == "aos.package.evaluation-input", descriptor
          return {"current": number, "marker": marker, "descriptor": descriptor}, {"number": number, **marker, **descriptor}


      def generation_attestation(machine, number):
          machine.succeed("systemctl restart aos-image-boot-commit.service", timeout=300)
          record = json.loads(machine.succeed(
              f"cat {PROFILE}/gen-{number}/gen-attestation.json"
          ))
          marker = json.loads(machine.succeed(f"cat {PROFILE}/gen-{number}/native-deployment.json"))
          assert record["schema"] == "aos.package.generation-attestation", record
          assert record["profile_generation"] == number, record
          assert record["sequence"] == marker["sequence"] and record["content"] == marker["content"], record
          assert record["quote_status"] == "quoted", record
          assert record["quote"], record
          return record


      def assert_live(machine, hostname, value):
          machine.succeed(f'test "$(cat /etc/hostname)" = {hostname}')
          machine.succeed(f'test "$(cat /etc/config-generation-axis)" = {value}')
          machine.succeed("systemctl is-active --quiet aos-test-agent.service")
          machine.succeed("systemctl is-active --quiet multi-user.target")


      def configure_registry(machine, public_key):
          machine.succeed(textwrap.dedent(f"""
              set -eu
              HOME=/tmp USER=root {APM} registry --system add \
                git://registry:9418/sysreg \
                --name sysreg \
                --tag 1.0.0 \
                --trust-key '{public_key}'
              HOME=/tmp USER=root {APM} update --system --registry sysreg
          """), timeout=180)


      def stage_candidate(machine):
          _, before = current_config(machine)
          before_boot = machine.succeed("cat /proc/sys/kernel/random/boot_id").strip()
          machine.succeed(
              "HOME=/tmp PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH "
              f"{APM} upgrade --system --yes", timeout=1800
          )
          staged = image_state(machine)
          assert staged["running"] == 1, staged
          number = staged["pending"]
          assert number is not None, staged
          candidates = [record for record in staged["generations"] if record["number"] == number]
          assert len(candidates) == 1, staged
          candidate = candidates[0]
          assert candidate["module_library"]["store_path"].startswith("/nix/store/"), candidate
          assert candidate["module_library"]["nar_size"] > 0, candidate
          assert candidate["evaluation_descriptor"].startswith("/nix/store/"), candidate
          # Native submission may publish rollout policy; it preserves the
          # operator role and the selected evaluator library during staging.
          _, after = current_config(machine)
          assert after["library"] == before["library"], (before, after)
          assert machine.succeed("cat /proc/sys/kernel/random/boot_id").strip() == before_boot
          return before, number


      target.wait_until_succeeds("systemctl is-active --quiet aos-activate.service", timeout=300)
      assert_live(target, "axis-one", "one")
      initial_state, initial = current_config(target)
      initial_attestation = generation_attestation(target, initial["number"])
      running_initial = next(record for record in image_state(target)["generations"] if record["number"] == 1)
      assert initial["library"].startswith(running_initial["module_library"]["store_path"] + "/"), (initial, running_initial)

      second_source = ${builtins.toJSON (import ./_native-runtime-source.nix {
        inherit pkgs;
        hostname = "axis-two";
        value = "two";
        filePath = "config-generation-axis";
        fileContent = "two\n";
      })}
      encoded = base64.b64encode(second_source.encode()).decode()
      target.succeed("mkdir -p /run/config-axis-two")
      target.succeed(f"printf '%s' {encoded} | base64 -d > /run/config-axis-two/host.nix")
      image_before_switch = image_state(target)
      boot_before_switch = target.succeed("cat /proc/sys/kernel/random/boot_id").strip()
      target.succeed(
          f"{APM} switch --worktree /run/config-axis-two --eval-root /run/config-axis-two-eval", timeout=300
      )
      second_state, second = current_config(target)
      assert second["number"] != initial["number"], (initial, second)
      assert second["library"] == initial["library"], (initial, second)
      assert second["runtimeConfiguration"] != initial["runtimeConfiguration"], (initial, second)
      assert image_state(target) == image_before_switch
      assert target.succeed("cat /proc/sys/kernel/random/boot_id").strip() == boot_before_switch
      assert_live(target, "axis-two", "two")
      second_attestation = generation_attestation(target, second["number"])
      assert second_attestation["activation_id"] != initial_attestation["activation_id"]

      # Rollback creates a new checked publication of the exact retained source.
      target.succeed(f"{APM} rollback --system --generation {initial['number']}", timeout=300)
      direct_state, direct = current_config(target)
      assert direct["number"] not in (initial["number"], second["number"]), direct
      assert direct["content"] == initial["content"], (direct, initial)
      assert direct_state["descriptor"] == initial_state["descriptor"], (direct_state, initial_state)
      assert image_state(target) == image_before_switch
      assert target.succeed("cat /proc/sys/kernel/random/boot_id").strip() == boot_before_switch
      assert_live(target, "axis-one", "one")
      refreshed_attestation = generation_attestation(target, direct["number"])
      assert refreshed_attestation["content"] == initial_attestation["content"]
      assert refreshed_attestation["activation_id"] != initial_attestation["activation_id"]
      assert refreshed_attestation["sequence"] > initial_attestation["sequence"]

      # Publish one real candidate dm-verity image and its authenticated UKI facts.
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
          printf 'experimental-features = nix-command\nsandbox = false\nbuild-users-group =\n' \
            > "$NIX_CONF_DIR/nix.conf"

          ${pkgs.nix}/bin/nix-store --check-validity '${candidateTop}'
          ${pkgs.nix}/bin/nix-store --check-validity '${candidateImage}'
          KEYGEN=$(${pkgs.aos.apr}/bin/apr keys generate release --registry sysreg 2>&1)
          printf '%s\n' "$KEYGEN"
          PUBKEY=$(printf '%s\n' "$KEYGEN" | awk '/Public key:/ {print $NF; exit}')
          test -n "$PUBKEY"
          KEY=$HOME/.config/apm/keys/sysreg-release.key
          ${pkgs.aos.apr}/bin/apr create sysreg \
            --trust-key "$PUBKEY" \
            --trust-key-id release \
            --key "$KEY"
          REG_DIR=$HOME/.local/share/apm/registries/sysreg
          DEFAULT_BRANCH=$(git -C "$REG_DIR" symbolic-ref --short HEAD)
          ORIGIN=/var/lib/aos-registry-server/registries/sysreg
          git init --bare --object-format=sha256 "$ORIGIN"
          git -C "$ORIGIN" symbolic-ref HEAD "refs/heads/$DEFAULT_BRANCH"
          git -C "$REG_DIR" remote add origin "$ORIGIN"
          mkdir -p "$HOME/.config/apm/registries.d"
          {
            printf '%s\n' '[registry]' 'name = "sysreg"'
            printf 'url = "file://%s"\n' "$REG_DIR"
            printf '\n%s\n' '[registry.signing_keys]'
            printf 'release = "%s"\n' "$KEY"
          } > "$HOME/.config/apm/registries.d/sysreg.toml"

          if ! ${pkgs.aos.apr}/bin/apr --json publish '${candidateTop}' \
            --name aos \
            --version 9999.0.0-generation-axes-candidate \
            --description 'Two-axis native image fixture' \
            --license MIT \
            --maintainer test \
            --sysroot \
            --image-payload '${candidateImage}' \
            --image-disk '${candidateImageDisk}' \
            --image-info '${candidateImageInfo}' --image-format raw \
            --image-contract-schema aos.image.metadata/v1 \
            --no-ca \
            --registry sysreg \
            --key-id release \
            --no-commit > /tmp/publish.json; then
            cat /tmp/publish.json >&2
            exit 1
          fi
          echo "$DEFAULT_BRANCH" > /tmp/sysreg-branch
          echo "$PUBKEY" > /tmp/sysreg-pubkey
      """), timeout=1200)

      publication = json.loads(registry.succeed("cat /tmp/publish.json"))
      images = publication.get("images", [])
      assert len(images) == 1, images
      contract = images[0]["delivery"]["artifact_contract"]
      assert contract["schema"] == "aos.image.metadata/v1", contract
      assert contract["document"]["store_path"] == '${candidateImageInfo}', contract
      assert contract["artifacts"]["store_path"] == '${candidateImage}', contract
      metadata_bytes = registry.succeed("cat '${candidateImageInfo}'")
      metadata = json.loads(metadata_bytes)
      assert metadata["schema_version"] == contract["schema"], metadata
      digest = registry.succeed("${pkgs.coreutils}/bin/sha256sum '${candidateImageInfo}'").split()[0]
      assert digest == contract["document"]["sha256"], contract
      for slot in ("a", "b"):
          normal = metadata["efi"]["normal_" + slot]
          assert re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", normal["expected_ready_pcr11"]), normal
          assert normal["artifact"]["size_bytes"] > 0, normal
      registry.succeed(textwrap.dedent(f"""
          set -eu
          export HOME=/tmp
          export GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test
          export GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test
          export NIX_REMOTE=""
          export NIX_CONF_DIR=/tmp/nix-conf
          export PATH="${pkgs.sbsigntools}/bin:${pkgs.binutils}/bin:${pkgs.systemd}/lib/systemd:$PATH"
          REG_DIR=$HOME/.local/share/apm/registries/sysreg
          DEFAULT_BRANCH=$(cat /tmp/sysreg-branch)
          ORIGIN=/var/lib/aos-registry-server/registries/sysreg
          KEY=$HOME/.config/apm/keys/sysreg-release.key
          {APR} verify --registry sysreg
          git -C "$REG_DIR" add -A
          git -C "$REG_DIR" \
            -c gpg.format=ssh \
            -c gpg.ssh.program='${pkgs.openssh}/bin/ssh-keygen' \
            -c user.signingkey="$KEY" \
            commit -S -m 'publish: configuration native image fixtures'
          # The cache server has a private mount namespace. Stop it before
          # mounting the publication disk so the restarted service sees the
          # mounted tree rather than the directory it replaced.
          systemctl stop aos-pkg-test-static-cache-server.target
          mkdir -p /var/lib/sysreg-cache
          ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -q /dev/sda
          ${pkgs.util-linux}/bin/mount /dev/sda /var/lib/sysreg-cache
          mkdir -p /var/lib/sysreg-cache/tmp
          export XDG_CACHE_HOME=/var/lib/sysreg-cache
          export TMPDIR=/var/lib/sysreg-cache/tmp
          {APR} release 1.0.0 \
            --registry sysreg \
            --key-id release \
            --jobs 1 \
            --cache-url http://registry:8000/sysreg-cache/apm/registry-static/sysreg \
            --cache-priority 46 \
            --upload-url file:///var/lib/sysreg-cache/apm/registry-static/sysreg
          chmod -R a+rX /var/lib/sysreg-cache
          systemctl start aos-pkg-test-static-cache-server.target
          systemctl is-active --quiet test-static-cache-server.socket
          git -C "$REG_DIR" push origin "$DEFAULT_BRANCH" --tags
          # Resolve ownership through the daemon's idmapped state directory.
          git_pid=$(systemctl show -p MainPID --value aos-registry-server-gitd.service)
          test "$git_pid" -gt 0
          git_owner=$(id -u aos-gitd):$(id -g aos-gitd)
          ${pkgs.util-linux}/bin/nsenter --target "$git_pid" --mount --root --wd=/ ${pkgs.coreutils}/bin/chown -R "$git_owner" "$ORIGIN"
      """), timeout=1800)
      public_key = registry.succeed("cat /tmp/sysreg-pubkey").strip()
      configure_registry(target, public_key)
      # Publish and physically stage a distinct authenticated image. This
      # fixture uses the same repository library; library-change replay is
      # exercised separately by native immutable-source integration tests.
      staged_target_config, target_candidate = stage_candidate(target)
      target.reboot(timeout=600)
      target.wait_until_succeeds("systemctl is-active --quiet multi-user.target", timeout=600)
      target.wait_until_succeeds("systemctl is-active --quiet aos-image-boot-commit.service", timeout=300)
      booted_images = image_state(target)
      assert booted_images["running"] == target_candidate, booted_images
      assert booted_images.get("pending") is None, booted_images
      rebound_state, rebound = current_config(target)
      running_image = next(record for record in booted_images["generations"] if record["number"] == target_candidate)
      assert running_image["toplevel"] != running_initial["toplevel"], (running_image, running_initial)
      assert running_image["module_library"] == running_initial["module_library"], (running_image, running_initial)
      assert rebound["library"] == staged_target_config["library"], rebound
      assert_live(target, "axis-one", "one")
      for source in second["configuration"] + second["runtimeConfiguration"] + [second["library"]]:
          target.succeed(f"test -e {source}")

      # A physical image transition leaves historical evaluator/source identity
      # intact. Rollback replays the retained descriptor into a new publication.
      boot_before_cross = target.succeed("cat /proc/sys/kernel/random/boot_id").strip()
      target.succeed(f"{APM} rollback --system --generation {second['number']}", timeout=300)
      cross_state, cross = current_config(target)
      assert cross["number"] not in (initial["number"], second["number"]), cross
      assert cross["content"] == second["content"], (cross, second)
      assert cross_state["descriptor"] == second_state["descriptor"], (cross_state, second_state)
      assert target.succeed("cat /proc/sys/kernel/random/boot_id").strip() == boot_before_cross
      assert image_state(target) == booted_images
      assert_live(target, "axis-two", "two")
      cross_attestation = generation_attestation(target, cross["number"])
      assert cross_attestation["image"]["toplevel"] == running_image["toplevel"], cross_attestation
      assert cross_attestation["evaluation"] == second_state["descriptor"], cross_attestation
    '';
}
