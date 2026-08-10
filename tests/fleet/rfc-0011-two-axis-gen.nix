# Two-axis generation acceptance.
#
# Exercises the production image publisher, A/B stage and boot path, first-boot
# evaluation, live configuration activation, and rollback porcelain. The two
# target VMs separate the successful cross-ABI path from the deliberately
# incompatible config-module path so the latter can fail closed without
# weakening the positive acceptance case.
{
  lib,
  mkSystem,
  pkgs,
  systems,
}: let
  abi2 = mkSystem [
    ../../systems/server-verity.nix
    {
      aos.system.version = "9999.0.0-rfc0011-abi2";
      aos.system.moduleAbi = 2;
      # The transition fixture exercises evaluator and image compatibility;
      # its retained configuration already supplies every selected package.
      # Keep the candidate image focused on that contract instead of baking
      # unused optional host-policy closures into the OTA payload.
      aos.image.hostConfigClosures = lib.mkForce [];
    }
  ];
  abi2Top = abi2.config.system.build.toplevel;
  abi2Image = abi2.config.system.build.image.raw;
  abi2Uki = abi2.config.system.build.uki;

  # A real installable package whose authored configuration module supports
  # ABI 1 only. Its empty expose policy gives APM a normal signed runtime
  # artifact while the authored option module remains the negative ABI gate.
  abi1OnlyConfig = pkgs.mkDerivation {
    pname = "rfc0011-abi1-config";
    version = "0";
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/rfc0011-abi1-config"
          printf '%s\n' fixture > "$out/share/rfc0011-abi1-config/payload"
        '';
      }
    ];
    expose = {};
    configModule = {
      src = ../../pkgs/tests/_config-module-smoke;
      moduleAbiCompat = {
        min = 1;
        max = 1;
      };
      declares = [
        "configModuleSmoke.command"
        "configModuleSmoke.enable"
        "configModuleSmoke.privateMessage"
      ];
      ownsRoots = [
        {
          root = "configModuleSmoke";
          interfaceAbi = 1;
          contributable = [];
        }
      ];
    };
  };

  # Image-mode machines do not consume fleet `extraClosures`. The test driver
  # clones the authenticated registry in each guest, so make the AOS-built Git
  # package part of the test images themselves.
  targetBase = mkSystem [
    ../../systems/server-verity.nix
    {environment.systemPackages = [pkgs.git];}
  ];
  abi1BaseLib = targetBase.config.aos.config.evalAtBoot.baseLib;

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
  name = "rfc-0011-two-axis-gen";
  timeout = 5400;
  bootTimeout = 600;

  machines = {
    registry = {
      system = registrySystem;
      packages = ["aos-registry-server" "test-static-cache-server"];
      extraClosures = [
        abi2Top
        abi2Image
        abi2Uki
        pkgs.sbsigntools
        pkgs.binutils
        pkgs.git
        pkgs.openssh
        pkgs.systemd
        abi1OnlyConfig
        abi1OnlyConfig.config
        abi1BaseLib
      ];
      varSizeMiB = 12288;
      # Cache publication writes several GiB of NARs before the target imports
      # them. Use a fresh sparse disk so staging does not amplify writes through
      # the registry VM's reflinked system disk.
      extraDisks = [
        {
          sizeMiB = 4096;
          serial = "aos-cache";
        }
      ];
      memoryMiB = 6144;
    };

    target = {
      system = targetBase;
      bootMode = "image";
      imageDiskMiB = 24576;
      memoryMiB = 4096;
      tpm = true;
      packages = ["aos-test-agent"];
      metadata."host.nix" = ''
        {
          aos.provisioning.storage.partitions.var.sizeMin = "8G";
          aos.networking.hostName = "axis-one";
          aos.apm.desiredPackages = [ "aos-test-agent" ];
          environment.etc."rfc0011-axis".text = "one\n";
        }
      '';
    };

    incompatible = {
      system = targetBase;
      bootMode = "image";
      imageDiskMiB = 24576;
      memoryMiB = 4096;
      tpm = true;
      packages = ["aos-test-agent"];
      metadata."host.nix" = ''
        {
          aos.provisioning.storage.partitions.var.sizeMin = "8G";
          aos.networking.hostName = "axis-incompatible";
          aos.apm.desiredPackages = [ "aos-test-agent" ];
          environment.etc."rfc0011-axis".text = "incompatible\n";
        }
      '';
    };
  };

  testScript =
    # python
    ''
      import base64
      import json
      import re
      import textwrap

      APM = "${pkgs.aos}/bin/apm"
      APR = "${pkgs.aos}/bin/apr"
      JQ = "${pkgs.jq}/bin/jq"
      CONFIG_STATE = "/var/lib/profiles/system/state.json"
      IMAGE_STATE = "/var/lib/profiles/image/state.json"


      def config_state(machine):
          return json.loads(machine.succeed(f"cat {CONFIG_STATE}"))


      def image_state(machine):
          return json.loads(machine.succeed(f"cat {IMAGE_STATE}"))


      def config_generation(state, number):
          matches = [g for g in state["generations"] if g["number"] == number]
          assert len(matches) == 1, (number, state)
          return matches[0]


      def current_config(machine):
          state = config_state(machine)
          return state, config_generation(state, state["current"])


      def generation_attestation(machine, number):
          return json.loads(machine.succeed(
              f"cat /var/lib/profiles/system/gen-{number}/gen-attestation.json"
          ))


      def generation_activation_inode(machine, number):
          return machine.succeed(
              f"stat -c %i /var/lib/profiles/system/gen-{number}/activation.json"
          ).strip()


      def assert_live(machine, hostname, value):
          machine.succeed(f'test "$(cat /etc/hostname)" = {hostname}')
          machine.succeed(f'test "$(cat /etc/rfc0011-axis)" = {value}')
          machine.succeed("systemctl is-active --quiet aos-test-agent.service")
          machine.succeed("systemctl is-active --quiet multi-user.target")


      def configure_registry(machine, public_key):
          machine.succeed(textwrap.dedent(f"""
              set -eu
              HOME=/tmp USER=root {APM} registry --system add \
                git://registry:9418/sysreg \
                --name sysreg \
                --version '=1.0.0' \
                --trust-key '{public_key}'
              HOME=/tmp USER=root {APM} update --system --registry sysreg
          """), timeout=180)


      def stage_abi2(machine):
          before_config = config_state(machine)
          before_boot = machine.succeed("cat /proc/sys/kernel/random/boot_id").strip()
          output = machine.succeed(
              "HOME=/tmp PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH "
              f"{APM} upgrade --system --yes 2>&1",
              timeout=1800,
          )
          assert "Staging inactive A/B image slot" in output, output
          staged = image_state(machine)
          assert staged["running"] == 1, staged
          candidate_number = staged["pending"]
          assert candidate_number is not None, staged
          assert staged["default"] == candidate_number, staged
          candidate = config_generation(
              {"generations": staged["generations"]}, candidate_number
          )
          assert candidate["module_abi"] == 2, candidate
          assert config_state(machine) == before_config
          assert machine.succeed(
              "cat /proc/sys/kernel/random/boot_id"
          ).strip() == before_boot
          return before_config, candidate_number


      # Establish both ABI-1 hosts through the real boot evaluator and graph.
      for machine in (target, incompatible):
          machine.wait_until_succeeds(
              "systemctl is-active --quiet aos-graph-compile.service", timeout=300
          )
          machine.succeed("systemctl is-active --quiet aos-config.target")
      assert_live(target, "axis-one", "one")
      assert_live(incompatible, "axis-incompatible", "incompatible")

      initial_state, initial = current_config(target)
      assert initial["module_abi_pinned"] == 1, initial
      assert initial["image_gen_parent"] == 1, initial
      initial_attestation = generation_attestation(target, initial["number"])
      initial_activation_inode = generation_activation_inode(target, initial["number"])
      # Config-only activation changes the overlay without selecting an image
      # or rebooting. Preserve this generation for the later cross-ABI replay.
      second_host = """{
        aos.provisioning.storage.partitions.var.sizeMin = \"8G\";
        aos.networking.hostName = \"axis-two\";
        aos.apm.desiredPackages = [ \"aos-test-agent\" ];
        environment.etc.\"rfc0011-axis\".text = \"two\\n\";
      }
      """
      encoded = base64.b64encode(second_host.encode()).decode()
      target.succeed(
          f"printf '%s' {encoded} | base64 -d > /run/rfc0011-axis-two.nix"
      )
      image_before_switch = image_state(target)
      boot_before_switch = target.succeed(
          "cat /proc/sys/kernel/random/boot_id"
      ).strip()
      target.succeed(f"""
          {APM} switch \
            --from /run/rfc0011-axis-two.nix \
            --eval-root /run/rfc0011-axis-two-eval
      """, timeout=300)
      second_state, second = current_config(target)
      assert second["number"] != initial["number"], (initial, second)
      assert second["module_abi_pinned"] == 1, second
      assert second["image_gen_parent"] == 1, second
      assert image_state(target) == image_before_switch
      assert target.succeed(
          "cat /proc/sys/kernel/random/boot_id"
      ).strip() == boot_before_switch
      assert_live(target, "axis-two", "two")
      second_attestation = generation_attestation(target, second["number"])
      assert second_attestation["generation_id"] == second["manifest_hash"]
      assert second_attestation["activation_id"] != initial_attestation["activation_id"]

      # Same-ABI rollback is direct reactivation: it changes only `current`,
      # creates no generation, and never changes the image or boot identity.
      generation_count = len(second_state["generations"])
      target.succeed(
          f"{APM} rollback --system --generation {initial['number']}", timeout=300
      )
      direct_state, direct = current_config(target)
      assert direct["number"] == initial["number"], direct_state
      assert len(direct_state["generations"]) == generation_count, direct_state
      assert image_state(target) == image_before_switch
      assert target.succeed(
          "cat /proc/sys/kernel/random/boot_id"
      ).strip() == boot_before_switch
      assert_live(target, "axis-one", "one")
      refreshed_attestation = generation_attestation(target, initial["number"])
      assert refreshed_attestation["generation_id"] == initial_attestation["generation_id"]
      assert refreshed_attestation["manifest_hash"] == initial_attestation["manifest_hash"]
      assert refreshed_attestation["activation_id"] != initial_attestation["activation_id"]
      assert refreshed_attestation["quote"] != initial_attestation["quote"]
      assert generation_activation_inode(target, initial["number"]) != initial_activation_inode
      initial_events = [
          json.loads(line)
          for line in target.succeed("cat /run/log/aos-packages.cel").splitlines()
          if line.strip()
      ]
      initial_activation_ids = [
          event["activation_id"]
          for event in initial_events
          if event["event_type"] == "aos-generation-attestation"
          and event["generation_id"] == initial_attestation["generation_id"]
      ]
      assert initial_attestation["activation_id"] in initial_activation_ids
      assert refreshed_attestation["activation_id"] in initial_activation_ids
      assert len(set(initial_activation_ids)) >= 2, initial_activation_ids

      # Publish one real ABI-2 dm-verity image and its authenticated UKI facts.
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

          ${pkgs.nix}/bin/nix-store --check-validity '${abi2Top}'
          ${pkgs.nix}/bin/nix-store --check-validity '${abi2Image}'
          KEYGEN=$(${pkgs.aos}/bin/apr keys generate release --registry sysreg 2>&1)
          printf '%s\n' "$KEYGEN"
          PUBKEY=$(printf '%s\n' "$KEYGEN" | awk '/Public key:/ {print $NF; exit}')
          test -n "$PUBKEY"
          KEY=$HOME/.config/apm/keys/sysreg-release.key
          ${pkgs.aos}/bin/apr create sysreg \
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

          set -- '${abi2Uki}'/*.efi
          test "$#" -eq 1
          ABI2_UKI="$1"

          if ! ${pkgs.aos}/bin/apr --json publish '${abi2Top}' \
            --name aos \
            --version 9999.0.0-rfc0011-abi2 \
            --description 'Two-axis ABI fixture' \
            --license MIT \
            --maintainer test \
            --sysroot \
            --image '${abi2Image}' --image-format raw \
            --image-uki "$ABI2_UKI" \
            --no-ca \
            --registry sysreg \
            --key-id release \
            --no-commit > /tmp/publish.json; then
            cat /tmp/publish.json >&2
            exit 1
          fi
          ${pkgs.aos}/bin/apr publish '${abi1OnlyConfig}' \
            --name rfc0011-abi1-config \
            --version 0 \
            --description 'ABI-1-only config module fixture' \
            --license MIT \
            --maintainer test \
            --config-module '${abi1OnlyConfig.config}' \
            --config-base-lib '${abi1BaseLib}' \
            --registry sysreg \
            --key-id release \
            --no-commit
          echo "$DEFAULT_BRANCH" > /tmp/sysreg-branch
          echo "$PUBKEY" > /tmp/sysreg-pubkey
      """), timeout=1200)

      publication = json.loads(registry.succeed("cat /tmp/publish.json"))
      images = publication.get("images", [])
      assert len(images) == 1, images
      ukis = images[0].get("ukis", [])
      assert {u.get("slot") for u in ukis} == {"a", "b"}, ukis
      signers = sorted({u["sb_signer_cert_sha256"] for u in ukis})
      assert all(re.fullmatch(r"[0-9a-f]{64}", signer) for signer in signers)
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
          export PATH="${pkgs.sbsigntools}/bin:${pkgs.binutils}/bin:${pkgs.systemd}/lib/systemd:$PATH"
          REG_DIR=$HOME/.local/share/apm/registries/sysreg
          DEFAULT_BRANCH=$(cat /tmp/sysreg-branch)
          ORIGIN=/var/lib/aos-registry-server/registries/sysreg
          KEY=$HOME/.config/apm/keys/sysreg-release.key
          {catalog_commands}
          {APR} verify --registry sysreg
          git -C "$REG_DIR" add -A
          git -C "$REG_DIR" \
            -c gpg.format=ssh \
            -c gpg.ssh.program='${pkgs.openssh}/bin/ssh-keygen' \
            -c user.signingkey="$KEY" \
            commit -S -m 'publish: configuration ABI fixtures'
          mkdir -p /var/lib/sysreg-cache
          ${pkgs.e2fsprogs}/bin/mkfs.ext4 -F -q /dev/disk/by-id/virtio-aos-cache
          ${pkgs.util-linux}/bin/mount /dev/disk/by-id/virtio-aos-cache /var/lib/sysreg-cache
          {APR} release 1.0.0 \
            --registry sysreg \
            --key-id release \
            --jobs 1 \
            --cache-url http://registry:8000/sysreg-cache \
            --cache-priority 46 \
            --upload-url file:///var/lib/sysreg-cache
          chmod -R a+rX /var/lib/sysreg-cache
          git -C "$REG_DIR" push origin "$DEFAULT_BRANCH" --tags
          chown -R aos-gitd:aos-gitd "$ORIGIN"
      """), timeout=1800)
      public_key = registry.succeed("cat /tmp/sysreg-pubkey").strip()
      configure_registry(target, public_key)
      configure_registry(incompatible, public_key)

      # The incompatible host starts clean, then consumes the ABI-1-only
      # config module from the signed release. This makes the generation's
      # release provenance and config realization independently verifiable.
      incompatible_host = """{
        aos.provisioning.storage.partitions.var.sizeMin = \"8G\";
        aos.networking.hostName = \"axis-incompatible\";
        aos.apm.desiredPackages = [ \"aos-test-agent\" \"rfc0011-abi1-config\" ];
        configModuleSmoke.enable = true;
        environment.etc.\"rfc0011-axis\".text = \"incompatible\\n\";
      }
      """
      incompatible_encoded = base64.b64encode(incompatible_host.encode()).decode()
      incompatible.succeed(
          f"printf '%s' {incompatible_encoded} | base64 -d > /run/rfc0011-incompatible.nix"
      )
      incompatible.succeed(f"""
          {APM} switch \
            --from /run/rfc0011-incompatible.nix \
            --eval-root /run/rfc0011-incompatible-eval
      """, timeout=600)
      incompatible_initial_state, incompatible_initial = current_config(incompatible)
      assert incompatible_initial["module_abi_pinned"] == 1, incompatible_initial
      assert incompatible_initial["config_module_paths"], incompatible_initial
      incompatible_initial_number = incompatible_initial["number"]
      incompatible_initial_hash = incompatible_initial["manifest_hash"]
      incompatible_attestation = generation_attestation(
          incompatible, incompatible_initial_number
      )
      release = incompatible_attestation["inputs"]["config_modules"]["release"]
      assert release["registry"] == "sysreg", release
      assert release["release_tag"] == "1.0.0", release
      assert release["tag_signer_key"], release
      assert release["realization"].startswith("sha256:"), release
      assert_live(incompatible, "axis-incompatible", "incompatible")

      # Image staging is image-only: neither host has re-evaluated before the
      # ABI-2 substrate is actually running.
      staged_target_config, target_candidate = stage_abi2(target)
      staged_incompatible_config, incompatible_candidate = stage_abi2(incompatible)

      # The positive host boots the staged image, then first-boot production
      # units re-evaluate and activate against the ABI-2 base library.
      target.reboot(timeout=600)
      target.wait_until_succeeds(
          "systemctl is-active --quiet aos-image-boot-commit.service", timeout=420
      )
      target.succeed("systemctl is-active --quiet aos-config.target")
      booted_images = image_state(target)
      assert booted_images["running"] == target_candidate, booted_images
      assert booted_images["default"] == target_candidate, booted_images
      assert booted_images.get("pending") is None, booted_images
      rebound_state, rebound = current_config(target)
      assert rebound["number"] != staged_target_config["current"], rebound_state
      assert rebound["image_gen_parent"] == target_candidate, rebound
      assert rebound["module_abi_pinned"] == 2, rebound
      assert_live(target, "axis-one", "one")

      # Both the source generation's ABI-1 base library and its exact source
      # inputs remain locally rooted after the A/B substrate switch.
      target.succeed(f"test -e {second['base_lib_ref']}")
      target.succeed(f"test -e {second['host_nix_ref']}")
      target.succeed(f"test -e {second['facts_ref']}")
      for module_path in second["config_module_paths"]:
          target.succeed(f"test -e {module_path}")

      # Rolling an ABI-1 generation forward while ABI 2 runs must evaluate the
      # exact retained host/facts/module inputs and create an ABI-2 child. It is
      # not legal to replay the old manifest or move the pointer to the old gen.
      boot_before_cross = target.succeed(
          "cat /proc/sys/kernel/random/boot_id"
      ).strip()
      cross_output = target.succeed(
          f"{APM} rollback --system --generation {second['number']} 2>&1",
          timeout=300,
      )
      assert "Re-evaluated generation" in cross_output, cross_output
      cross_state, cross = current_config(target)
      assert cross["number"] not in (initial["number"], second["number"]), cross_state
      assert cross["image_gen_parent"] == target_candidate, cross
      assert cross["module_abi_pinned"] == 2, cross
      assert cross["host_nix_ref"] == second["host_nix_ref"], (cross, second)
      assert cross["facts_ref"] == second["facts_ref"], (cross, second)
      assert cross["config_module_paths"] == second["config_module_paths"], (cross, second)
      running_image = next(
          generation for generation in booted_images["generations"]
          if generation["number"] == booted_images["running"]
      )
      assert cross["base_lib_ref"] == running_image["evaluator_ref"], (
          cross,
          running_image,
      )
      assert cross["base_lib_ref"] != second["base_lib_ref"], (cross, second)
      assert target.succeed(
          "cat /proc/sys/kernel/random/boot_id"
      ).strip() == boot_before_cross
      assert image_state(target) == booted_images
      assert_live(target, "axis-two", "two")

      # The second host carries a genuine ABI-1-only package config module.
      # Its ABI-2 first-boot evaluation fails before manifest publication and
      # activation; the old pointer and live overlay remain intact and the host
      # stays reachable for repair. The pending image is deliberately unblessed.
      incompatible.reboot(timeout=600)
      incompatible.wait_until_succeeds(
          "systemctl is-active --quiet multi-user.target", timeout=420
      )
      incompatible.wait_until_succeeds(
          "systemctl is-failed --quiet aos-eval.service", timeout=180
      )
      failed_output = incompatible.succeed(
          "journalctl -b -u aos-eval.service --no-pager"
      )
      assert "module ABI" in failed_output, failed_output
      assert "rfc0011-abi1-config" in failed_output, failed_output
      after_failure = config_state(incompatible)
      assert after_failure == staged_incompatible_config, after_failure
      failed_current = config_generation(
          after_failure, incompatible_initial_number
      )
      assert failed_current["manifest_hash"] == incompatible_initial_hash
      assert_live(incompatible, "axis-incompatible", "incompatible")
      failed_images = image_state(incompatible)
      assert failed_images["running"] == incompatible_candidate, failed_images
      assert failed_images["pending"] == incompatible_candidate, failed_images
      incompatible.succeed(
          "systemctl show -p ActiveState --value "
          "aos-image-boot-commit.service | grep -Fx inactive"
      )
    '';
}
