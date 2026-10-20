# Host-selected role closure activation.
#
# The production server image carries boot/storage capability only. This gate
# enables the edge runtime role exclusively through authenticated host.nix and
# proves that the role's absolute unit references are pinned, realized, and
# usable even though chrony and OpenSSH are intentionally absent from the
# interactive system package set.
{
  pkgs,
  systems,
  ...
}: let
  roleImage = systems.server.extendModules {
    modules = [
      {
        # Image-boot fleet machines need the transport agent as a bundled
        # package. This is a test-harness capability, not runtime role policy.
        aos.packages.aos-test-agent = {
          package = pkgs.aos-test-agent;
          bundle = true;
        };
        # This production-profile image deliberately carries the fleet control
        # agent as test infrastructure. Keep the runtime-closure audit strict
        # for every other artifact while admitting that explicit fixture.
        aos.image.allowTestArtifacts = true;
        # Admit role modules without enabling their services in the golden image.
        aos.packages.chrony = {
          package = pkgs.chrony;
          enable = true;
        };
        aos.packages.openssh = {
          package = pkgs.openssh;
          enable = true;
        };
        aos.packages.audit = {
          package = pkgs.audit;
          enable = true;
        };
        aos.packages.aos-network-ruleset-provider = {
          package = pkgs.aos-network-ruleset-provider;
          enable = true;
        };
        aos.packages.nftables = {
          package = pkgs.nftables;
          enable = true;
        };
        aos.image.hostConfigClosures = [pkgs.chrony pkgs.openssh pkgs.audit pkgs.nftables pkgs.aos-network-ruleset-provider];
        # Host-selectable OpenSSH/chrony closures plus the control agent make
        # this acceptance image larger than the production golden-image gate.
        # The measured fixture root occupies 666 MiB; retain the separate
        # production publication contract.
        aos.image.budgets = {
          maxRootMiB = 704;
          maxRuntimeClosureMiB = 3072;
          maxDevelopmentPayloadMiB = 80;
        };
        aos.image.erofsCompressionLevel = 1;
      }
    ];
  };
in
  assert !roleImage.config.aos.roles.server.enable;
  assert !roleImage.config.aos.roles.edge.enable;
  assert !roleImage.config.aos.services.ssh.enable;
  assert !roleImage.config.aos.services.chrony.enable;
  assert builtins.elem pkgs.openssh roleImage.config.aos.image.hostConfigClosures;
  assert builtins.elem pkgs.chrony roleImage.config.aos.image.hostConfigClosures; {
    name = "runtime-config-role";
    timeout = 1200;

    machines.runtime = {
      system = roleImage;
      bootMode = "image";
      imageDiskMiB = 16384;
      memoryMiB = 4096;
      packages = ["aos-test-agent"];
      metadata."host.nix" = ''
        {
          aos.provisioning.storage.partitions.var.sizeMin = "2G";
          aos.roles.edge.enable = true;
        }
      '';
    };

    testScript =
      # python
      ''
        import json


        runtime.wait_until_succeeds(
            "systemctl is-active --quiet aos-activate.service", timeout=300
        )
        runtime.wait_until_succeeds(
            "systemctl is-active --quiet sshd.service", timeout=120
        )
        runtime.wait_until_succeeds(
            "systemctl is-active --quiet chronyd.service", timeout=120
        )
        runtime.succeed("test -d /var/empty")
        runtime.succeed("test -d /var/lib/chrony")
        runtime.succeed("test -d /var/log/chrony")
        runtime.succeed("test -d /run/chrony")

        RUNTIME = "${pkgs.aos.packageRuntime}/bin/aos-package-runtime"
        profile = "/var/lib/profiles/system"
        generation = json.loads(runtime.succeed(
            f"{RUNTIME} deployment-current --profile {profile} --committed-during-recovery"
        ))["generation"]
        descriptor = json.loads(runtime.succeed(f"cat {profile}/gen-{generation}/evaluation.json"))
        marker = json.loads(runtime.succeed(f"cat {profile}/gen-{generation}/native-deployment.json"))
        assert descriptor["scope"] == ["profile", "system"], descriptor
        assert descriptor["runtimeConfiguration"], descriptor
        roots = {artifact["path"] for artifact in descriptor["packages"]["artifacts"]}
        for module in descriptor["packages"]["modules"]:
            roots.add(module["artifacts"]["package"]["path"])
            roots.update(artifact["path"] for artifact in module["artifacts"]["dependencies"].values())
        expected = {"${pkgs.openssh}": "sshd.service", "${pkgs.chrony}": "chronyd.service"}
        for store_path, unit in expected.items():
            assert store_path in roots, (store_path, roots)
            runtime.succeed(f"test -d {store_path}")
            assert store_path in runtime.succeed(f"systemctl cat {unit}"), unit

        # Role policy is live but did not mutate the golden-image storage
        # boundary or conscript feature payloads onto the login PATH.
        runtime.succeed("read value < /proc/sys/vm/swappiness; test \"$value\" = 10")
        runtime.succeed("read value < /proc/sys/vm/vfs_cache_pressure; test \"$value\" = 200")
        runtime.fail("command -v chronyd")
        runtime.fail("command -v sshd")

        # A malformed tmpfiles rule fails its native prerequisite before the
        # new daemon starts. The previous committed role remains authoritative.
        runtime.succeed("mkdir -p /run/aos-tmpfiles-fault")
        runtime.succeed(r"""
            cat > /run/aos-tmpfiles-fault/host.nix <<'MODULE'
            { config, ... }: {
              aos.roles.edge.enable = true;
              aos.abilities.configuration.operations.file.effects.tmpfiles-fault.input = {
                path = "/etc/tmpfiles.d/aos-test-invalid.conf";
                content = "d /run/aos-invalid-mode not-a-mode root root -\n";
                mode = "0644";
              };
              aos.services.aos-tmpfiles-fault-canary = {
                enable = true;
                activationAfter = [ config.aos.abilities.configuration.operations.file.effects.tmpfiles-fault.outputs.resource ];
                lifecycle = {
                  description = "Reject invalid ownership before starting a new daemon";
                  execution_model = "oneshot";
                  environment_files = [];
                  condition = [];
                  pre_start = [{
                    executable = {
                      path = "${pkgs.systemd}/bin/systemd-tmpfiles";
                      arguments = [ "--create" "/etc/tmpfiles.d/aos-test-invalid.conf" ];
                    };
                    ignore_failure = false;
                  }];
                  start = [{ executable = { path = "${pkgs.coreutils}/bin/touch"; arguments = [ "/run/aos-tmpfiles-fault-canary" ]; }; ignore_failure = false; }];
                  post_start = [];
                  stop = [];
                  post_stop = [];
                  restart = "never";
                  restart_delay_millis = 0;
                  configuration_change_action = "restart";
                  remain_after_exit = true;
                  start_timeout_millis = 30000;
                  stop_timeout_millis = 30000;
                };
              };
            }
            MODULE
        """)
        status, stdout, stderr = runtime.execute(
            "${pkgs.aos.apm}/bin/apm switch --worktree /run/aos-tmpfiles-fault",
            timeout=600,
        )
        assert status != 0, (status, stdout, stderr)
        current = json.loads(runtime.succeed(
            f"{RUNTIME} deployment-current --profile {profile} --committed-during-recovery"
        ))["generation"]
        assert current == generation, (current, generation)
        assert json.loads(runtime.succeed(f"cat {profile}/gen-{current}/native-deployment.json")) == marker
        runtime.fail("test -e /run/aos-tmpfiles-fault-canary")
        runtime.fail("systemctl is-active --quiet aos-tmpfiles-fault-canary.service")
        runtime.succeed("systemctl is-active --quiet sshd.service")
        runtime.succeed("systemctl is-active --quiet chronyd.service")
      '';
  }
