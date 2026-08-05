# tests/fleet/rfc-0011-runtime-role.nix — host-selected role closure activation.
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
          preset = false;
        };
        aos.image.erofsCompressionLevel = 1;
      }
    ];
  };
in
  assert !roleImage.config.aos.roles.server.enable;
  assert !roleImage.config.aos.roles.edge.enable;
  assert !builtins.elem (builtins.toString pkgs.openssh) roleImage.config.system.build.configManifest.storePaths;
  assert !builtins.elem (builtins.toString pkgs.chrony) roleImage.config.system.build.configManifest.storePaths; {
    name = "rfc-0011-runtime-role";
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
            "systemctl is-active --quiet aos-graph-compile.service", timeout=300
        )
        runtime.wait_until_succeeds(
            "systemctl is-active --quiet aos-activate.service", timeout=300
        )
        runtime.wait_until_succeeds(
            "systemctl is-active --quiet sshd.service", timeout=120
        )
        runtime.wait_until_succeeds(
            "systemctl is-active --quiet chronyd.service", timeout=120
        )

        manifest = json.loads(runtime.succeed("cat /run/aos/manifest.json"))
        expected = {
            "${pkgs.openssh}": "sshd.service",
            "${pkgs.chrony}": "chronyd.service",
        }
        for store_path, unit in expected.items():
            assert store_path in manifest["storePaths"], (store_path, manifest["storePaths"])
            # The operator selects the role, while the authenticated base
            # module supplies these fixed package references. The closure is
            # therefore base-owned rather than reclassified as host content.
            assert manifest["ownership"]["storePaths"][store_path] == "@base", (
                store_path,
                manifest["ownership"]["storePaths"],
            )
            runtime.succeed(f"test -d {store_path}")
            unit_text = runtime.succeed(f"systemctl cat {unit}")
            assert store_path in unit_text, (unit, unit_text)

        # Role policy is live but did not mutate the golden-image storage
        # boundary or conscript feature payloads onto the login PATH.
        runtime.succeed("test \"$(sysctl -n vm.swappiness)\" = 10")
        runtime.succeed("test \"$(sysctl -n vm.vfs_cache_pressure)\" = 200")
        runtime.fail("command -v chronyd")
        runtime.fail("command -v sshd")
      '';
  }
