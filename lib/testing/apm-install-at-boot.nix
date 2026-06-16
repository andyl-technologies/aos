##! lib/testing/apm-install-at-boot.nix — Ignition-authored apm intent check.
{
  pkgs,
  mkSystem,
  testing,
}: let
  anchorKey = "example:Ed25519:QUJDREVGR0g=";
  testSystem = mkSystem {
    modules = [
      ../../systems/server.nix
    ];
  };
  metadataSystem = mkSystem {
    modules = [
      ../../systems/server.nix
      {
        aos.apm.registries.example = {
          url = "https://registry.example/aos";
          trustKeys = [anchorKey];
        };
        aos.apm.installAtBoot = {
          enable = true;
          packages = [];
        };
      }
    ];
  };
in
  testing.mkVMTest {
    name = "apm-install-at-boot";
    system = testSystem;
    timeout = 300;
    instanceMetadata.config = metadataSystem.config.aos.apm.installAtBoot.ignitionConfig;
    testScript = ''
      vm.wait_for_unit("aos-install-packages.service", timeout=120)

      desired = vm.succeed("cat /etc/aos/packages.d/desired.toml")
      assert "packages = []" in desired, desired

      registry = vm.succeed("cat /etc/apm/registries.d/example.toml")
      assert 'name = "example"' in registry, registry
      assert 'url = "https://registry.example/aos"' in registry, registry
      assert 'public_key = "${anchorKey}"' in registry, registry

      keys = vm.succeed("cat /etc/apm/trusted-keys.d/example.pub")
      assert "${anchorKey}" in keys, keys

      vm.succeed("systemctl is-active --quiet aos-install-packages.service")
      assert "success" in vm.succeed(
          "systemctl show -p Result --value aos-install-packages.service"
      )
    '';
  }
