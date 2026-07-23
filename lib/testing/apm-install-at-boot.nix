##! lib/testing/apm-install-at-boot.nix — apm install-at-boot intent check.
##!
##! `aos.apm.installAtBoot` bakes `desired.toml` + registry config straight into
##! the image /etc; `aos-install-baked-packages` reconciles it at
##! first boot. The system under test enables it directly.
{
  pkgs,
  mkSystem,
  testing,
}: let
  anchorKey = "example:Ed25519:QUJDREVGR0g=";
  testSystem = mkSystem {
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
    testScript = ''
      vm.wait_for_unit("aos-install-baked-packages.service", timeout=120)

      desired = vm.succeed("cat /etc/aos/packages.d/desired.toml")
      assert "packages = []" in desired, desired
      vm.succeed("test \"$(stat -c %a /etc/aos/packages.d/desired.toml)\" = 600")

      registry = vm.succeed("cat /etc/apm/registries.d/example.toml")
      assert 'name = "example"' in registry, registry
      assert 'url = "https://registry.example/aos"' in registry, registry
      assert 'public_key = "${anchorKey}"' in registry, registry

      keys = vm.succeed("cat /etc/apm/trusted-keys.d/example.pub")
      assert "${anchorKey}" in keys, keys

      vm.succeed("systemctl is-active --quiet aos-install-baked-packages.service")
      assert "success" in vm.succeed(
          "systemctl show -p Result --value aos-install-baked-packages.service"
      )
    '';
  }
