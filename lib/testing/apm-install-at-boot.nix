##! lib/testing/apm-install-at-boot.nix — baked apm install-at-boot intent check.
##!
##! RFC-0011: the desired-packages list (`/etc/aos/packages.d/desired.toml`) and
##! the apm registries are baked straight into the read-only image `/etc` when
##! `aos.apm.installAtBoot.enable` is set (modules/base/apm.nix and
##! modules/base/apm-registries.nix). The booting system carries the intent
##! directly — there is no Ignition stage to author it at first boot — so the
##! test enables installAtBoot on the system under test and asserts the baked
##! files are present and `aos-install-packages.service` reconciles cleanly.
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
      vm.wait_for_unit("aos-install-packages.service", timeout=120)

      desired = vm.succeed("cat /etc/aos/packages.d/desired.toml")
      assert "packages = []" in desired, desired
      vm.succeed("test \"$(stat -c %a /etc/aos/packages.d/desired.toml)\" = 600")

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
