##! lib/testing/package-test-http-server.nix - Exposed test-http-server VM check.
{
  pkgs,
  lib,
  mkSystem,
  testing,
}: let
  storePathHash = path:
    builtins.elemAt (lib.splitString "-" (baseNameOf (builtins.toString path))) 0;
  packageHash = storePathHash pkgs.test-http-server;
  exposeHash = storePathHash pkgs.test-http-server.expose;
  target = pkgs.test-http-server.expose.passthru.manifest.expose.target;
  inertPackageHash = storePathHash pkgs.expose-smoke;
  inertExposeHash = storePathHash pkgs.expose-smoke.expose;
  inertTarget = pkgs.expose-smoke.expose.passthru.manifest.expose.target;

  testSystem = mkSystem {
    modules = [
      ../../systems/server.nix
      {
        aos.packages.expose-smoke = {
          package = pkgs.expose-smoke;
          bundle = true;
          preset = false;
        };
        aos.packages.test-http-server = {
          package = pkgs.test-http-server;
          bundle = true;
          preset = true;
        };
        # The test probes the served port with bare `curl`; image slimming
        # dropped it from the server PATH (modules/profiles/server.nix).
        environment.systemPackages = [pkgs.curl];
      }
    ];
  };
in
  testing.mkVMTest {
    name = "package-test-http-server";
    system = testSystem;
    timeout = 300;
    testScript = ''
      vm.wait_for_unit("aos-seed-baked-packages.service", timeout=120)
      vm.wait_for_unit("aos-preset.service", timeout=120)

      vm.succeed("test -L /var/lib/profiles/system-packages/current")
      vm.succeed("${pkgs.jq}/bin/jq -e '.current_generation == 1 and .next_generation == 2' /var/lib/profiles/system-packages/state.json")
      vm.succeed("test -L /var/lib/profiles/system-packages/gen-1/usr/${packageHash}")
      vm.succeed("test -L /var/lib/profiles/system-packages/gen-1/expose/${exposeHash}")
      vm.fail("test -e /var/lib/profiles/system-packages/gen-1/usr/${inertPackageHash}")
      vm.fail("test -e /var/lib/profiles/system-packages/gen-1/expose/${inertExposeHash}")
      vm.succeed("test -f /var/lib/profiles/system-packages/meta/${packageHash}.json")
      vm.succeed("${pkgs.jq}/bin/jq -e '.apm.name == \"test-http-server\" and .apm.expose.target == \"${target}\"' /var/lib/profiles/system-packages/meta/${packageHash}.json")
      vm.succeed("test -e ${pkgs.expose-smoke}")
      vm.succeed("test -e ${pkgs.expose-smoke.expose}")

      vm.succeed("test -f /usr/lib/systemd/system-preset/50-aos-image-packages.preset")
      vm.succeed("grep -qx 'enable ${target}' /usr/lib/systemd/system-preset/50-aos-image-packages.preset")
      vm.fail("grep -qx 'enable ${inertTarget}' /usr/lib/systemd/system-preset/50-aos-image-packages.preset")
      vm.succeed("grep -qx 'enable ${target}' /etc/systemd/system-preset/30-aos-apm.preset")
      vm.fail("grep -qx 'enable ${inertTarget}' /etc/systemd/system-preset/30-aos-apm.preset")
      vm.succeed("test -L /etc/systemd/system.attached/${target}")
      vm.succeed("test -L /etc/systemd/system.attached/test-http-server.socket")
      vm.succeed("test -L /etc/systemd/system.attached/test-http-server.service")
      vm.fail("test -e /etc/systemd/system.attached/${inertTarget}")

      vm.succeed("systemctl is-enabled --quiet ${target}")
      vm.succeed("systemctl is-active --quiet ${target}")
      vm.succeed("systemctl is-active --quiet test-http-server.socket")
      vm.succeed("test \"$(systemctl is-active test-http-server.service || true)\" = inactive")

      assert "Directory listing" in vm.succeed(
          "curl -sf --max-time 10 http://127.0.0.1:8000/"
      )
      vm.succeed("systemctl is-active --quiet test-http-server.service")
      assert "yes" in vm.succeed(
          "systemctl show -p PrivateNetwork --value test-http-server.service"
      )
      assert "${pkgs.test-http-server}" in vm.succeed(
          "systemctl show -p RootDirectory --value test-http-server.service"
      )

      vm.succeed("systemctl stop ${target}")
      vm.fail("curl -sf --max-time 2 http://127.0.0.1:8000/")
    '';
  }
