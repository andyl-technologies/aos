##! lib/testing/package-preset.nix — RFC-0001 preset enablement VM check.
{
  pkgs,
  mkSystem,
  testing,
}: let
  hostPreset = "enable aos-pkg-preset-enabled.target\n";
  testSystem = mkSystem {
    modules = [
      ../../systems/server.nix
      {
        systemd.units = {
          "aos-pkg-preset-enabled.target".text = ''
            [Unit]
            Description=RFC-0001 preset-enabled package target
            Wants=preset-enabled.service

            [Install]
            WantedBy=multi-user.target
          '';
          "preset-enabled.service".text = ''
            [Unit]
            Description=RFC-0001 preset-enabled package service
            PartOf=aos-pkg-preset-enabled.target

            [Service]
            Type=oneshot
            RemainAfterExit=yes
            ExecStart=${pkgs.bash}/bin/bash -c '${pkgs.coreutils}/bin/mkdir -p /var/lib/aos-preset-enabled && ${pkgs.coreutils}/bin/printf boot >> /var/lib/aos-preset-enabled/boots'
          '';
          "aos-pkg-preset-disabled.target".text = ''
            [Unit]
            Description=RFC-0001 preset-disabled package target
            Wants=preset-disabled.service

            [Install]
            WantedBy=multi-user.target
          '';
          "preset-disabled.service".text = ''
            [Unit]
            Description=RFC-0001 preset-disabled package service
            PartOf=aos-pkg-preset-disabled.target

            [Service]
            Type=oneshot
            RemainAfterExit=yes
            ExecStart=${pkgs.bash}/bin/bash -c '${pkgs.coreutils}/bin/mkdir -p /var/lib/aos-preset-disabled && ${pkgs.coreutils}/bin/printf boot >> /var/lib/aos-preset-disabled/boots'
          '';
        };
        # The per-host preset is baked directly into the image's /etc tree.
        environment.etc."systemd/system-preset/20-aos-host.preset".text = hostPreset;
      }
    ];
  };
in
  testing.mkVMTest {
    name = "package-preset";
    system = testSystem;
    timeout = 300;
    testScript = ''
      vm.wait_for_unit("aos-preset.service", timeout=120)
      vm.wait_until_succeeds("test -f /var/lib/aos-preset-enabled/boots", timeout=60)
      vm.succeed("test -f /usr/lib/systemd/system-preset/99-aos-default.preset")
      vm.succeed("grep -qx 'disable \\*' /usr/lib/systemd/system-preset/99-aos-default.preset")
      vm.succeed("test -f /etc/systemd/system-preset/20-aos-host.preset")
      vm.succeed("grep -qx 'enable aos-pkg-preset-enabled.target' /etc/systemd/system-preset/20-aos-host.preset")
      vm.succeed("test -f /etc/systemd/system/aos-pkg-preset-enabled.target")
      vm.succeed("test -f /etc/systemd/system/aos-pkg-preset-disabled.target")
      vm.succeed("systemctl is-enabled --quiet aos-pkg-preset-enabled.target")
      vm.fail("systemctl is-enabled --quiet aos-pkg-preset-disabled.target")
      vm.succeed("systemctl is-active --quiet aos-pkg-preset-enabled.target")
      vm.succeed("systemctl is-active --quiet preset-enabled.service")
      vm.fail("systemctl is-active --quiet aos-pkg-preset-disabled.target")
      vm.fail("systemctl is-active --quiet preset-disabled.service")
      vm.succeed("test ! -e /var/lib/aos-preset-disabled/boots")

      vm.reboot()
      vm.wait_for_unit("aos-preset.service", timeout=120)
      vm.wait_until_succeeds("test $(wc -c < /var/lib/aos-preset-enabled/boots) -ge 8", timeout=60)
      vm.succeed("test -f /etc/systemd/system-preset/20-aos-host.preset")
      vm.succeed("systemctl is-enabled --quiet aos-pkg-preset-enabled.target")
      vm.fail("systemctl is-enabled --quiet aos-pkg-preset-disabled.target")
      vm.succeed("systemctl is-active --quiet aos-pkg-preset-enabled.target")
      vm.fail("systemctl is-active --quiet preset-disabled.service")
      vm.succeed("test ! -e /var/lib/aos-preset-disabled/boots")
    '';
  }
