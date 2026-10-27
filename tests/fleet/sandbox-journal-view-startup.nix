# Qualifies the fixed idmapped views independently of owner credentials.
{
  lib,
  pkgs,
  systems,
  ...
} @ args: let
  base = import ./sandbox-source-startup.nix args;
in
  base
  // {
    name = "sandbox-journal-view-startup";
    timeout = 1800;
    testScript =
      builtins.readFile ./_sandbox-startup-diagnostics.py
      + builtins.readFile ./_sandbox-cold-boot.py
      + ''
        import shlex

        units = (
            "aos-sandbox-cache-journal-view.service",
            "aos-sandbox-source-signer-view.service",
        )
        python = "${pkgs.python3}/bin/python3"
        check = r"""
        import pathlib

        pairs = (
            ('/var/lib/aos/sandbox/cache-residency-journals', '/run/aos/sandbox-policy-cache-journals'),
            ('/var/lib/aos/sandboxd', '/run/aos/sandbox-root-controller'),
            ('/var/lib/aos/sandboxd/broker-session/storage', '/run/aos/sandbox-root-storage-session'),
            ('/var/lib/aos/sandboxd/broker-session/host', '/run/aos/sandbox-root-host-session'),
            ('/var/lib/aos/sandboxd/broker-session/mount', '/run/aos/sandbox-root-mount-session'),
            ('/var/lib/aos/sandboxd/broker-session/network', '/run/aos/sandbox-root-network-session'),
            ('/var/lib/aos/sandbox/source-domains', '/run/aos/sandbox-root-source'),
            ('/var/lib/aos/sandboxd/cache-residency-authority', '/run/aos/sandbox-root-cache-bootstrap'),
            ('/var/lib/aos/sandbox/cache-residency-objects', '/run/aos/sandbox-root-cache-objects'),
            ('/var/lib/aos/sandbox/source-domains', '/run/aos/sandbox-source-signer-journal'),
        )
        mounts = {fields[4]: fields for fields in
                  (line.split() for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines())}
        # The immutable fixed preparers check both owners, modes and inode
        # equality before returning success. PID 1 cannot traverse either
        # protected view parent; independently check the public kernel mount
        # records here without giving the test observer protected path access.
        for source, view in pairs:
            assert mounts[view][2] == mounts['/var'][2], mounts[view]
            assert mounts[view][3] == source.removeprefix('/var'), mounts[view]
            assert {'ro', 'nosuid', 'nodev', 'noexec', 'nosymfollow'} <= set(mounts[view][5].split(',')), mounts[view]
        print('FIXED_JOURNAL_VIEWS_VERIFIED')
        """

        def verify_views():
            # Qualify the actual fixed view units at their own frontier. Full
            # native activation and boot completion have a separate startup
            # test; they are not prerequisites of these completed preparers.
            vm.succeed("test $(cat /sys/fs/selinux/enforce) = 1")
            for unit in units:
                vm.wait_for_unit(unit, timeout=120)
                assert vm.succeed(f"systemctl show {unit} --property=ExecMainStatus --value").strip() == "0"
            output = vm.succeed(f"{python} -c {shlex.quote(check)}")
            assert "FIXED_JOURNAL_VIEWS_VERIFIED" in output, output

        with startup_diagnostics(vm, *units):
            verify_views()
            vm.succeed("systemctl stop " + " ".join(reversed(units)))
            vm.succeed("systemctl start " + units[-1])
            verify_views()

            power_cycle_and_require_new_boot(vm)
            verify_views()
      '';
  }
