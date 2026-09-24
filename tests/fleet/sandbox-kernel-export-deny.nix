# Exercises the separate deny-only BPF-LSM artifact on a live unique mount ID.
{
  mkSystem,
  pkgs,
  ...
}: let
  gate = pkgs.aos-sandbox-kernel-export-deny;
  probeSource = ../sandbox/kernel-export-deny-probe.c;
  probe = pkgs.mkDerivation {
    pname = "aos-sandbox-kernel-export-deny-probe";
    version = "1";
    src = null;
    buildDeps = [pkgs.linux-headers];
    runtimeDeps = [gate];
    propagatedDeps = [];
    disallowedReferences = [probeSource];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p $out/bin
          $CC -std=c17 -O2 -Wall -Wextra -Werror \
            -DAOS_KERNEL_EXPORT_DENY_LOADER='"${gate}/bin/aos-sandbox-kernel-export-deny"' \
            ${probeSource} -o $out/bin/kernel-export-deny-probe
        '';
      }
    ];
    meta.license = "Apache-2.0";
  };
  system = mkSystem [
    ../../systems/server-test.nix
    {
      aos.sandbox.networkWorker.enable = true;
      environment.systemPackages = [gate probe pkgs.coreutils pkgs.util-linux];
    }
  ];
in {
  name = "sandbox-kernel-export-deny";
  timeout = 240;
  bootTimeout = 150;

  machines.vm = {inherit system;};

  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=150)
    vm.wait_for_unit("aos-bpffs-mount.service", timeout=30)
    vm.succeed("${pkgs.coreutils}/bin/mkdir -p /run/kernel-export-deny-test")
    vm.succeed("${pkgs.util-linux}/bin/mount -t tmpfs -o size=1m tmpfs /run/kernel-export-deny-test")
    vm.succeed("${pkgs.coreutils}/bin/printf 'protected bytes\\n' > /run/kernel-export-deny-test/data")
    vm.succeed("${probe}/bin/kernel-export-deny-probe /run/kernel-export-deny-test/data")
  '';
}
