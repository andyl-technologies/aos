# Exercises the isolated grant-owner primitive; Storage handoff remains sealed.
{
  mkSystem,
  pkgs,
  ...
}: let
  gate = pkgs.aos-sandbox-kernel-export-owner;
  probeSource = ../sandbox/kernel-export-owner-probe.c;
  probe = pkgs.mkDerivation {
    pname = "aos-sandbox-kernel-export-owner-probe";
    version = "1";
    src = null;
    buildDeps = [pkgs.linux-headers pkgs.pkg-config];
    runtimeDeps = [gate pkgs.libbpf pkgs.openssl];
    propagatedDeps = [];
    disallowedReferences = [probeSource];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p $out/bin
          $CC -std=c17 -O2 -Wall -Wextra -Werror \
            -DAOS_KERNEL_EXPORT_OWNER_BIN='"'${gate}/bin/aos-sandbox-kernel-export-owner'"' \
            ${probeSource} -o $out/bin/kernel-export-owner-probe \
            $(pkg-config --cflags --libs libbpf openssl)
        '';
      }
    ];
    meta.license = "Apache-2.0";
  };
  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [gate probe pkgs.coreutils pkgs.util-linux];
    }
  ];
in {
  name = "sandbox-kernel-export-owner";
  timeout = 240;
  bootTimeout = 150;

  machines.vm = {inherit system;};

  # Exercise the owner on bpffs without pulling in the unrelated Network worker.
  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=150)
    vm.succeed("${pkgs.util-linux}/bin/mountpoint -q /sys/fs/bpf || ${pkgs.util-linux}/bin/mount -t bpf -o nosuid,nodev,noexec,mode=0700 bpf /sys/fs/bpf")
    vm.succeed("${pkgs.coreutils}/bin/mkdir -p /sys/fs/bpf/aos")
    vm.succeed("${pkgs.coreutils}/bin/chmod 0700 /sys/fs/bpf/aos")
    vm.succeed("${pkgs.coreutils}/bin/test \"$(${pkgs.coreutils}/bin/stat -f -c %t /sys/fs/bpf)\" = cafe4a11")
    vm.succeed("${pkgs.coreutils}/bin/mkdir -p /run/kernel-export-owner-test")
    vm.succeed("${pkgs.util-linux}/bin/mount -t tmpfs -o size=1m tmpfs /run/kernel-export-owner-test")
    vm.succeed("${pkgs.coreutils}/bin/printf 'protected bytes\\n' > /run/kernel-export-owner-test/data")
    vm.succeed("${probe}/bin/kernel-export-owner-probe /run/kernel-export-owner-test")
  '';
}
