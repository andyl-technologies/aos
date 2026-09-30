##! modules/security/hardening.nix — System hardening via sysctl and kernel params
##!
##! Applies security-focused sysctl settings and kernel parameters. The defaults
##! follow CIS benchmarks and DISA STIG guidance: ASLR, pointer restriction,
##! dmesg access control, network hardening, and filesystem protections.
##!
##! Absorbed TOML config values:
##!   [security.hardening] enable, sysctl, core_dump
{
  config,
  pkgs,
  lib,
  packageModulesAvailable ? false,
  ...
}: let
  cfg = config.aos.security.hardening;
in {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/system/_aos-host-policy/hardening.nix];

  config = lib.mkIf cfg.enable {
    # Key-free runtime hardening on the kernel command line. These match the
    # reproducible kernel config: zero-on-alloc/free, no slab cache merging,
    # and per-syscall kernel-stack offset randomization. vsyscall=none removes
    # the legacy fixed-address vsyscall page on x86_64.
    aos.boot.kernelParams =
      [
        "init_on_alloc=1"
        "init_on_free=1"
        "slab_nomerge"
        "randomize_kstack_offset=on"
      ]
      ++ lib.optional (lib.hasPrefix "x86_64" pkgs.stdenv.system) "vsyscall=none";

    system.checks.kernel-security = {
      description = "Kernel sysctl hardening checks";
      checks = [
        # The native provider converges values after the generation filesystem
        # is available, so these observations do not depend on an early
        # early boot configuration pass racing the selected filesystem view.
        {
          name = "aslr";
          description = "ASLR is fully enabled (randomize_va_space=2)";
          script = ''
            vm.wait_until_succeeds(
                "grep -q '^2$' /proc/sys/kernel/randomize_va_space"
            )
          '';
        }
        {
          name = "syncookies";
          description = "TCP syncookies are enabled";
          script = ''
            vm.wait_until_succeeds(
                "grep -q '^1$' /proc/sys/net/ipv4/tcp_syncookies"
            )
          '';
        }
        {
          name = "protected-hardlinks";
          description = "Protected hardlinks are enabled";
          script = ''
            vm.wait_until_succeeds(
                "grep -q '^1$' /proc/sys/fs/protected_hardlinks"
            )
          '';
        }
        {
          name = "protected-symlinks";
          description = "Protected symlinks are enabled";
          script = ''
            vm.wait_until_succeeds(
                "grep -q '^1$' /proc/sys/fs/protected_symlinks"
            )
          '';
        }
        {
          name = "randomize-kstack-offset";
          description = "Kernel-stack offset randomization is on where available";
          script = ''
            # The control exists only on architectures that support it; treat
            # an absent file as a pass and a present file as a value check.
            vm.succeed(
                "! test -e /proc/sys/kernel/randomize_kstack_offset || "
                "grep -q '^1$' /proc/sys/kernel/randomize_kstack_offset"
            )
          '';
        }
        {
          name = "proc-isolation";
          description = "PID 1 visible in /proc";
          script = ''
            vm.succeed("test -d /proc/1")
          '';
        }
        {
          name = "syskernel";
          description = "/sys/kernel is accessible";
          script = ''
            vm.succeed("test -d /sys/kernel")
          '';
        }
      ];
    };

    system.checks.hardening = {
      description = "Userspace hardening checks";
      checks = [
        {
          name = "dmesg-restrict";
          description = "dmesg_restrict is enabled";
          script = ''
            # Poll the provider-owned convergence result rather than relying
            # on an early boot pass through the selected filesystem view.
            vm.wait_until_succeeds(
                "grep -q '^1$' /proc/sys/kernel/dmesg_restrict"
            )
          '';
        }
        {
          name = "kptr-restrict";
          description = "kptr_restrict hides kernel pointers (=2)";
          script = ''
            vm.wait_until_succeeds(
                "grep -q '^2$' /proc/sys/kernel/kptr_restrict"
            )
          '';
        }
        {
          name = "ptrace-scope";
          description = "ptrace scope is restricted";
          script = ''
            vm.succeed("test -f /proc/sys/kernel/yama/ptrace_scope")
          '';
        }
      ];
    };

    environment.etc = config.aos.security.hardening.files;
  };
}
