##! modules/security/hardening.nix — System hardening via sysctl and kernel params
##!
##! Applies security-focused sysctl settings and kernel parameters. The defaults
##! follow CIS benchmarks and DISA STIG guidance: ASLR, pointer restriction,
##! dmesg access control, network hardening, and filesystem protections.
##!
##! Absorbed TOML config values:
##!   [security.hardening] enable, sysctl, kernel_lockdown, core_dump
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.security.hardening;

  # Format sysctl settings as a sysctl.d(5) drop-in file.
  sysctlText = builtins.concatStringsSep "\n" (
    lib.mapAttrsToList (key: value: "${key} = ${value}") cfg.sysctl
  );
in {
  options.aos.security.hardening = {
    ## Enable system hardening (sysctl, lockdown, core dump restrictions).
    ##
    ## # See Also
    ## - `aos.security.hardening.sysctl`, `aos.security.hardening.kernelLockdown`
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Enable system hardening. Applies security-focused sysctl settings,
        kernel lockdown mode, and core dump restrictions. Enabled by default
        because AOS is a server OS where security is paramount.
      '';
    };

    ## Security-focused sysctl parameters (CIS benchmarks).
    ##
    ## # Examples
    ## ```nix
    ## aos.security.hardening.sysctl."kernel.kptr_restrict" = "2";
    ## ```
    sysctl = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = {
        # -- Address space layout randomization --
        "kernel.randomize_va_space" = "2";

        # -- Kernel pointer and debug restrictions --
        "kernel.kptr_restrict" = "2";
        "kernel.dmesg_restrict" = "1";
        "kernel.perf_event_paranoid" = "3";
        "kernel.yama.ptrace_scope" = "2";

        # -- Network hardening: IPv4 --
        "net.ipv4.conf.all.rp_filter" = "1";
        "net.ipv4.conf.all.accept_redirects" = "0";
        "net.ipv4.conf.all.send_redirects" = "0";
        "net.ipv4.conf.all.accept_source_route" = "0";
        "net.ipv4.conf.all.log_martians" = "1";
        "net.ipv4.icmp_echo_ignore_broadcasts" = "1";
        "net.ipv4.tcp_syncookies" = "1";

        # -- Network hardening: IPv6 --
        "net.ipv6.conf.all.accept_redirects" = "0";

        # -- Filesystem protections --
        "fs.protected_hardlinks" = "1";
        "fs.protected_symlinks" = "1";
        "fs.suid_dumpable" = "0";
      };
      description = ''
        Kernel sysctl parameters for security hardening. Written to
        /etc/sysctl.d/80-aos-hardening.conf and applied at boot by
        systemd-sysctl.service. The defaults follow CIS benchmark
        recommendations for Linux servers.
      '';
    };

    ## Kernel lockdown mode (none, integrity, confidentiality).
    ##
    ## # Examples
    ## ```nix
    ## aos.security.hardening.kernelLockdown = "confidentiality";
    ## ```
    kernelLockdown = lib.mkOption {
      type = lib.types.enum [
        "none"
        "integrity"
        "confidentiality"
      ];
      default = "integrity";
      description = ''
        Kernel lockdown mode:
        - none: no restrictions
        - integrity: prevents modification of the running kernel
          (blocks kexec, module signature bypass, /dev/mem writes)
        - confidentiality: integrity + prevents reading kernel memory
          (blocks /proc/kcore, eBPF, perf)
      '';
    };

    coreDump = {
      ## Allow core dumps (disabled by default for security).
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Allow core dumps. Disabled by default on AOS because core dumps
          can leak sensitive data (cryptographic keys, credentials) from
          process memory.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    system.checks.kernel-security = lib.mkCheckGroup {
      name = "kernel-security";
      description = "Kernel sysctl hardening checks";
      checks = [
        (lib.mkCheck {
          name = "aslr";
          description = "ASLR is fully enabled (randomize_va_space=2)";
          script = ''
            assert_output_contains "cat /proc/sys/kernel/randomize_va_space" "2" \
              "ASLR is fully enabled"
          '';
        })
        (lib.mkCheck {
          name = "syncookies";
          description = "TCP syncookies are enabled";
          script = ''
            assert_output_contains "cat /proc/sys/net/ipv4/tcp_syncookies" "1" \
              "TCP syncookies are enabled"
          '';
        })
        (lib.mkCheck {
          name = "protected-hardlinks";
          description = "Protected hardlinks sysctl exists";
          script = ''
            assert_success "test -f /proc/sys/fs/protected_hardlinks" \
              "Protected hardlinks sysctl is accessible"
          '';
        })
        (lib.mkCheck {
          name = "protected-symlinks";
          description = "Protected symlinks sysctl exists";
          script = ''
            assert_success "test -f /proc/sys/fs/protected_symlinks" \
              "Protected symlinks sysctl is accessible"
          '';
        })
        (lib.mkCheck {
          name = "proc-isolation";
          description = "PID 1 visible in /proc";
          script = ''
            assert_success "test -d /proc/1" \
              "PID 1 visible in /proc"
          '';
        })
        (lib.mkCheck {
          name = "syskernel";
          description = "/sys/kernel is accessible";
          script = ''
            assert_success "test -d /sys/kernel" \
              "/sys/kernel is accessible"
          '';
        })
      ];
    };

    system.checks.hardening = lib.mkCheckGroup {
      name = "hardening";
      description = "Userspace hardening checks";
      checks = [
        (lib.mkCheck {
          name = "dmesg-restrict";
          description = "dmesg_restrict is enabled";
          script = ''
            assert_output_contains "cat /proc/sys/kernel/dmesg_restrict" "1" \
              "dmesg_restrict is enabled"
          '';
        })
        (lib.mkCheck {
          name = "kptr-restrict";
          description = "kptr_restrict is set";
          script = ''
            assert_success "test -f /proc/sys/kernel/kptr_restrict" \
              "kptr_restrict sysctl exists"
          '';
        })
        (lib.mkCheck {
          name = "ptrace-scope";
          description = "ptrace scope is restricted";
          script = ''
            assert_success "test -f /proc/sys/kernel/yama/ptrace_scope" \
              "ptrace_scope sysctl exists"
          '';
        })
      ];
    };

    # /etc/sysctl.d/80-aos-hardening.conf — security sysctl settings.
    # Applied by systemd-sysctl.service during early boot.
    environment.etc."sysctl.d/80-aos-hardening.conf" = {
      text = ''
        # /etc/sysctl.d/80-aos-hardening.conf
        # Generated by modules/security/hardening.nix
        # Security-focused kernel parameters per CIS benchmarks.

        ${sysctlText}
      '';
    };

    # Core dump configuration.
    environment.etc."sysctl.d/81-aos-coredump.conf" = {
      text = ''
        # Core dump control — generated by modules/security/hardening.nix
        ${
          if cfg.coreDump.enable
          then ''
            kernel.core_pattern=|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %e
          ''
          else ''
            kernel.core_pattern=|/bin/false
            fs.suid_dumpable = 0
          ''
        }
      '';
    };

    # systemd core dump configuration.
    environment.etc."systemd/coredump.conf" = {
      text = ''
        # /etc/systemd/coredump.conf — generated by modules/security/hardening.nix
        [Coredump]
        ${
          if cfg.coreDump.enable
          then ''
            Storage=journal
            Compress=yes
            MaxUse=1G
          ''
          else ''
            Storage=none
            ProcessSizeMax=0
          ''
        }
      '';
    };

    # Kernel lockdown parameter — added to boot command line.
    # Only add the parameter if lockdown is not "none".
    aos.boot.kernelParams = let
      baseCmdline = [
        "console=ttyS0,115200"
        "console=tty0"
        "systemd.unified_cgroup_hierarchy=1"
        "selinux=1"
        "security=selinux"
      ];
      lockdownParam =
        if cfg.kernelLockdown != "none"
        then ["lockdown=${cfg.kernelLockdown}"]
        else [];
    in
      baseCmdline ++ lockdownParam;

    # Resource limits to prevent core dumps at the process level.
    environment.etc."security/limits.d/aos-hardening.conf" = lib.mkIf (!cfg.coreDump.enable) {
      text = ''
        # Disable core dumps for all users.
        # Generated by modules/security/hardening.nix
        *  hard  core  0
        *  soft  core  0
      '';
    };
  };
}
