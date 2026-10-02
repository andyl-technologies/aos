##! Portable kernel hardening and userspace core-dump restrictions.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.security.hardening;
in {
  options.aos.security.hardening = {
    ## Enable system hardening (sysctl, core dump restrictions).
    ##
    ## # See Also
    ## - `aos.security.hardening.sysctl`
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Enable system hardening. Applies security-focused sysctl settings
        and core dump restrictions. Enabled by default because AOS is a
        server OS where security is paramount.
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

        # -- Network hardening: IPv4 (all zone) --
        "net.ipv4.conf.all.rp_filter" = "1";
        "net.ipv4.conf.all.accept_redirects" = "0";
        "net.ipv4.conf.all.send_redirects" = "0";
        "net.ipv4.conf.all.accept_source_route" = "0";
        "net.ipv4.conf.all.log_martians" = "1";
        "net.ipv4.icmp_echo_ignore_broadcasts" = "1";
        "net.ipv4.tcp_syncookies" = "1";

        # -- Network hardening: IPv4 (default zone) --
        # The "all" zone only applies to interfaces that existed when
        # the sysctls were set; "default" is inherited by NICs brought
        # up later (hotplug, late DHCP, second-NIC hardware).
        "net.ipv4.conf.default.rp_filter" = "1";
        "net.ipv4.conf.default.accept_redirects" = "0";
        "net.ipv4.conf.default.accept_source_route" = "0";
        "net.ipv4.conf.default.log_martians" = "1";

        # Secure ICMP redirects: accept only from listed gateways.
        "net.ipv4.conf.all.secure_redirects" = "1";
        "net.ipv4.conf.default.secure_redirects" = "1";

        # Ignore malformed ICMP error responses (prevents log-spam DoS).
        "net.ipv4.icmp_ignore_bogus_error_responses" = "1";

        # -- Network hardening: IPv6 --
        "net.ipv6.conf.all.accept_redirects" = "0";
        "net.ipv6.conf.default.accept_redirects" = "0";
        "net.ipv6.conf.all.accept_source_route" = "0";
        "net.ipv6.conf.default.accept_source_route" = "0";

        # -- Filesystem protections --
        "fs.protected_hardlinks" = "1";
        "fs.protected_symlinks" = "1";
        "fs.suid_dumpable" = "0";
      };
      description = ''
        Kernel parameters converged through the native kernel-tunable
        provider. The defaults follow CIS benchmark recommendations for
        Linux servers.
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

  options.aos.security.hardening.files = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule {
      options.text = lib.mkOption {type = lib.types.lines;};
    });
    default = {};
    readOnly = true;
    description = "Core-dump restriction files derived from the native policy.";
  };
  options.aos.security.hardening.crashFiles = lib.mkOption {
    extensible = true;
    type = lib.types.attrsOf (lib.types.submodule {options.text = lib.mkOption {type = lib.types.lines;};});
    default = {};
    readOnly = true;
    description = "Crash collection files derived by the selected native backend.";
  };
  config = lib.mkIf cfg.enable {
    aos.kernel.sysctl = cfg.sysctl;
    aos.security.hardening.files = lib.mkIf (!cfg.coreDump.enable) {
      "security/limits.d/aos-hardening.conf".text = ''
        # Disable core dumps for all users.
        *  hard  core  0
        *  soft  core  0
      '';
    };
    aos.abilities.configuration.operations.file.effects.hardening-limits = lib.mkIf (!cfg.coreDump.enable) {
      input = {
        path = "/etc/security/limits.d/aos-hardening.conf";
        content = cfg.files."security/limits.d/aos-hardening.conf".text;
        mode = "0444";
      };
    };
  };
}
