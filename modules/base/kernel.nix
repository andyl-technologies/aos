##! modules/base/kernel.nix — Kernel configuration module
##!
##! Configures kernel tunables, kernel module loading, and optional TCP BBR
##! congestion control through the native kernel providers.
##!
##! These are performance/functionality sysctls — security-focused sysctls
##! belong in modules/security/hardening.nix.
{
  pkgs,
  lib,
  ...
}: {
  options.aos.kernel = {
    ## Enable TCP BBR congestion control.
    bbr = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Enable TCP BBR congestion control. BBR achieves higher throughput and
        lower latency than CUBIC on lossy or high-BDP paths. When enabled,
        the tcp_bbr module is loaded and the default congestion control
        algorithm and queue discipline are converged through the native
        kernel providers.
      '';
    };

    ## Performance-oriented sysctl parameters.
    ##
    ## # See Also
    ## - `aos.security.hardening.sysctl` (security sysctls)
    sysctl = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      # Keep the base map in a normal definition below. An option default is
      # discarded wholesale as soon as any module contributes one key.
      default = {};
      description = ''
        Kernel parameters converged through the native kernel-tunable
        provider. Modules merge definitions per key; normal priority can
        replace one base key without discarding unrelated performance policy.
      '';
    };

    ## Kernel modules to load at boot.
    modules = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = ''
        Kernel modules loaded and observed through the native kmod provider.
        Example: ["br_netfilter" "overlay"].
      '';
    };

    modulePackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [];
      description = ''
        External kernel-module packages built against system.build.kernel.
        Their module trees are merged into the root filesystem and indexed
        together with the in-tree modules. Packages needed before switch-root
        must also be listed in aos.boot.initrd.modulePackages.
      '';
    };

    firmwarePackages = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [pkgs.firmware];
      description = ''
        Firmware packages exposed below /usr/lib/firmware in the runtime
        system. Package trees are merged in list order and duplicate paths are
        rejected at image-build time. Early-boot firmware is selected
        separately with aos.boot.initrd.firmwarePackages.
      '';
    };
  };

  config.aos.kernel.sysctl = lib.mkDefault {
    # This must be a mergeable definition rather than the option default so a
    # package policy adding one tunable retains every unrelated base key.
    # -- Network performance --
    "net.core.somaxconn" = "32768";
    "net.core.netdev_max_backlog" = "16384";
    # Socket buffer ceilings for high-throughput network services.
    "net.core.rmem_max" = "7500000";
    "net.core.wmem_max" = "7500000";

    # -- Virtual memory --
    "vm.swappiness" = "10";
    # Raise the mmap region ceiling so apps that map many regions
    # (modern games, large JVMs, container runtimes) don't hit
    # ENOMEM from the default 65530 limit.
    "vm.max_map_count" = "1048576";

    # -- Filesystem watches (IDEs, file sync, container runtimes) --
    "fs.inotify.max_user_instances" = "8192";
    "fs.inotify.max_user_watches" = "524288";

    # -- Process limits --
    "kernel.pid_max" = "4194304";
  };
}
