##! Portable kernel policy shared by image evaluation and profile replay.
{lib, ...}: {
  imports = [./kernel-effects.nix ./kernel-packages.nix];
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

    ## Kernel modules to load at boot.
    modules = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = ''
        Kernel modules loaded and observed through the native kmod provider.
        Example: ["br_netfilter" "overlay"].
      '';
    };
  };
  config.aos.kernel = {
    sysctl = lib.mkDefault {
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
  };
}
