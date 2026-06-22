##! modules/security/selinux.nix — SELinux configuration module
##!
##! Configures SELinux mode, policy, and generates the config file, policy
##! loading service, and optional auto-relabeling service. SELinux is a
##! mandatory access control (MAC) system that confines processes to the
##! minimum privileges they need.
##!
##! Absorbed TOML config values:
##!   [security.selinux] enable, mode, policy, autorelabel
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.security.selinux;
  policyName = cfg.policy;
  refpolicy = pkgs.refpolicy;
  semodule = "${pkgs.policycoreutils}/sbin/semodule";
  loadPolicy = "${pkgs.policycoreutils}/sbin/load_policy";
  setenforce = "${pkgs.libselinux}/sbin/setenforce";
  selinuxPolicyLoad = pkgs.writeShellScriptBin "aos-selinux-load-policy" ''
    set -eu

    policy=${lib.escapeShellArg policyName}
    module_dir=${lib.escapeShellArg "${refpolicy}/usr/share/selinux/refpolicy"}
    store_root=/var/lib/selinux
    policy_dir="/etc/selinux/$policy/policy"
    marker="$store_root/$policy/.aos-refpolicy-source"
    desired=${lib.escapeShellArg (builtins.toString refpolicy)}

    ${pkgs.coreutils}/bin/mkdir -p \
      "$store_root" \
      "/etc/selinux/$policy" \
      "$policy_dir"

    policy_file_exists() {
      for policy_file in "$policy_dir"/policy.*; do
        [ -f "$policy_file" ] && return 0
      done
      return 1
    }

    if [ ! -f "$marker" ] || ! ${pkgs.grep}/bin/grep -qx "$desired" "$marker" || ! policy_file_exists; then
      set -- -s "$policy" -S "$store_root" -i "$module_dir/base.pp"
      for module in "$module_dir"/*.pp; do
        case "$(${pkgs.coreutils}/bin/basename "$module")" in
          base.pp)
            ;;
          *)
            set -- "$@" -i "$module"
            ;;
        esac
      done

      ${semodule} "$@"
      if ! policy_file_exists; then
        echo "SELinux policy install did not create $policy_dir/policy.*" >&2
        exit 1
      fi
      ${pkgs.coreutils}/bin/mkdir -p "$(${pkgs.coreutils}/bin/dirname "$marker")"
      ${pkgs.coreutils}/bin/printf '%s\n' "$desired" > "$marker"
    else
      ${loadPolicy} -qi
    fi

    case ${lib.escapeShellArg cfg.mode} in
      enforcing)
        ${setenforce} 1
        ;;
      permissive)
        ${setenforce} 0
        ;;
      disabled)
        ;;
      *)
        echo "unsupported SELinux mode: ${cfg.mode}" >&2
        exit 1
        ;;
    esac
  '';
in {
  options.aos.security.selinux = {
    ## Enable SELinux mandatory access control.
    ##
    ## # Examples
    ## ```nix
    ## aos.security.selinux.enable = true;
    ## ```
    ##
    ## # See Also
    ## - `aos.security.selinux.mode`, `aos.security.selinux.policy`
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable SELinux mandatory access control. When enabled, the kernel
        enforces the configured policy on all processes. Requires kernel
        support (selinux=1 security=selinux in boot parameters).
      '';
    };

    ## SELinux operating mode (enforcing, permissive, disabled).
    ##
    ## # Examples
    ## ```nix
    ## aos.security.selinux.mode = "permissive";
    ## ```
    mode = lib.mkOption {
      type = lib.types.enum [
        "enforcing"
        "permissive"
        "disabled"
      ];
      default = "enforcing";
      description = ''
        SELinux operating mode:
        - enforcing: denies access and logs violations
        - permissive: logs violations but does not deny access
        - disabled: SELinux is completely disabled
      '';
    };

    ## SELinux policy to load ("targeted" or "strict").
    policy = lib.mkOption {
      type = lib.types.str;
      default = "refpolicy";
      description = ''
        SELinux policy store name to load. The default matches the AOS-built
        Reference Policy package.
      '';
    };

    ## Automatically relabel the filesystem on first boot or policy change.
    autorelabel = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Automatically relabel the filesystem on first boot or when the
        /.autorelabel file exists. Required after policy changes to ensure
        all files have correct security contexts.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    system.checks.selinux = {
      description = "SELinux checks";
      checks = [
        {
          name = "selinuxfs";
          description = "/sys/fs/selinux is present";
          script = ''
            vm.succeed("test -d /sys/fs/selinux")
          '';
        }
        {
          name = "enforce-file";
          description = "SELinux enforce file exists";
          script = ''
            vm.succeed("test -f /sys/fs/selinux/enforce")
          '';
        }
      ];
    };

    environment.systemPackages = [
      pkgs.policycoreutils
      pkgs.libselinux
      pkgs.libsemanage
      pkgs.semodule-utils
    ];

    environment.etc = {
      # /etc/selinux/config — main SELinux configuration file.
      # Read by libselinux at boot and by selinux-policy-load.service.
      "selinux/config" = {
        text = ''
          # /etc/selinux/config — generated by modules/security/selinux.nix
          # SELinux mode: enforcing, permissive, or disabled
          SELINUX=${cfg.mode}

          # SELinux policy name
          SELINUXTYPE=${cfg.policy}
        '';
      };

      "selinux/semanage.conf".source = "${pkgs.libsemanage}/etc/selinux/semanage.conf";
      "selinux/${policyName}/contexts".source = "${refpolicy}/etc/selinux/refpolicy/contexts";
    };

    systemd.services = {
      # Load the SELinux policy early in boot.
      # This must run before any confined services start.
      "selinux-policy-load" = {
        description = "Load SELinux Policy";
        wantedBy = ["sysinit.target"];
        before = [
          "sysinit.target"
          "systemd-tmpfiles-setup.service"
        ];
        after = ["local-fs.target"];
        unitConfig.ConditionSecurity = "selinux";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${selinuxPolicyLoad}/bin/aos-selinux-load-policy";
        };
      };

      # Filesystem relabeling service.
      # Runs on first boot or when /.autorelabel exists.
      "selinux-autorelabel" = lib.mkIf cfg.autorelabel {
        description = "SELinux Filesystem Relabeling";
        wantedBy = ["sysinit.target"];
        before = ["sysinit.target"];
        after = [
          "selinux-policy-load.service"
          "local-fs.target"
        ];
        requires = ["selinux-policy-load.service"];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          # Only relabel if the marker file exists.
          ExecCondition = "${pkgs.coreutils}/bin/test -f /.autorelabel";
          ExecStart = "${pkgs.policycoreutils}/sbin/fixfiles -f -F relabel";
          ExecStartPost = "${pkgs.coreutils}/bin/rm -f /.autorelabel";
        };
      };
    };

    # Ensure SELinux kernel parameters are present in the boot config.
    # The boot module handles the actual cmdline; we just declare what
    # we need here and the system compositor merges it.
    aos.boot.kernelParams = [
      "selinux=1"
      "security=selinux"
      "enforcing=0"
    ];
  };
}
