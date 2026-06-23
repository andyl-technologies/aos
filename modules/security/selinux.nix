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

  # AOS-authored SELinux module shipped alongside the upstream refpolicy.
  #
  # On AOS systems the root filesystem is not relabeled (autorelabel=false in
  # the appliance images and the VM tests), so virtually every inode carries
  # the default `unlabeled_t` context and PID1 never makes the kernel_t ->
  # init_t domain transition refpolicy expects — systemd therefore runs as
  # `kernel_t` for the whole boot. The upstream refpolicy `kernel_t` domain
  # predates the privileged sandbox-setup operations modern systemd performs
  # on behalf of confined units, so the policy denies them even though both
  # the classes and permissions are *defined* (so handle-unknown=allow cannot
  # help). Two such operations block AOS exposed/confined package units:
  #
  #   * `user_namespace { create }` — systemd opens a user namespace when a
  #     unit sets PrivateUsers=identity (every confined `expose` unit does;
  #     see pkgs/build-support/_expose-renderer.nix). Without this the unit
  #     dies at "Failed to set up user namespacing" / status=217/USER before
  #     it can transition into its generated domain, and the smoke check sees
  #     it still in system_u:system_r:kernel_t.
  #   * `filesystem { associate }` for the unlabeled root associating with a
  #     `tmpfs_t` superblock — systemd mounts the per-unit
  #     TemporaryFileSystem=/tmp:/var/tmp and PrivateTmp tmpfs instances while
  #     still in kernel_t/unlabeled_t, and the new tmpfs inodes must associate
  #     with the unlabeled context the rootfs uses.
  #
  # These grants apply only to the unlabeled-rootfs `kernel_t`/`unlabeled_t`
  # subjects; the confined domains generated per package are unaffected and
  # remain fully default-deny. The module is compiled to a `.pp` here (the
  # same checkmodule + semodule_package pipeline refpolicy and the test use)
  # and installed in the same semodule transaction as base.pp by the loader.
  aosBaseModuleName = "aos_base";
  # The `.te` source. Authored as a writeTextFile (a plain file at
  # $out/aos_base.te, with store-path refs preserved) rather than a builder
  # heredoc — the latter's terminator cannot be indented under the AOS dash
  # builder, and SELinux `.te` syntax is whitespace-insensitive anyway.
  aosBaseModuleSource = pkgs.writeTextFile {
    name = "${aosBaseModuleName}.te";
    destination = "/${aosBaseModuleName}.te";
    text = ''
      module ${aosBaseModuleName} 1.0;

      require {
        type kernel_t;
        type unlabeled_t;
        type tmpfs_t;
        class user_namespace { create };
        class filesystem { associate };
      }

      # systemd (running as kernel_t on the unlabeled AOS rootfs) opens a user
      # namespace for confined units that set PrivateUsers=identity.
      allow kernel_t self:user_namespace create;

      # Per-unit TemporaryFileSystem / PrivateTmp tmpfs mounts must associate
      # with the unlabeled rootfs context.
      allow unlabeled_t tmpfs_t:filesystem associate;
    '';
  };
  aosBaseModule = pkgs.mkDerivation {
    pname = "aos-selinux-base-module";
    version = "1.0";
    src = null;
    buildDeps = [pkgs.checkpolicy pkgs.semodule-utils];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp ${aosBaseModuleSource}/${aosBaseModuleName}.te "$out/${aosBaseModuleName}.te"
          ${pkgs.checkpolicy}/bin/checkmodule -M -m \
            -o "$out/${aosBaseModuleName}.mod" "$out/${aosBaseModuleName}.te"
          ${pkgs.semodule-utils}/bin/semodule_package \
            -o "$out/${aosBaseModuleName}.pp" -m "$out/${aosBaseModuleName}.mod"
          test -s "$out/${aosBaseModuleName}.pp"
        '';
      }
    ];
  };
  aosBasePp = "${aosBaseModule}/${aosBaseModuleName}.pp";

  # libsemanage (used by semodule when it commits a policy) forks several
  # external helpers and the `.pp` high-level-language compiler. Its
  # compiled-in defaults are FHS paths (/usr/sbin/sefcontext_compile,
  # /usr/sbin/setfiles, /usr/sbin/load_policy, /usr/libexec/selinux/hll) that
  # do not exist in the hermetic AOS layout. Without overrides, the policy
  # commit aborts with "sefcontext_compile returned error code 1 … (No such
  # file or directory)" and the store is left without a usable policy.* —
  # which keeps SELinux degraded in enforcing mode. Pin every path to its
  # AOS store location so semodule can compile file_contexts and load the
  # policy. See man semanage.conf(5) and libsemanage/src/conf-parse.y.
  #
  # Materialized via the `environment.etc` `text` attribute (not a hand-rolled
  # writeTextFile + `source`): AOS's writeTextFile with no `destination`
  # produces a *directory* output, which environment.etc would expose as a
  # directory at /etc/selinux/semanage.conf — libsemanage's flex scanner then
  # aborts with "input in flex scanner failed". The etc module's `text` path
  # already handles the destination dance (modules/base/build.nix) and keeps
  # store-path refs intact (writeTextFile sets dontNukeRefs).
  semanageConfText = ''
    # /etc/selinux/semanage.conf — generated by modules/security/selinux.nix
    module-store = direct

    # The refpolicy we ship predates several SELinux object classes the
    # running kernel defines (user_namespace, io_uring, the watch_* perms,
    # …). With the default handle-unknown=deny the kernel denies any
    # operation in an undefined class — which breaks confined services that
    # use newer primitives (e.g. systemd PrivateUsers=identity needs the
    # user_namespace class), failing them with "Failed to set up user
    # namespacing: Permission denied" before they can transition into their
    # domain. Allow access checks against classes/perms the policy does not
    # define; everything the policy *does* define is still fully enforced.
    handle-unknown = allow

    # Directory holding the per-language high-level-language compilers; for
    # the `.pp` modules refpolicy ships, libsemanage runs
    # <compiler-directory>/pp.
    compiler-directory = ${pkgs.policycoreutils}/libexec/selinux/hll

    [load_policy]
    path = ${pkgs.policycoreutils}/sbin/load_policy
    args =
    [end]

    [setfiles]
    path = ${pkgs.policycoreutils}/sbin/setfiles
    args = -q -c $@ $<
    [end]

    [sefcontext_compile]
    path = ${pkgs.libselinux}/sbin/sefcontext_compile
    args = $@
    [end]
  '';
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

      # AOS-authored grants for the unlabeled-rootfs kernel_t/unlabeled_t
      # subjects (see aosBaseModule above). Installed in the same transaction
      # as the upstream modules so it lands in the compiled policy store.
      set -- "$@" -i ${lib.escapeShellArg aosBasePp}

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

      "selinux/semanage.conf".text = semanageConfText;
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
