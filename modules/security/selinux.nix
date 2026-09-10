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
  immutableStage0 = cfg.bootMode == "immutable-stage0";
  protectedSandboxNetworkRoots = cfg.protectedSandboxNetworkRoots.enable;
  policyName = cfg.policy;
  refpolicy = pkgs.refpolicy;
  productionPolicy = pkgs.aos-selinux-production-policy;
  canonicalPolicyPath = "${productionPolicy}/etc/selinux/aos/policy/policy.33";
  productionAdmissionUnit = "aos-selinux-stage0-hold.target";
  selectedStage0 = config.aos.boot.initrd.stage0;
  runtimeRootsProvisioner = pkgs.aos-selinux-runtime-roots;
  strictKernelConfig = builtins.readFile ../../pkgs/kernel/config/selinux-immutable.config;
  semodule = "${pkgs.policycoreutils}/sbin/semodule";
  loadPolicy = "${pkgs.policycoreutils}/sbin/load_policy";
  setenforce = "${pkgs.libselinux}/sbin/setenforce";

  countKernelParameter = name:
    lib.length (
      lib.filter (
        parameter:
          parameter == name || lib.hasPrefix "${name}=" parameter
      )
      config.aos.boot.kernelParams
    );

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

    bootMode = lib.mkOption {
      type = lib.types.enum [
        "legacy"
        "immutable-stage0"
      ];
      default = "legacy";
      description = ''
        Policy admission path. Legacy compiles a mutable module store after
        local filesystems mount. Immutable-stage0 loads the kernel-matched
        policy from a signed static PID 1 before labeled stage-1 systemd.
      '';
    };

    _qualificationAdmissionRelease = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      description = "Allows signed test images to replace the production admission hold with the normal initrd target.";
    };

    protectedSandboxNetworkRoots = {
      enable = lib.mkEnableOption ''
        the fixed SELinux-labeled sandbox Network state-root topology
      '';

      _varRootContext = lib.mkOption {
        type = lib.types.str;
        default = "system_u:object_r:var_t";
        internal = true;
        readOnly = true;
        description = "Exact non-MLS SELinux context shared by every protected /var mount path.";
      };
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = cfg.enable || !immutableStage0;
          message = "immutable SELinux stage 0 requires aos.security.selinux.enable.";
        }
        {
          assertion = !protectedSandboxNetworkRoots || cfg.enable;
          message = "protected sandbox Network roots require SELinux.";
        }
        {
          assertion = !protectedSandboxNetworkRoots || immutableStage0;
          message = "protected sandbox Network roots require immutable SELinux stage 0.";
        }
        {
          assertion = !protectedSandboxNetworkRoots || cfg.mode == "enforcing";
          message = "protected sandbox Network roots require enforcing SELinux.";
        }
        {
          assertion = !protectedSandboxNetworkRoots || cfg.policy == "aos";
          message = "protected sandbox Network roots require the kernel-matched aos policy.";
        }
        {
          assertion = !protectedSandboxNetworkRoots || config.aos.sandbox.networkBroker.enable;
          message = "protected sandbox Network roots require the Network broker.";
        }
        {
          assertion = !protectedSandboxNetworkRoots || !config.aos.filesystems.zfs.enable;
          message = "protected sandbox Network roots currently require the ext4 /var substrate.";
        }
        {
          assertion =
            !cfg._qualificationAdmissionRelease
            || config.aos.image.allowTestArtifacts;
          message = "SELinux admission release is restricted to test-artifact images.";
        }
      ];
    }

    (lib.mkIf cfg.enable {
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

      # /etc/selinux/config is common to both paths. The legacy service reads
      # it after local-fs; strict stage 0 embeds the same selected identity.
      environment.etc."selinux/config".text = ''
        # /etc/selinux/config — generated by modules/security/selinux.nix
        SELINUX=${cfg.mode}
        SELINUXTYPE=${cfg.policy}
      '';
    })

    (lib.mkIf (cfg.enable && !immutableStage0) {
      environment.etc = {
        "selinux/semanage.conf".text = semanageConfText;
        "selinux/${policyName}/contexts".source = "${refpolicy}/etc/selinux/refpolicy/contexts";
      };

      systemd.services = {
        # Compatibility path: compile and load a mutable module store after
        # local filesystems. Immutable stage 0 structurally excludes it.
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
            ExecCondition = "${pkgs.coreutils}/bin/test -f /.autorelabel";
            ExecStart = "${pkgs.policycoreutils}/sbin/fixfiles -f -F relabel";
            ExecStartPost = "${pkgs.coreutils}/bin/rm -f /.autorelabel";
          };
        };
      };

      aos.boot.kernelParams = [
        "selinux=1"
        "security=selinux"
        "enforcing=0"
      ];
    })

    (lib.mkIf (cfg.enable && immutableStage0) {
      assertions = [
        {
          assertion = cfg.mode == "enforcing";
          message = "immutable SELinux stage 0 requires enforcing mode.";
        }
        {
          assertion = cfg.policy == "aos";
          message = "immutable SELinux stage 0 requires the kernel-matched aos policy.";
        }
        {
          assertion = !cfg.autorelabel;
          message = "immutable SELinux stage 0 forbids runtime autorelabeling.";
        }
        {
          assertion = config.aos.security.verity.enable;
          message = "immutable SELinux stage 0 requires dm-verity root verification.";
        }
        {
          assertion = config.aos.boot.secureBoot.enable;
          message = "immutable SELinux stage 0 requires a signed Secure Boot image.";
        }
        {
          assertion = config.aos.boot.secureBoot.lockdown.enable;
          message = "immutable SELinux stage 0 requires the lockdown kernel.";
        }
        {
          assertion = config.aos.boot.initrd.enable;
          message = "immutable SELinux stage 0 requires the systemd initrd.";
        }
        {
          assertion =
            countKernelParameter "selinux" == 1
            && builtins.elem "selinux=1" config.aos.boot.kernelParams;
          message = "immutable SELinux stage 0 requires exactly one selinux=1 parameter.";
        }
        {
          assertion =
            countKernelParameter "security" == 1
            && builtins.elem "security=selinux" config.aos.boot.kernelParams;
          message = "immutable SELinux stage 0 requires exactly one security=selinux parameter.";
        }
        {
          assertion =
            countKernelParameter "enforcing" == 1
            && builtins.elem "enforcing=1" config.aos.boot.kernelParams;
          message = "immutable SELinux stage 0 requires exactly one enforcing=1 parameter.";
        }
        {
          assertion =
            countKernelParameter "aos.selinux.root_handoff" == 1
            && builtins.elem "aos.selinux.root_handoff=1" config.aos.boot.kernelParams;
          message = "immutable SELinux stage 0 requires exactly one aos.selinux.root_handoff=1 parameter.";
        }
        {
          assertion =
            countKernelParameter "rootflags" == 1
            && builtins.elem "rootflags=nodev" config.aos.boot.kernelParams;
          message = "immutable SELinux stage 0 requires exactly one rootflags=nodev parameter.";
        }
        {
          assertion = selectedStage0 != null && (selectedStage0.loadedPolicy or null) == canonicalPolicyPath;
          message = "immutable SELinux stage 0 must load the canonical production policy.";
        }
        {
          assertion = selectedStage0 != null && (selectedStage0.expectedPolicy or null) == canonicalPolicyPath;
          message = "immutable SELinux stage 0 must authenticate the canonical production policy.";
        }
        {
          assertion = selectedStage0 != null && (selectedStage0.immutablePolicy or null) == productionPolicy;
          message = "immutable SELinux stage 0 must identify the canonical immutable policy derivation.";
        }
        {
          assertion =
            selectedStage0 != null
            && (
              (selectedStage0.admissionUnit or null) == productionAdmissionUnit
              || (
                cfg._qualificationAdmissionRelease
                && config.aos.image.allowTestArtifacts
                && (selectedStage0.admissionUnit or null) == ""
              )
            );
          message = "immutable SELinux stage 0 must retain the production admission hold target.";
        }
        {
          assertion = selectedStage0 != null && (selectedStage0.runtimeRootsProvisioner or null) == runtimeRootsProvisioner;
          message = "immutable SELinux stage 0 must authenticate the canonical runtime-root provisioner.";
        }
        {
          assertion = selectedStage0 != null && (selectedStage0.qualificationPostPinGate or null) == "";
          message = "immutable SELinux stage 0 forbids the qualification post-pin gate in production composition.";
        }
      ];

      aos.security.selinux = {
        mode = lib.mkDefault "enforcing";
        policy = lib.mkDefault "aos";
        autorelabel = lib.mkDefault false;
      };

      aos.boot.kernelParams = [
        "selinux=1"
        "security=selinux"
        "enforcing=1"
        "aos.selinux.root_handoff=1"
        "rootflags=nodev"
      ];
      aos.boot.initrd.stage0 = pkgs.aos-selinux-stage0;
      aos.kernel._extraConfigFragments = [strictKernelConfig];

      # Keep production admission closed until the signed-boot VM matrix has
      # qualified the EROFS guard, complete runtime-closure pins, descriptor
      # custody, and daemon-reexec path. The qualification fixture selects a
      # normal initrd target through its own stage0 build; it does not weaken
      # this production target.
      boot.initrd.systemd.targets."aos-selinux-stage0-hold" = {
        description = "AOS immutable SELinux stage-0 hold";
        unitConfig = {
          DefaultDependencies = "no";
          Conflicts = "initrd-root-fs.target initrd-switch-root.target";
        };
      };

      system.build.immutableSelinuxPolicy = productionPolicy;
      environment.etc."selinux/aos".source = "${productionPolicy}/etc/selinux/aos";
      environment.etc."ld.so.preload".text = "";
    })
  ];
}
