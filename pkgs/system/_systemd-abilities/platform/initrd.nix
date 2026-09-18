##! pkgs/system/_systemd-abilities/platform/initrd.nix — Stage 1 systemd module (tier ii)
##!
##! Declares the typed `boot.initrd.systemd.*` option tree for the
##! systemd-based initrd and produces `system.build.initrd` by
##! rendering the options through the stage-1 `*-ToUnit` helpers in
##! `pkgs/system/_systemd-abilities/platform/render.nix`, flattening the pure `generateUnits`
##! result, and materializing it for the cpio assembler in
##! `_initrd-builder.nix`.
##!
##! Uses the `stage1*` option + type variants from
##! `pkgs/system/_systemd-abilities/platform/unit-options.nix` / `pkgs/system/_systemd-abilities/platform/types.nix`,
##! so modules that contribute initrd units declare
##! them with real per-option validation exactly like stage-2 services.
##! The stage-1 option trees drop the switch-to-configuration knobs
##! (`startAt`, `restartIfChanged`, ...) and otherwise mirror the
##! stage-2 options.
##!
##! Unlike stage 2 (`system.nix`), this module does NOT fold the
##! rendered units into a shared `systemd.units` attrset — the stage-2
##! and stage-1 renderers produce a parallel set each, and the initrd
##! has its own generateUnits invocation with `type = "initrd"`.
##!
##! Outputs (wired by the `config` block below):
##!   * `system.build.systemdInitrdUnits` — directory matching
##!     `/etc/systemd/system/` for the initrd, materialized from the pure
##!     unit plan. Consumed by the initrd builder.
##!   * `system.build.initrd` — the final gzip+cpio initramfs
##!     derivation produced by `_initrd-builder.nix`.
{
  abilitySelection ? null,
  config,
  initrdAbilityEvaluation ? null,
  lib,
  packageArtifactFor,
  packageFor,
  ...
}: let
  managerBindings =
    if abilitySelection == null
    then []
    else abilitySelection.bindingsForImplementation "system-manager";
  selected = builtins.length managerBindings == 1;
  packageOutput = package: lib.abilities.packageOutput {inherit package;};
  packageRootFor = package: packageFor (packageOutput package);
  rendererPackages = {
    bash = packageArtifactFor (packageOutput "bash");
    coreutils = packageArtifactFor (packageOutput "coreutils");
    findutils = packageArtifactFor (packageOutput "findutils");
    grep = packageArtifactFor (packageOutput "grep");
    sed = packageArtifactFor (packageOutput "sed");
    systemd = packageArtifactFor (lib.abilities.packageOutput {});
  };
  systemdLib = import ./render.nix {
    inherit lib;
    pkgs = rendererPackages;
  };
  systemdUnitOptions = import ./unit-options.nix {
    inherit lib systemdLib;
  };
  systemdTypes = import ./types.nix {
    inherit lib systemdLib systemdUnitOptions;
  };

  cfg = config.boot.initrd.systemd;
  providerRenderPlanType = lib.types.submodule {
    config._module.strict = true;
    options = {
      input = lib.mkOption {type = lib.types.str;};
      name = lib.mkOption {type = lib.types.nonEmptyStr;};
    };
  };
  providerNetworkRenderPlanType = lib.types.submodule {
    config._module.strict = true;
    options = {
      input = lib.mkOption {type = lib.types.str;};
      name = lib.mkOption {type = lib.types.nonEmptyStr;};
      resolverEnabled = lib.mkOption {type = lib.types.bool;};
    };
  };

  # Render each initrd unit category through its stage-1 *-ToUnit
  # renderer and key the result by unit file name (e.g. "foo.service").
  # Mirrors `pkgs/system/_systemd-abilities/platform/system.nix`'s stage-2 pattern but without
  # the `globalEnvironment` pre-merge — initrd services don't need it.
  #
  withName = cfgToUnit: c: lib.nameValuePair c.name (cfgToUnit c);
  renderedInitrdUnits =
    lib.mapAttrs' (_: withName systemdLib.serviceToUnit) cfg.services
    // lib.mapAttrs' (_: withName systemdLib.targetToUnit) cfg.targets
    // lib.mapAttrs' (_: withName systemdLib.socketToUnit) cfg.sockets
    // lib.mapAttrs' (_: withName systemdLib.timerToUnit) cfg.timers
    // lib.mapAttrs' (_: withName systemdLib.pathToUnit) cfg.paths
    // lib.mapAttrs' (_: withName systemdLib.sliceToUnit) cfg.slices
    // lib.listToAttrs (map (withName systemdLib.mountToUnit) cfg.mounts)
    // lib.listToAttrs (map (withName systemdLib.automountToUnit) cfg.automounts);

  pureInitrdUnits = systemdLib.generateUnits {
    type = "initrd";
    units = renderedInitrdUnits;
  };
  initrdJobScripts = lib.listToAttrs (builtins.map (job:
    lib.nameValuePair job.key {
      text = job.body;
      inherit (job) mode;
      name = job.scriptName;
    })
  (lib.concatLists (lib.mapAttrsToList (_: service: service.jobScripts) cfg.services)));
  initrdProviderPlans =
    if initrdAbilityEvaluation == null
    then []
    else initrdAbilityEvaluation.config.systemd.providerUnitPlans or [];
  initrdProviderNetworkPlans =
    if initrdAbilityEvaluation == null
    then []
    else initrdAbilityEvaluation.config.systemd.providerNetworkConfigurationPlans or [];
in {
  options.boot.initrd.systemd = {
    enable = lib.mkEnableOption "a systemd-based initrd (tier ii, not yet implemented)";

    services = lib.mkOption {
      type = systemdTypes.initrdServices;
      default = {};
      description = ''
        Typed .service units to include in the systemd initrd. Same
        option tree as the stage-2 `systemd.services`, minus the
        stage-2-specific switch-to-configuration knobs (`startAt`,
        `restartIfChanged`, …). No builder consumes this yet;
        contributions are type-checked at eval time for future use.
      '';
    };

    targets = lib.mkOption {
      type = systemdTypes.initrdTargets;
      default = {};
      description = "Typed .target units to include in the systemd initrd.";
    };

    sockets = lib.mkOption {
      type = systemdTypes.initrdSockets;
      default = {};
      description = "Typed .socket units to include in the systemd initrd.";
    };

    timers = lib.mkOption {
      type = systemdTypes.initrdTimers;
      default = {};
      description = "Typed .timer units to include in the systemd initrd.";
    };

    paths = lib.mkOption {
      type = systemdTypes.initrdPaths;
      default = {};
      description = "Typed .path units to include in the systemd initrd.";
    };

    slices = lib.mkOption {
      type = systemdTypes.initrdSlices;
      default = {};
      description = "Typed .slice units to include in the systemd initrd.";
    };

    mounts = lib.mkOption {
      type = systemdTypes.initrdMounts;
      default = [];
      description = "Typed .mount units to include in the systemd initrd. Keyed by `where`, not by name.";
    };

    automounts = lib.mkOption {
      type = systemdTypes.initrdAutomounts;
      default = [];
      description = "Typed .automount units to include in the systemd initrd. Keyed by `where`, not by name.";
    };

    maskedUnits = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "emergency.service"
        "rescue.service"
      ];
      description = ''
        Unit names to mask (symlink to /dev/null) in the initrd.
        Needed because the initrd's /usr→. symlink collapses systemd's
        unit search priority, making kernel-cmdline systemd.mask=
        ineffective. The interactive emergency and rescue services are
        masked by default so normal initrds fail closed without exposing a
        password prompt. Explicit debug gettys are separate opt-in units.
      '';
    };
  };

  options.system.build.systemdInitrdPlan = lib.mkOption {
    type = lib.types.submodule {
      options = {
        etc = lib.mkOption {type = lib.types.attrsOf lib.types.attrs;};
        jobScripts = lib.mkOption {type = lib.types.attrsOf lib.types.attrs;};
        providerPlans = lib.mkOption {
          type = lib.types.listOf providerRenderPlanType;
        };
        providerNetworkPlans = lib.mkOption {
          type = lib.types.listOf providerNetworkRenderPlanType;
        };
        renderedUnits = lib.mkOption {type = lib.types.listOf lib.types.str;};
      };
    };
    readOnly = true;
    internal = true;
    description = "Pure package-owned rendering plan for the selected systemd initrd.";
  };

  config = lib.mkIf selected {
    aos.contributions.kernelParameters.systemd-manager = [
      "systemd.unified_cgroup_hierarchy=1"
      "systemd.gpt-auto=0"
      "systemd.mask=systemd-boot-random-seed.service"
      "systemd.mask=systemd-boot-update.service"
      "systemd.mask=systemd-bless-boot.service"
    ];

    # The selected initrd manager owns its package implementations. Security
    # policy contributes only provider-neutral intent; it does not select a
    # manager or a TPM token format from the generic secure-boot module.
    aos.boot.initrd.packageRoots =
      (builtins.map packageRootFor [
        "bash"
        "coreutils"
        "cryptsetup"
        "e2fsprogs"
        "grep"
        "gptfdisk"
        "iproute2"
        "kmod"
        "less"
        "util-linux"
      ])
      ++ [
        (packageFor (lib.abilities.packageOutput {}))
      ];

    # Re-run stage-1 config oneshots against the real /etc in stage-2.
    #
    # systemd-modules-load / systemd-sysctl / systemd-tmpfiles-setup run once
    # in the initrd against stage-1's near-empty /etc. systemd serializes unit
    # *state* across the initrd→rootfs switch-root but deliberately drops any
    # un-run *job* (src/core/unit-serialize.c — job serialization is guarded by
    # `if (!switching_root)`). These units are oneshot `RemainAfterExit=yes`,
    # so they end the initrd as `active (exited)`; that state is carried into
    # stage-2, where `sysinit.target` treats them as already satisfied and
    # never re-runs them — so the real /etc/{modules-load,sysctl,tmpfiles}.d/*
    # are silently ignored (e.g. br_netfilter never loads, k3s bridge sysctls
    # fail). Same family as systemd issue #38765.
    #
    # `RemainAfterExit=no` in the initrd lets each oneshot do its stage-1 work
    # and then return to `inactive`. The
    # serialized state is then `inactive` regardless of switch-root job timing
    # or closure membership, so stage-2 starts each one fresh against the real
    # /etc. Stage-2 keeps the stock `RemainAfterExit=yes`.
    boot.initrd.systemd.services =
      lib.genAttrs [
        "systemd-sysctl"
        "systemd-tmpfiles-setup"
        "systemd-tmpfiles-setup-dev"
      ] (_: {
        overrideStrategy = "asDropin";
        serviceConfig.RemainAfterExit = false;
      })
      // {
        # modules-load already ignores
        # missing (-ENOENT) and hardware-absent (-ENODEV) modules; it exits
        # non-zero (1) only when a module is present but fails to insert.
        # SuccessExitStatus=0 1 keeps even that non-fatal, matching the
        # stage-2 drop-in in modules/base/kernel.nix.
        "systemd-modules-load" = {
          overrideStrategy = "asDropin";
          serviceConfig = {
            RemainAfterExit = false;
            SuccessExitStatus = "0 1";
          };
        };
      };

    system.build.systemdInitrdPlan = {
      etc = systemdLib.unitsToEtc pureInitrdUnits;
      jobScripts = initrdJobScripts;
      providerPlans = initrdProviderPlans;
      providerNetworkPlans = initrdProviderNetworkPlans;
      renderedUnits = builtins.attrNames renderedInitrdUnits;
    };
  };
}
