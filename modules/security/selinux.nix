##! modules/security/selinux.nix — SELinux configuration module
##!
##! Extends the package-owned SELinux policy with authenticated immutable-stage0
##! admission and protected sandbox roots. Mutable policy loading and relabeling
##! remain owned by the native refpolicy package.
{
  config,
  pkgs,
  lib,
  packageModulesAvailable ? false,
  ...
}: let
  cfg = config.aos.security.selinux;
  immutableStage0 = cfg.bootMode == "immutable-stage0";
  # Native stages replay retained configuration rather than the whole image.
  # Keep the labeling selection bound to immutable source in that descriptor.
  initrdPolicy = builtins.path {
    path = ./_selinux-initrd-policy.nix;
    name = "aos-selinux-initrd-policy.nix";
  };
  protectedSandboxNetworkRoots = cfg.protectedSandboxNetworkRoots.enable;
  selectedSourceMount = config.aos.sandbox.mountBroker.sourceProviderSession.enable;
  selectedOnlineNix = config.aos.sandbox.nixBroker.enable;
  policyName = cfg.policy;
  viewPreparers = [
    {
      package = config.aos.sandbox.policyAuthority._stopPreparerPackage;
      program = "aos-sandbox-cache-journal-view-stop";
      role = "cache";
    }
    {
      package = config.aos.sandbox.policyAuthority._preparerPackage;
      program = "aos-sandbox-cache-journal-view";
      role = "cache";
    }
    {
      package = config.aos.sandbox.cacheSignerView._preparerPackage;
      program = "aos-sandbox-cache-signer-views";
      role = "cache";
    }
    {
      package = config.aos.sandbox.cacheSignerView._stopPackage;
      program = "aos-sandbox-cache-signer-views-stop";
      role = "cache";
    }
    {
      package = config.aos.sandbox.sourceSignerView._preparerPackage;
      program = "aos-sandbox-source-signer-view";
      role = "source";
    }
  ];
  # Exact script outputs contain the image's real UID/GID values. Their
  # interpreter/tool paths do not depend on this policy, avoiding a cycle.
  productionPolicy = pkgs.aosSelinuxProductionPolicyWith ({
      inherit viewPreparers homeContextAliases;
      environmentProvision = config.aos.sandbox.policyAuthority.environmentProvision;
      gitReadDelegation = config.aos.sandbox.controllerService.gitReadInspection.enable;
      sourceProviderMount = selectedSourceMount;
      runtimeDeploymentPublisher = config.aos.sandbox.runtimeDeploymentPublisher.enable;
      resourceBankEnrollment = config.aos.sandbox.resourceBank.policy != null;
      hostComponentControl = config.aos.sandbox.hostBroker.componentControl;
    }
    // lib.optionalAttrs selectedOnlineNix {
      onlineNix = true;
      aos-sandboxd = config.aos.sandbox.nixBroker._package;
      aos-nix-runtime-tpm-helpers = pkgs.aos-nix-runtime-tpm-helpers;
      aos-nix-online-store-reader = config.aos.sandbox.nixBroker._package.passthru.nixOnlineStoreReader;
    });
  canonicalPolicyPath = "${productionPolicy}/etc/selinux/aos/policy/policy.33";
  # selinuxfs serializes the loaded policydb; its bytes are not the input file.
  # Bind the exact expected image to the selected deployment kernel.
  canonicalReadback = pkgs.aosSelinuxKernelPolicyReadbackWith {
    linux = config.system.build.kernel;
    aos-selinux-production-policy = productionPolicy;
  };
  canonicalReadbackPath = "${canonicalReadback}/policy.33";
  productionAdmissionUnit = "aos-selinux-stage0-hold.target";
  selectedStage0 = config.aos.boot.initrd.stage0;
  controllerFloorRequired = config.aos.sandbox.controllerService.method46TpmFloor.required;
  storageFloorRequired = config.aos.sandbox.storageBroker.method46TpmFloor.required;
  ownerFloorRequired = controllerFloorRequired || storageFloorRequired;
  runtimeRootsProvisioner =
    if immutableStage0
    then
      pkgs.aosSelinuxRuntimeRootsWith {
        controllerUid = config.aos.sandbox.controller.uid;
        controllerGid = config.aos.sandbox.controller.gid;
        inherit controllerFloorRequired storageFloorRequired;
        sourceViewRequired = config.aos.sandbox.sourceSignerView.enable;
        cacheViewRequired = config.aos.sandbox.policyAuthority.enable;
        cacheSignerViewRequired = config.aos.sandbox.cacheSignerView.enable;
        environmentEvidenceRequired = config.aos.sandbox.policyAuthority.environmentProvision != null;
        viewZfsState = config.aos.filesystems.zfs.enable && config.aos.filesystems.zfs.systemState;
        viewZfsSource = "${config.aos.filesystems.zfs.poolName}/var/lib";
        aos-selinux-production-policy = productionPolicy;
        expectedPolicy = canonicalReadbackPath;
        expectedPolicyKernel = config.system.build.kernel;
      }
    else pkgs.aos-selinux-runtime-roots;
  strictKernelConfig = builtins.readFile ../../pkgs/kernel/config/selinux-immutable.config;
  countKernelParameter = name:
    lib.length (
      lib.filter (
        parameter:
          parameter == name || lib.hasPrefix "${name}=" parameter
      )
      config.aos.boot.kernelParams
    );

  # Immutable policy includes these same state-volume home aliases.
  homeContextAliases = ''
    /var/home /home
    /var/roothome /root
  '';
in {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/system/_aos-host-policy/selinux.nix];

  options.aos.security.selinux = {
    _qualificationAdmissionRelease = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      description = "Allows signed test images to replace the production admission hold with the normal initrd target.";
    };

    _runtimeRootsProvisioner = lib.mkOption {
      type = lib.types.package;
      internal = true;
      readOnly = true;
      default = runtimeRootsProvisioner;
      description = "Same immutable fixed runtime-root image used by stage 0 and both existing preparation routes.";
    };

    _productionPolicy = lib.mkOption {
      type = lib.types.package;
      internal = true;
      readOnly = true;
      default = productionPolicy;
      description = "Exact configuration-selected policy whose package runs the effective matrix checker; this path is not a live proof token.";
    };

    _canonicalReadback = lib.mkOption {
      type = lib.types.package;
      internal = true;
      readOnly = true;
      default = canonicalReadback;
      description = "Same selected-policy canonical serialization generated by the actual deployment kernel.";
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
          assertion = !ownerFloorRequired || (immutableStage0 && cfg.enable && cfg.mode == "enforcing" && !(config.aos.filesystems.zfs.enable && config.aos.filesystems.zfs.systemState));
          message = "required TPM owner-root preparation currently requires immutable enforcing SELinux and the existing exact ext4 /var substrate (ZFS data pools are unaffected)";
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
            name = "home-context-aliases";
            description = "the state-volume home directories alias their FHS paths";
            script = ''
              subs = vm.succeed("cat /etc/selinux/${policyName}/contexts/files/file_contexts.subs_dist")
              assert "/var/home /home" in subs, subs
              assert "/var/roothome /root" in subs, subs
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
    })

    (lib.mkIf (cfg.enable && immutableStage0) {
      aos.activation.stages.initrd.configuration = [initrdPolicy];

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
            countKernelParameter "selinux"
            == 1
            && builtins.elem "selinux=1" config.aos.boot.kernelParams;
          message = "immutable SELinux stage 0 requires exactly one selinux=1 parameter.";
        }
        {
          assertion =
            countKernelParameter "security"
            == 1
            && builtins.elem "security=selinux" config.aos.boot.kernelParams;
          message = "immutable SELinux stage 0 requires exactly one security=selinux parameter.";
        }
        {
          assertion =
            countKernelParameter "enforcing"
            == 1
            && builtins.elem "enforcing=1" config.aos.boot.kernelParams;
          message = "immutable SELinux stage 0 requires exactly one enforcing=1 parameter.";
        }
        {
          assertion =
            countKernelParameter "aos.selinux.root_handoff"
            == 1
            && builtins.elem "aos.selinux.root_handoff=1" config.aos.boot.kernelParams;
          message = "immutable SELinux stage 0 requires exactly one aos.selinux.root_handoff=1 parameter.";
        }
        {
          assertion =
            countKernelParameter "rootflags"
            == 1
            && builtins.elem "rootflags=nodev" config.aos.boot.kernelParams;
          message = "immutable SELinux stage 0 requires exactly one rootflags=nodev parameter.";
        }
        {
          assertion = selectedStage0 != null && (selectedStage0.passthru.loadedPolicy or null) == canonicalPolicyPath;
          message = "immutable SELinux stage 0 must load the canonical production policy.";
        }
        {
          assertion = selectedStage0 != null && (selectedStage0.passthru.expectedPolicy or null) == canonicalReadbackPath;
          message = "immutable SELinux stage 0 must authenticate the selected kernel's canonical policy readback.";
        }
        {
          assertion = selectedStage0 != null && (selectedStage0.passthru.expectedPolicyKernel or null) == config.system.build.kernel;
          message = "immutable SELinux stage 0 policy readback must bind the selected deployment kernel.";
        }
        {
          assertion = selectedStage0 != null && (selectedStage0.passthru.immutablePolicy or null) == productionPolicy;
          message = "immutable SELinux stage 0 must identify the canonical immutable policy derivation.";
        }
        {
          assertion =
            selectedStage0
            != null
            && (
              (selectedStage0.passthru.admissionUnit or null)
              == productionAdmissionUnit
              || (
                cfg._qualificationAdmissionRelease
                && config.aos.image.allowTestArtifacts
                && (selectedStage0.passthru.admissionUnit or null) == ""
              )
            );
          message = "immutable SELinux stage 0 must retain the production admission hold target.";
        }
        {
          assertion = selectedStage0 != null && (selectedStage0.passthru.runtimeRootsProvisioner or null) == runtimeRootsProvisioner;
          message = "immutable SELinux stage 0 must authenticate the canonical runtime-root provisioner.";
        }
        {
          assertion = config.aos.security.selinux._runtimeRootsProvisioner == runtimeRootsProvisioner && (runtimeRootsProvisioner.passthru.expectedPolicy or null) == canonicalReadbackPath && (runtimeRootsProvisioner.passthru.expectedPolicyReadback or null) == canonicalReadbackPath && (runtimeRootsProvisioner.passthru.expectedPolicyKernel or null) == config.system.build.kernel;
          message = "all immutable runtime-root preparation routes must use the selected-kernel canonical readback image, never the input policy or a substituted preparation image.";
        }
        {
          assertion = selectedStage0 != null && (selectedStage0.passthru.qualificationPostPinGate or null) == "";
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
      ];
      aos.boot.initrd.stage0 = pkgs.aosSelinuxStage0With ({
          systemd = config.aos.manager.selected.package;
          aos-selinux-production-policy = productionPolicy;
          aos-selinux-runtime-roots = runtimeRootsProvisioner;
          expectedPolicy = canonicalReadbackPath;
          expectedPolicyKernel = config.system.build.kernel;
        }
        // lib.optionalAttrs selectedSourceMount {
          mountExecutableCarrier = config.boot.initrd.systemd.mountExecutableCarrier;
          mountCarrierFirstLauncher = true;
        });
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

      # This configuration belongs to the immutable admission path; the native
      # refpolicy owner independently supplies it for mutable legacy boot.
      environment.etc."selinux/config".text = ''
        SELINUX=${cfg.mode}
        SELINUXTYPE=${cfg.policy}
      '';
      system.build.immutableSelinuxPolicy = productionPolicy;
      environment.etc."selinux/aos".source = "${productionPolicy}/etc/selinux/aos";
      # The switch-root guard bind-pins its authenticated empty file over a
      # regular /etc inode. The default environment.etc symlink cannot serve
      # as that mount target and must never be followed before custody.
      environment.etc."ld.so.preload" = {
        text = "";
        mode = "0644";
      };
    })
  ];
}
