##! Exact package-selected kernel projection.
{
  config,
  lib,
  pkgs,
  ...
}: let
  targetPlatformType = lib.types.submodule {
    config._module.strict = true;

    options = {
      abi = lib.mkOption {
        type = lib.types.nonEmptyStr;
        description = "Target application binary interface.";
      };
      cpu = lib.mkOption {
        type = lib.types.nonEmptyStr;
        description = "Target processor architecture.";
      };
      os = lib.mkOption {
        type = lib.types.nonEmptyStr;
        description = "Target operating-system family.";
      };
      system = lib.mkOption {
        type = lib.types.nonEmptyStr;
        description = "Canonical Nix target system.";
      };
    };
  };
  identityType = lib.types.submodule {
    config._module.strict = true;

    options = {
      binding = lib.mkOption {
        type = lib.types.nonEmptyStr;
        description = "Checked binding that selected this kernel provider.";
      };
      implementation = lib.mkOption {
        type = lib.types.nonEmptyStr;
        description = "Qualified selected implementation declaration.";
      };
      package = lib.mkOption {
        type = lib.types.submodule {
          config._module.strict = true;

          options = {
            name = lib.mkOption {
              type = lib.types.nonEmptyStr;
              description = "Authenticated package name.";
            };
            version = lib.mkOption {
              type = lib.types.nonEmptyStr;
              description = "Authenticated package version.";
            };
          };
        };
        description = "Authenticated package identity owning the implementation.";
      };
      providerInstance = lib.mkOption {
        type = lib.abilities.types.instanceId;
        description = "Canonical selected provider instance identity.";
      };
    };
  };
  configurationType = lib.types.submodule {
    config._module.strict = true;

    options = {
      bootImage = lib.mkOption {
        type = lib.types.pathInStore;
        description = "Exact boot image supplied by the selected kernel package.";
      };
      moduleTree = lib.mkOption {
        type = lib.types.nullOr lib.types.pathInStore;
        description = "Exact loadable-module tree, when the selected kernel supplies one.";
      };
      release = lib.mkOption {
        type = lib.types.nonEmptyStr;
        description = "Kernel ABI release identifier.";
      };
    };
  };
  selectedKernelType =
    lib.types.addCheck (lib.types.submodule {
      config._module.strict = true;

      options = {
        _type = lib.mkOption {
          type = lib.types.enum ["aos-selected-kernel"];
          description = "Selected-kernel record discriminator.";
        };
        artifact = lib.mkOption {
          type = lib.abilities.types.packageOutputSelector;
          description = "Symbolic planning output selecting the authenticated kernel package.";
        };
        configuration = lib.mkOption {
          type = configurationType;
          description = "Package-owned kernel artifact projection.";
        };
        identity = lib.mkOption {
          type = identityType;
          description = "Authority that selected the exact kernel implementation.";
        };
        name = lib.mkOption {
          type = lib.types.nonEmptyStr;
          description = "Human-readable selected kernel name.";
        };
        package = lib.mkOption {
          type = lib.types.pathInStore;
          description = "Authenticated package output containing the kernel.";
        };
        targetPlatform = lib.mkOption {
          type = targetPlatformType;
          description = "Exact platform targeted by the selected kernel artifact.";
        };
      };
    })
    (value: value.targetPlatform == config.aos.kernel.targetPlatform);
in {
  options = {
    aos.kernel.packageRoot = lib.mkOption {
      type = lib.types.uniq lib.types.package;
      internal = true;
      description = "Exact kernel provider package selected by the system composition.";
    };

    aos.kernel.selected = lib.mkOption {
      type = lib.types.nullOr (lib.types.uniq selectedKernelType);
      default = null;
      readOnly = true;
      internal = true;
      contributable = true;
      description = "Derived kernel artifact selected by the checked ability binding.";
    };

    aos.kernel.targetPlatform = lib.mkOption {
      type = lib.types.uniq targetPlatformType;
      readOnly = true;
      internal = true;
      description = "Canonical target platform the selected kernel must implement.";
    };
  };

  config = {
    aos.kernel.targetPlatform = {
      inherit (pkgs.stdenv.hostPlatform) system;
      inherit (pkgs.stdenv.hostPlatform.constraints) abi cpu os;
    };
    environment.systemPackages = [config.aos.kernel.packageRoot];
    aos.boot.initrd.packageRoots = [config.aos.kernel.packageRoot];
  };
}
