##! Exact package-selected immutable image builder projection.
{
  config,
  lib,
  ...
}: let
  consumer = "image:builder";
  builderInterface = lib.abilities.interfaces.imageBuilder.interfaces.builder;
  artifactFilenameType = lib.types.strMatching "[A-Za-z0-9][A-Za-z0-9._+-]*";
  pathSegments = path: lib.splitString "/" path;
  safeRelativePath = path:
    builtins.all (segment: segment != "." && segment != "..") (pathSegments path);
  strictSubmodule = options:
    lib.types.submodule {
      inherit options;
      config._module.strict = true;
    };
  packageIdentityType = strictSubmodule {
    name = lib.mkOption {
      type = lib.types.nonEmptyStr;
      description = "Authenticated package name.";
    };
    version = lib.mkOption {
      type = lib.types.nonEmptyStr;
      description = "Authenticated package version.";
    };
  };
  kernelIdentityType = strictSubmodule {
    binding = lib.mkOption {
      type = lib.types.nonEmptyStr;
      description = "Checked binding that selected the kernel provider.";
    };
    implementation = lib.mkOption {
      type = lib.types.nonEmptyStr;
      description = "Qualified selected kernel implementation.";
    };
    package = lib.mkOption {
      type = packageIdentityType;
      description = "Authenticated package identity owning the kernel implementation.";
    };
    providerInstance = lib.mkOption {
      type = lib.abilities.types.instanceId;
      description = "Canonical selected kernel provider instance.";
    };
  };
  imageIdentityType = lib.types.addCheck (strictSubmodule {
      schema = lib.mkOption {
        type = lib.types.enum ["aos.image.identity/v1"];
        description = "Immutable image identity schema.";
      };
      builder = lib.mkOption {
        type = strictSubmodule {
          artifact = lib.mkOption {
            type = lib.abilities.types.artifactSelector;
            description = "Symbolic output selector for the authenticated image-builder package.";
          };
          name = lib.mkOption {
            type = lib.types.nonEmptyStr;
            description = "Selected image-builder name.";
          };
        };
        description = "Authenticated image-builder identity.";
      };
      target = lib.mkOption {
        type = strictSubmodule {
          cpu = lib.mkOption {
            type = lib.types.nonEmptyStr;
            description = "Target processor architecture.";
          };
          system = lib.mkOption {
            type = lib.types.nonEmptyStr;
            description = "Canonical Nix target system.";
          };
        };
        description = "Target platform identity.";
      };
      release = lib.mkOption {
        type = strictSubmodule {
          name = lib.mkOption {
            type = lib.types.nonEmptyStr;
            description = "System release name.";
          };
          version = lib.mkOption {
            type = lib.types.nonEmptyStr;
            description = "System release version.";
          };
          "state-version" = lib.mkOption {
            type = lib.types.nonEmptyStr;
            description = "Persistent state migration version.";
          };
          "module-abi" = lib.mkOption {
            type = lib.types.addCheck lib.types.int (value: value > 0);
            description = "Shared module schema ABI.";
          };
          "config-input-abi" = lib.mkOption {
            type = lib.types.addCheck lib.types.int (value: value > 0);
            description = "Persistent evaluator input ABI.";
          };
        };
        description = "Immutable release identity.";
      };
      kernel = lib.mkOption {
        type = kernelIdentityType;
        description = "Authenticated selected kernel identity.";
      };
      boot = lib.mkOption {
        type = strictSubmodule {
          "normal-artifact-path" = lib.mkOption {
            type = lib.types.strMatching "[A-Za-z0-9][A-Za-z0-9._+/-]*";
            description = "Firmware-relative path of the normal boot artifact.";
          };
        };
        description = "Selected boot artifact identity.";
      };
    })
    (value:
      value.target.system == lib.system
      && value.target.cpu == lib.platform.constraints.cpu
      && safeRelativePath value.boot."normal-artifact-path");
  selectedBuilderType = lib.types.addCheck (lib.types.submodule {
    config._module.strict = true;

    options = {
      _type = lib.mkOption {
        type = lib.types.enum ["aos-image-builder"];
        description = "Selected image-builder record discriminator.";
      };
      artifact = lib.mkOption {
        type = lib.abilities.types.artifactSelector;
        description = "Checked symbolic output selector for the selected package.";
      };
      build = lib.mkOption {
        type = lib.types.functionTo lib.types.attrs;
        description = "Opaque package-owned immutable image artifact builder.";
      };
      name = lib.mkOption {
        type = lib.types.nonEmptyStr;
        description = "Human-readable selected image-builder name.";
      };
      normalArtifactPath = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z0-9][A-Za-z0-9._+/-]*";
        description = "Firmware-relative path of the normal boot artifact.";
      };
      package = lib.mkOption {
        type = lib.types.pathInStore;
        description = "Authenticated package output that owns the selected image builder.";
      };
      identity = lib.mkOption {
        type = imageIdentityType;
        description = "Pure image identity projected by the selected builder.";
      };
    };
  }) (value:
    safeRelativePath value.normalArtifactPath
    && value.identity.builder.artifact == value.artifact
    && value.identity.builder.name == value.name
    && value.identity.boot."normal-artifact-path" == value.normalArtifactPath);
  nullableArtifact = lib.types.nullOr lib.types.package;
  imagePlanType = lib.types.addCheck (lib.types.submodule {
    config._module.strict = true;

    options = {
      _type = lib.mkOption {
        type = lib.types.enum ["aos-image-build-plan"];
        description = "Immutable image plan discriminator.";
      };
      budgetCheck = lib.mkOption {
        type = lib.types.package;
        description = "Selected provider's image budget check.";
      };
      finishConvertedImage = lib.mkOption {
        type = lib.types.functionTo lib.types.package;
        description = "Opaque provider finalizer for one converted disk image.";
      };
      initialBootExecutable = lib.mkOption {
        type = lib.types.package;
        description = "Initial boot executable emitted by the selected provider.";
      };
      installBundle = lib.mkOption {
        type = nullableArtifact;
        description = "Optional selected-provider installation bundle.";
      };
      rawDiskFilename = lib.mkOption {
        type = artifactFilenameType;
        description = "Filename of the compressed raw disk inside its artifact.";
      };
      rawImage = lib.mkOption {
        type = lib.types.package;
        description = "Selected provider's compressed raw disk artifact.";
      };
      rawMetadataFilename = lib.mkOption {
        type = artifactFilenameType;
        description = "Filename of image metadata inside the raw artifact.";
      };
      recoveryBootExecutableA = lib.mkOption {
        type = nullableArtifact;
        description = "Optional recovery boot executable for slot A.";
      };
      recoveryBootExecutableB = lib.mkOption {
        type = nullableArtifact;
        description = "Optional recovery boot executable for slot B.";
      };
      recoveryBundle = lib.mkOption {
        type = nullableArtifact;
        description = "Optional fixed-layout recovery artifact bundle.";
      };
      recoveryInitrd = lib.mkOption {
        type = nullableArtifact;
        description = "Optional selected-provider recovery initrd.";
      };
      recoverySlotManifest = lib.mkOption {
        type = nullableArtifact;
        description = "Optional recovery slot manifest.";
      };
      unsignedAssembly = lib.mkOption {
        type = lib.types.package;
        description = "Deterministic public-only image assembly inputs.";
      };
    };
  }) (value: let
    recoveryArtifacts = [
      value.recoveryBootExecutableA
      value.recoveryBootExecutableB
      value.recoveryBundle
      value.recoveryInitrd
      value.recoverySlotManifest
    ];
    present = builtins.map (artifact: artifact != null) recoveryArtifacts;
  in
    value.rawDiskFilename != value.rawMetadataFilename
    && (lib.all (value: value) present || lib.all (value: !value) present));
in {
  options.aos.image.platform = lib.mkOption {
    type = lib.types.nullOr (lib.types.uniq selectedBuilderType);
    default = null;
    readOnly = true;
    internal = true;
    contributable = true;
    description = "Exact package-owned image builder selected by an ability binding.";
  };

  options.aos.image.plan = lib.mkOption {
    type = lib.types.nullOr (lib.types.uniq imagePlanType);
    default = null;
    readOnly = true;
    internal = true;
    description = "Typed immutable image plan produced by the selected package.";
  };

  options.aos.image.identity = lib.mkOption {
    type = lib.types.nullOr (lib.types.uniq imageIdentityType);
    default = null;
    readOnly = true;
    internal = true;
    description = "Acyclic identity projected by the selected image platform.";
  };

  config = {
    aos.image.identity = lib.mkIf (config.aos.image.platform != null) config.aos.image.platform.identity;
    aos.abilities = {
      instances.${consumer} = {};
      requirementTemplates.${consumer} = {
        description = "Requires one package-owned immutable image builder.";
        interface = builderInterface.identity.name;
        inherit (builderInterface.identity) abi descriptor;
      };
      requests.${consumer} = {
        requirement = consumer;
        inherit consumer;
        parameters = true;
      };
    };
  };
}
