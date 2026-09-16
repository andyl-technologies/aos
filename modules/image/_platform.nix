##! Exact package-selected immutable image builder projection.
{lib, ...}: let
  consumer = "image:builder";
  builderInterface = lib.abilities.interfaces.imageBuilder.interfaces.builder;
  selectedBuilderType = lib.types.submodule {
    config._module.strict = true;

    options = {
      _type = lib.mkOption {
        type = lib.types.enum ["aos-image-builder"];
        description = "Selected image-builder record discriminator.";
      };
      artifact = lib.mkOption {
        type = lib.abilities.types.artifactReference;
        description = "Checked planning output that authenticates the selected package.";
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
        type = lib.types.nonEmptyStr;
        description = "Firmware-relative path of the normal boot artifact.";
      };
      package = lib.mkOption {
        type = lib.types.pathInStore;
        description = "Authenticated package output that owns the selected image builder.";
      };
    };
  };
  nullableArtifact = lib.types.nullOr lib.types.package;
  imagePlanType = lib.types.submodule {
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
        type = lib.types.nonEmptyStr;
        description = "Filename of the compressed raw disk inside its artifact.";
      };
      rawImage = lib.mkOption {
        type = lib.types.package;
        description = "Selected provider's compressed raw disk artifact.";
      };
      rawMetadataFilename = lib.mkOption {
        type = lib.types.nonEmptyStr;
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
  };
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

  config.aos.abilities = {
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
}
