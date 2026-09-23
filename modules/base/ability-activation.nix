##! Deployment inputs for structured ability activation.
{
  config,
  pkgs,
  lib,
  ...
}: let
  abilityTypes = lib.abilities.types;
  storePath = abilityTypes.refined {
    name = "Nix store path";
    description = "a canonical Nix store output path";
    type = abilityTypes.string {
      maxLength = 4096;
      syntax = null;
    };
    constraints = [
      {
        kind = "string-pattern";
        pattern = "/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+";
      }
    ];
  };
  narHash = abilityTypes.refined {
    name = "NAR hash";
    description = "a canonical SHA-256 NAR hash";
    type = abilityTypes.string {
      maxLength = 59;
      syntax = null;
    };
    constraints = [
      {
        kind = "string-pattern";
        pattern = "sha256:[0-9abcdfghijklmnpqrsvwxyz]{52}";
      }
    ];
  };
  storeHash = abilityTypes.refined {
    name = "store path hash";
    description = "a canonical Nix store-path hash component";
    type = abilityTypes.string {
      maxLength = 32;
      syntax = null;
    };
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[0-9abcdfghijklmnpqrsvwxyz]{32}";
      }
    ];
  };
  sidecar = abilityTypes.record {
    fields = {
      store_path = storePath;
      nar_hash = narHash;
      nar_size = abilityTypes.integer {
        minimum = 1;
        maximum = abilityTypes.limits.maxSafeInteger;
      };
      references = {
        type = abilityTypes.list {
          element = storeHash;
          maxItems = 100000;
          unique = true;
          canonicalOrder = true;
        };
        default = [];
      };
      document = abilityTypes.relativePath;
      document_sha256 = abilityTypes.digest;
      document_size = abilityTypes.integer {
        minimum = 1;
        maximum = abilityTypes.limits.maxDocumentBytes;
      };
    };
  };
  executionObserver = abilityTypes.record {
    fields = {
      request = abilityTypes.declarationKey;
      resource = abilityTypes.resolvedResourceReference;
      socket = abilityTypes.executionPath;
    };
  };
  requiredFeatures = [
    "abilities-v1"
    "ability-effects-v1"
    "native-platform-policy-v1"
    "native-resource-map-v1"
  ];
  requiredFeaturesType = lib.types.addCheck (abilityTypes.list {
    element = abilityTypes.enum requiredFeatures;
    maxItems = builtins.length requiredFeatures;
    unique = true;
  }) (value: value == requiredFeatures);
  activationInput = abilityTypes.record {
    fields = {
      schema = {
        type = abilityTypes.enum ["aos.contract.activation-input/v1"];
        default = "aos.contract.activation-input/v1";
      };
      required_features = {
        type = requiredFeaturesType;
        default = requiredFeatures;
      };
      desired_state = sidecar;
      authenticated_policy_set = sidecar;
      execution_observer = {
        type = executionObserver;
        optional = true;
      };
    };
  };
  selectedArtifactBackend = config.aos.artifacts.backend;
  artifactBackend =
    if
      builtins.isAttrs selectedArtifactBackend
      && (selectedArtifactBackend._type or null) == "aos-package-artifact-backend"
    then selectedArtifactBackend
    else throw "host static ability contracts require one selected package-owned artifact backend";
  targetPlatform = {
    os = pkgs.stdenv.hostPlatform.constraints.os;
    cpu = pkgs.stdenv.hostPlatform.constraints.cpu;
    abi = pkgs.stdenv.hostPlatform.constraints.abi;
    features = pkgs.stdenv.hostPlatform.constraints.features;
  };
  staticAbilityContractBuild = artifactBackend.buildStaticContract {
    inherit lib targetPlatform;
    inherit (pkgs) ociTools;
    pname = "aos-host-static-abilities";
    artifactClass = "bootable";
    executionStage = "host";
    packageRoots = config.environment.systemPackages;
  };
  staticAbilityContractSource = staticAbilityContractBuild.artifact;
  # The base library captures the image-built contract under this key. Runtime
  # evaluation reuses that path and leaves the build-only package thunks lazy.
  staticAbilityContract =
    if config.aos.config.frozenArtifacts ? "host-static-ability-contract"
    then let
      path = config.aos.config.frozenArtifacts.host-static-ability-contract;
    in {
      type = "derivation";
      name = "host-static-ability-contract";
      outPath = path;
      __toString = _: path;
    }
    else staticAbilityContractSource;
in {
  options = {
    aos.abilities.activationInput = lib.mkOption {
      type = lib.types.nullOr activationInput;
      default = null;
      description = ''
        Immutable desired-state and authenticated-policy sidecars used to plan
        structured ability effects. The on-host evaluator replaces package
        coordinates from the authenticated runtime resolution and validates
        the complete activation input before publishing a configuration generation.
      '';
    };

    aos.boot.initrd.abilityHandoff.enable = lib.mkEnableOption ''
      the signed initrd-to-host ability ownership handoff
    '';

    system.build.staticAbilityContract = lib.mkOption {
      type = lib.types.package;
      readOnly = true;
      description = ''
        Static host-stage ability declarations in the immutable system image.
        Required runtime inputs remain explicit deployment obligations and the
        contract carries no runtime grants.
      '';
    };
  };

  config = {
    system.build.staticAbilityContract = staticAbilityContract;
    aos.boot.initrd.packageRoots = lib.mkIf config.aos.boot.initrd.abilityHandoff.enable [
      pkgs.aos
      # The initrd configuration materializer runs from this separate output.
      pkgs.aos.packageRuntime
    ];
  };
}
