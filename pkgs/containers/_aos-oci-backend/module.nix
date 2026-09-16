##! Concrete OCI artifact construction selected by the backend package.
{
  abilitySelection ? null,
  config,
  lib,
  packageArtifactFor,
  ...
}: let
  raw = {
    name = "package artifact backend";
    description = "package-owned artifact backend implementation";
    check = _: true;
    merge = location: definitions:
      if builtins.length definitions == 1
      then (builtins.head definitions).value
      else throw "The option '${builtins.concatStringsSep "." location}' requires exactly one selected artifact backend.";
  };
  schema = import ./container/schema.nix;
  backendInterface = lib.abilities.declareInterface {
    name = "aos.artifacts.backend";
    abi = 1;
    description = "Selects one package-owned artifact construction backend.";
    requestType = lib.abilities.types.boolean;
    outputs = {};
    methods = {};
    lifecycle.persistentDeleteMethod = null;
    guarantees = [];
    aggregation = {
      scope = "provider-instance";
      key = "slot";
      rejectSlotCollisions = true;
      mergeContract = null;
      controllerGroup = "artifact-backend";
    };
  };
  backendIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration backendInterface
  );
  backendArtifact = lib.abilities.packageOutput {};
  selected =
    config.aos.abilities.environment != null
    && abilitySelection != null
    && abilitySelection.isImplementationSelected "artifact-backend";

  checkedProjectionFor = package: let
    owner = package.contract.value.package;
  in {
    _type = "aos-checked-package-projection";
    payload = package;
    inherit (package) contract;
    origin = {
      _type = "aos-authenticated-package-origin";
      package = {
        inherit (owner) name version;
        document = builtins.toString package.contract.document;
      };
      packageArtifactFor = selector:
        lib.abilities.authenticatedPackageOutputFor {
          inherit package selector;
        };
    };
  };
  packageProjectionsFor = packages:
    builtins.map checkedProjectionFor (builtins.filter
      (package:
        builtins.isAttrs package
        && package ? abilities
        && package ? contract
        && package ? module
        && package.contract.value.package_module != null)
      packages);
  platformFor = targetPlatform:
    if targetPlatform.os == "linux" && targetPlatform.cpu == "x86_64"
    then {
      os = "linux";
      architecture = "amd64";
    }
    else if targetPlatform.os == "linux" && targetPlatform.cpu == "aarch64"
    then {
      os = "linux";
      architecture = "arm64";
    }
    else
      throw
      "aos-oci-backend does not support target ${targetPlatform.cpu}-${targetPlatform.os}";
  mkOci = {
    lib,
    buildPackages,
    mkReferenceGraph,
  }:
    import ./oci {
      inherit lib mkReferenceGraph;
      inherit (buildPackages) mkDerivation coreutils findutils gzip jq tar;
      abilityContractValidator = buildPackages.aos-ability-contract-validator;
    };
  backend = {
    _type = "aos-package-artifact-backend";
    name = "oci";
    package = packageArtifactFor backendArtifact;

    buildStaticContract = args: let
      oci = mkOci {
        inherit (args) lib buildPackages mkReferenceGraph;
      };
    in
      oci.mkStaticAbilityContract {
        inherit
          (args)
          pname
          artifactClass
          executionStage
          ;
        packageProjections = packageProjectionsFor args.packageRoots;
        runtimeRoots = args.packageRoots;
        platform = platformFor args.targetPlatform;
        targetPlatform = {
          system = args.targetPlatform.os;
          architecture = args.targetPlatform.cpu;
        };
      };

    defaultDefinition = args:
      import ./aos-definition.nix {
        inherit (args) lib pkgs goldenRoots;
        evidenceOverrides = args.evidenceOverrides or [];
        platform = platformFor args.targetPlatform;
      };

    buildContainer = args: let
      oci = mkOci {
        inherit (args) lib buildPackages mkReferenceGraph;
      };
    in
      import ./container/build.nix {
        buildPkgs = args.buildPackages;
        inherit
          (args)
          lib
          pkgs
          runtimeClosureAudit
          container
          systemIdentity
          definitionAttribute
          ;
        packageProjections = packageProjectionsFor args.container.packageRoots;
        inherit oci;
      };
  };
in {
  options = {
    aos.artifacts.backend = lib.mkOption {
      type = raw;
      readOnly = true;
      internal = true;
      description = "Selected package-owned static-contract builder.";
    };

    aos.containers = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Whether the selected OCI backend produces associated container artifacts.";
      };

      default = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Name of the OCI container associated with this system variant by default.";
      };

      definitions = lib.mkOption {
        type = lib.types.attrsOf (lib.types.submodule schema);
        default = {};
        contributable = true;
        description = "OCI artifact definitions owned by the selected backend.";
      };
    };
  };

  config = {
    aos.abilities = {
      interfaces.artifact-backend = backendInterface;
      implementations.artifact-backend = {
        description = "Builds static contracts and OCI artifacts from checked package origins.";
        interface = "artifact-backend";
        artifact = backendArtifact;
        methods = [];
        guarantees = [];
      };
      requirementTemplates.artifact-backend = {
        description = "Requires one package-owned artifact construction backend.";
        interface = backendIdentity.name;
        inherit (backendIdentity) abi descriptor;
      };
      instances = lib.mkIf (config.aos.abilities.environment != null) (
        {
          artifact-backend-consumer = {};
        }
        // lib.optionalAttrs selected {
          artifact-backend-provider.implementation = "artifact-backend";
        }
      );
      requests = lib.mkIf (config.aos.abilities.environment != null) {
        artifact-backend = {
          requirement = "artifact-backend";
          consumer = "artifact-backend-consumer";
          parameters = true;
        };
      };
    };

    aos.artifacts.backend = lib.mkIf selected backend;
    aos.containers = lib.mkIf selected {
      enable = true;
      default = "aos";
    };
  };
}
