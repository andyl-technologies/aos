##! Concrete OCI artifact construction selected by the backend package.
{
  lib,
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
          packageProjections
          runtimeRoots
          ;
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
        inherit (args)
          lib
          pkgs
          buildPackages
          runtimeClosureAudit
          container
          systemIdentity
          definitionAttribute
          packageProjections
          ;
        inherit oci;
      };
  };
in {
  options = {
    aos.artifacts.staticContractBackend = lib.mkOption {
      type = raw;
      readOnly = true;
      internal = true;
      description = "Selected package-owned static-contract builder.";
    };

    aos.containers = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Whether the selected OCI backend produces associated container artifacts.";
      };

      default = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = "aos";
        description = "Name of the OCI container associated with this system variant by default.";
      };

      definitions = lib.mkOption {
        type = lib.types.attrsOf (lib.types.submodule schema);
        default = {};
        contributable = true;
        description = "OCI artifact definitions owned by the selected backend.";
      };

      backend = lib.mkOption {
        type = raw;
        readOnly = true;
        internal = true;
        description = "Selected package-owned OCI container builder.";
      };
    };
  };

  config = {
    aos.artifacts.staticContractBackend = backend;
    aos.containers.backend = backend;
  };
}
