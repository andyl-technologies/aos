##! Package-owned OCI artifact composition selected through ordinary modules.
{
  config,
  lib,
  package,
  ...
}: let
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
  authoredBackend = {
    _type = "aos-package-artifact-backend";
    name = "oci";
    inherit package;

    buildDeploymentArtifact = args:
      args.ociTools.mkDeploymentArtifact {
        inherit
          (args)
          pname
          artifactClass
          executionStage
          ;
        pkgs = args.pkgs;
        packages = args.packages;
        packageArtifacts = args.packageArtifacts or (lib.packageModules.payloads args.packages);
        evaluated = args.evaluated or null;
        configuration = args.configuration or [];
        runtimeConfiguration = args.runtimeConfiguration or [];
        evaluationInput = args.evaluationInput or null;
        osRelease =
          args.osRelease or (
            if config.aos ? system
            then {inherit (config.aos.system) name version;}
            else null
          );
        operatorModules = args.operatorModules or [];
        scope = args.scope;
        runtimeRoots = args.packageRoots;
        platform = platformFor args.targetPlatform;
        targetPlatform = {
          system = args.targetPlatform.os;
          architecture = args.targetPlatform.cpu;
        };
      };

    defaultDefinition = args:
      import ./aos-definition.nix {
        inherit (args) lib pkgs systemPackageSlice;
        evidenceOverrides = args.evidenceOverrides or [];
        platform = platformFor args.targetPlatform;
      };

    buildContainer = args:
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
        operatorModules = args.operatorModules or [];
        configuration = args.configuration or [];
        runtimeConfiguration = args.runtimeConfiguration or [];
        evaluationInput = args.evaluationInput or null;
        oci = args.pkgs.ociTools;
      };
  };
in {
  imports = [./backend-option.nix];

  options = {
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

      systemPackageSlice = lib.mkOption {
        type = lib.types.listOf lib.types.package;
        default = [];
        apply = lib.uniqueBy builtins.toString;
        # Derivations are image-composition inputs, not portable runtime values.
        internal = true;
        description = ''
          Packages selected from the evaluated system profile for the default
          container. The backend adds its runtime core and AOS CLI roots.
        '';
      };

      definitions = lib.mkOption {
        type = lib.types.attrsOf (lib.types.submodule schema);
        default = {};
        internal = true;
        extensible = true;
        description = "OCI artifact definitions owned by the selected backend.";
      };
    };
  };

  config = {
    assertions = lib.concatMap (
      name:
        map (check: {
          inherit (check) assertion;
          message = "aos.containers.definitions.${name}: ${check.message}";
        })
        config.aos.containers.definitions.${name}.assertions
    ) (builtins.attrNames config.aos.containers.definitions);

    aos.artifacts.backend = authoredBackend // {artifact = package;};
    aos.containers = {
      enable = lib.mkDefault true;
      default = lib.mkDefault "aos";
    };
  };
}
