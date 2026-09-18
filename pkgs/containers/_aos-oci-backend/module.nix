##! Concrete OCI artifact construction selected by the backend package.
{
  abilitySelection ? null,
  config,
  lib,
  packageArtifactFor,
  ...
}: let
  schema = import ./container/schema.nix;
  backendInterface = lib.abilities.interfaces.artifactBackend.interfaces.backend;
  backendArtifact = lib.abilities.packageOutput {};
  selectedBindings =
    if abilitySelection == null
    then []
    else abilitySelection.bindingsForImplementation "artifact-backend";
  selectedBinding =
    if builtins.length selectedBindings > 1
    then throw "the OCI artifact backend implementation has several selected bindings"
    else if selectedBindings == []
    then null
    else builtins.head selectedBindings;
  selected =
    if selectedBinding == null
    then false
    else
      config.aos.abilities.environment
      != null
      && config.aos.abilities.environment.stage == "host";
  providerReady =
    selected
    && selectedBinding.implementation.value.provide != null;

  packageProjectionsFor = packages:
    builtins.map
    lib.abilities.authenticatedPackageProjectionFor
    (lib.abilities.canonicalizeAuthenticatedPackages (builtins.filter
      (package:
        builtins.isAttrs package
        && package ? abilities
        && package ? contract
        && package ? module
        && package.contract.value.package_module != null)
      packages));
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
  selectedBackendOutput =
    config.aos.abilities.compositionOutputs.${selectedBinding.binding.request}.artifact-reference.value
    or null;
  authoredBackend = {
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
  backendProjectionReady =
    selectedBackendOutput
    != null
    && selectedBackendOutput == backendArtifact;
  checkedProviderReady =
    providerReady
    && (
      if backendProjectionReady
      then true
      else throw "selected artifact backend projection differs from its checked planning output"
    );
in {
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
      implementations.artifact-backend = {
        description = "Builds static contracts and OCI artifacts from checked package origins.";
        interface = backendInterface.identity;
        artifact = backendArtifact;
        methods = [];
        guarantees = [];
        providerModule = {
          artifact = lib.abilities.packageOutput {output = "module";};
          path = "provider.nix";
        };
      };
      instances = lib.mkIf selected {
        artifact-backend-provider.implementation = "artifact-backend";
      };
    };

    aos.artifacts.backend = lib.mkIf checkedProviderReady (authoredBackend // {artifact = selectedBackendOutput;});
    aos.containers = lib.mkIf selected {
      enable = true;
      default = "aos";
    };
  };
}
