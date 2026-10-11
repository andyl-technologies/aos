##! Evaluates one package deployment scope without building or activating it.
{
  lib,
  system,
}: let
  moduleLib = import ../build/package-modules.nix {};
  artifactLib = import ./artifacts.nix {};
  compatibility = import ./release-compatibility.nix {inherit lib;};
in
  {
    scope,
    packages ? [],
    packageModules ? moduleLib.closure packages,
    packageArtifacts ? moduleLib.payloads packages,
    packageReleases ? map artifactLib.releaseIdentity packages,
    moduleRequirements ? compatibility.requirements packages,
    osRelease ? null,
    osRequirements ? compatibility.osRequirements packages,
    enforceOsRequirements ? false,
    modules ? [],
    operatorModules ? [],
    runtimeModules ? [],
    packageImportRoots ? {},
    evaluationInputs ? [],
    evaluationInput ? null,
    checkDefinitions ? true,
  }: let
    records = moduleLib.canonicalize packageModules;
    # Retained envelope metadata supplies policy for payloads without modules too.
    releaseIdentities = packageReleases ++ map artifactLib.releaseIdentity records;
    selectedIdentities =
      map (artifact: {inherit (artifact) name version;})
      (packageArtifacts ++ map (record: record.artifacts.package) records);
    releaseMetadata = builtins.foldl' (result: identity: let
      coordinate = {inherit (identity) name version;};
      canonical = artifactLib.releaseIdentity identity;
    in
      if !(builtins.elem coordinate selectedIdentities)
      then throw "Package '${identity.name}' release metadata does not match a selected artifact."
      else if builtins.removeAttrs identity ["name" "version" "versionRequirement"] != {}
      then throw "Package '${identity.name}' release metadata is not canonical."
      else if result ? ${identity.name} && result.${identity.name} != canonical
      then throw "Package '${identity.name}' has conflicting release requirements."
      else result // {${identity.name} = canonical;}) {}
    releaseIdentities;
    releaseRequirements = lib.unique (osRequirements
      ++ builtins.concatLists (map (record:
        lib.optional ((record.osVersion or null) != null) {
          owner = record.name;
          inherit (record) osVersion;
        })
      records));
    evaluated = lib.evalModules {
      inherit lib operatorModules runtimeModules packageImportRoots;
      # Discovery projects declared options before all package modules are
      # available. Publication always evaluates the complete set with checks.
      enforcePackageAuthorship = checkDefinitions;
      enforceRuntimeDeclarations = checkDefinitions;
      packageModules = builtins.map (record:
        record
        // {
          module = (packageImportRoots.${builtins.unsafeDiscardStringContext record.configRoot} or record.configRoot) + "/module.nix";
        })
      records;
      modules =
        [
          ../effects/module.nix
          {
            aos.activation.scope = scope;
            _module.strict = lib.mkForce checkDefinitions;
            # A caller may retain a descriptor of evaluation inputs before this
            # fixed point runs. It never contains the resulting graph itself.
            _module.args.evaluationInput = evaluationInput;
          }
        ]
        ++ modules;
    };
    documentation = import ../effects/documentation.nix {inherit lib;};
    declarations = builtins.map (declaration: {
      inherit (declaration) path owner description type visibility readOnly extensible hasDefault;
    }) (builtins.filter (declaration: declaration.path != [] && builtins.head declaration.path != "_module") evaluated._optionDecls);
    graph = evaluated._withoutProvenance evaluated.config.aos.activation.graph;
    inputs = artifactLib.graphInputs {
      inherit graph packageArtifacts evaluationInputs;
      packageModules = records;
    };
    selectedArtifacts = builtins.map (artifact:
      (artifactLib.metadata artifact)
      // {
        path = (artifactLib.value artifact).outPath;
      })
    packageArtifacts;
  in
    assert compatibility.checkSeeds packages;
    assert !enforceOsRequirements || compatibility.checkOsRequirements releaseRequirements osRelease;
      evaluated
      // {
        documentation = {
          schema = "aos.module.documentation";
          inherit scope system;
          packages = builtins.attrValues (builtins.foldl' (result: artifact: let
            identity = releaseMetadata.${artifact.name} or (artifactLib.releaseIdentity artifact);
          in
            if identity.version != artifact.version || (result ? ${artifact.name} && result.${artifact.name} != identity)
            then throw "Package '${artifact.name}' has conflicting documentation identities."
            else result // {${artifact.name} = identity;}) {}
          (packageArtifacts ++ builtins.map (record: record.artifacts.package) records));
          options = declarations;
          abilities = documentation.abilities evaluated.config.aos.abilities;
          inherit osRelease;
          osRequirements = releaseRequirements;
          moduleRequirements = lib.unique (moduleRequirements
            ++ builtins.concatLists (map (record:
              map (requirement: requirement // {owner = record.name;}) (record.moduleRequirements or []))
            records));
        };
        deployment = {
          schema = "aos.package.transaction";
          inherit scope system;
          artifacts = selectedArtifacts;
          inherit inputs;
          packages = builtins.map (record:
            record
            // {
              artifacts = {
                package = artifactLib.metadata record.artifacts.package;
                dependencies = builtins.mapAttrs (_: artifactLib.metadata) record.artifacts.dependencies;
              };
            })
          records;
          inherit graph;
          retire = evaluated.config.aos.activation.retire;
        };
      }
