##! Evaluates one package deployment scope without building or activating it.
{
  lib,
  system,
}: let
  moduleLib = import ../build/package-modules.nix {};
  artifactLib = import ./artifacts.nix {};
in
  {
    scope,
    packages ? [],
    packageModules ? moduleLib.closure packages,
    packageArtifacts ? moduleLib.payloads packages,
    modules ? [],
    operatorModules ? [],
    runtimeModules ? [],
    packageImportRoots ? {},
    evaluationInputs ? [],
    evaluationInput ? null,
  }: let
    records = moduleLib.canonicalize packageModules;
    evaluated = lib.evalModules {
      inherit lib operatorModules runtimeModules packageImportRoots;
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
            # A caller may retain a descriptor of evaluation inputs before this
            # fixed point runs. It never contains the resulting graph itself.
            _module.args.evaluationInput = evaluationInput;
          }
        ]
        ++ modules;
    };
    documentation = import ../effects/documentation.nix {inherit lib;};
    declarations = builtins.map (declaration: {
      inherit (declaration) path owner description type visibility readOnly extensible;
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
    evaluated
    // {
      documentation = {
        schema = "aos.module.documentation";
        inherit scope system;
        packages = builtins.attrValues (builtins.foldl' (result: artifact: let
          identity = {inherit (artifact) name version;};
        in
          if result ? ${artifact.name} && result.${artifact.name} != identity
          then throw "Package '${artifact.name}' has conflicting documentation identities."
          else result // {${artifact.name} = identity;}) {}
        (packageArtifacts ++ builtins.map (record: record.artifacts.package) records));
        options = declarations;
        abilities = documentation.abilities evaluated.config.aos.abilities;
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
