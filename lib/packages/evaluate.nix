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
    packageArtifacts ?
      if packages == []
      then artifactLib.unique (builtins.concatLists (builtins.map (record: [record.artifacts.package] ++ builtins.attrValues record.artifacts.dependencies) packageModules))
      else moduleLib.payloads packages,
    modules ? [],
    operatorModules ? [],
    runtimeModules ? [],
    packageImportRoots ? {},
    evaluationInputs ? [],
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
      modules = [../effects/module.nix {aos.activation.scope = scope;}] ++ modules;
    };
    documentation = import ../effects/documentation.nix {inherit lib;};
    declarations = builtins.map (declaration: {
      inherit (declaration) path owner description type visibility readOnly extensible;
    }) (builtins.filter (declaration: declaration.path != [] && builtins.head declaration.path != "_module") evaluated._optionDecls);
  in
    evaluated
    // {
      documentation = {
        options = declarations;
        abilities = documentation.abilities evaluated.config.aos.abilities;
      };
      deployment = {
        schema = "aos.package.transaction";
        inherit scope system;
        artifacts = packageArtifacts;
        inputs = evaluationInputs;
        packages = records;
        graph = evaluated.config.aos.activation.graph;
      };
    }
