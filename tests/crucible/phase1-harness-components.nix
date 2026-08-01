{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;
  harnessPackage = "crucible-harness";
  harnessSrc = cratesDir + "/${harnessPackage}/src";
  harnessLib = builtins.readFile (harnessSrc + "/lib.rs");

  componentSpecs = [
    {
      name = "fingerprint comparator";
      module = "fingerprint";
      gate = "gate:single-vm-fingerprint";
    }
    {
      name = "divergence bisector";
      module = "divergence";
      gate = "gate:divergence-bisect";
    }
    {
      name = "replay-oracle checker";
      module = "replay_oracle";
      gate = "gate:replay-oracle";
    }
    {
      name = "ABI golden-vector runner";
      module = "abi";
      gate = "gate:abi-conformance";
    }
    {
      name = "adversarial driver";
      module = "adversarial";
      gate = "gate:adversarial-determinism";
    }
  ];

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  componentFailures =
    lib.concatMap (
      spec:
        lib.optionals (!(builtins.pathExists (harnessSrc + "/${spec.module}.rs"))) [
          "${harnessPackage}: missing module file src/${spec.module}.rs for ${spec.name}"
        ]
        ++ lib.optionals (!(hasInfix "pub mod ${spec.module};" harnessLib)) [
          "${harnessPackage}: crate root does not export module `${spec.module}` for ${spec.name}"
        ]
        ++ lib.optionals (!(hasInfix "gate: ${builtins.toJSON spec.gate}" harnessLib || hasInfix "gate: \"${spec.gate}\"" harnessLib)) [
          "${harnessPackage}: component ${spec.name} does not reference ${spec.gate}"
        ]
    )
    componentSpecs;

  workspaceManifest = builtins.fromTOML (builtins.readFile (cratesDir + "/Cargo.toml"));
  workspaceDependencies =
    if workspaceManifest ? workspace && workspaceManifest.workspace ? dependencies
    then workspaceManifest.workspace.dependencies
    else {};
  harnessManifest = builtins.fromTOML (builtins.readFile (cratesDir + "/${harnessPackage}/Cargo.toml"));

  harnessNormalDependencyFailures =
    if harnessManifest ? dependencies && harnessManifest.dependencies != {}
    then [
      "${harnessPackage}: must keep external crates as dev-dependencies only"
    ]
    else [];

  workspacePackages = builtins.filter (
    name:
      name
      != harnessPackage
      && builtins.pathExists (cratesDir + "/${name}/Cargo.toml")
  ) (builtins.attrNames (builtins.readDir cratesDir));

  dependencyPackageName = workspaceDeps: name: value:
    if builtins.isAttrs value && value ? workspace && value.workspace == true
    then
      if builtins.hasAttr name workspaceDeps && builtins.isAttrs workspaceDeps.${name} && workspaceDeps.${name} ? package
      then workspaceDeps.${name}.package
      else name
    else if builtins.isAttrs value && value ? package
    then value.package
    else name;

  dependencyTableSpecs = workspaceDeps: scope: manifest: let
    tableName = lib.last (lib.splitString "." scope);
    dependencies =
      if builtins.hasAttr tableName manifest
      then manifest.${tableName}
      else {};
  in
    lib.mapAttrsToList (name: value: {
      inherit name scope;
      package = dependencyPackageName workspaceDeps name value;
    })
    dependencies;

  productionDependencySpecs = workspaceDeps: manifest: let
    direct =
      dependencyTableSpecs workspaceDeps "dependencies" manifest
      ++ dependencyTableSpecs workspaceDeps "build-dependencies" manifest;
    target =
      if manifest ? target
      then
        lib.concatMap (
          targetName: let
            targetSpec = manifest.target.${targetName};
          in
            dependencyTableSpecs workspaceDeps "target.${targetName}.dependencies" targetSpec
            ++ dependencyTableSpecs workspaceDeps "target.${targetName}.build-dependencies" targetSpec
        ) (builtins.attrNames manifest.target)
      else [];
  in
    direct ++ target;

  harnessDependencyFailuresFor = workspaceDeps: manifests:
    lib.concatMap (
      package:
        lib.concatMap (
          dependency:
            lib.optionals (dependency.package == harnessPackage) [
              "${package}: production dependency `${dependency.name}` reaches ${harnessPackage} in ${dependency.scope}"
            ]
        ) (productionDependencySpecs workspaceDeps manifests.${package})
    ) (builtins.attrNames manifests);

  realManifests = builtins.listToAttrs (
    map (package: {
      name = package;
      value = builtins.fromTOML (builtins.readFile (cratesDir + "/${package}/Cargo.toml"));
    })
    workspacePackages
  );

  dependencyRegressionFailures = let
    directFindings = harnessDependencyFailuresFor workspaceDependencies {
      crucible-api = {
        dependencies.harness.package = harnessPackage;
      };
    };
    targetFindings = harnessDependencyFailuresFor workspaceDependencies {
      crucible-daemon = {
        target."cfg(unix)"."build-dependencies".harness.package = harnessPackage;
      };
    };
    workspaceFindings = harnessDependencyFailuresFor (workspaceDependencies
      // {
        harness = {
          package = harnessPackage;
        };
      }) {
      crucible-session = {
        target."cfg(unix)".dependencies.harness.workspace = true;
      };
    };
  in
    lib.optionals (directFindings == []) [
      "harness dependency regression failed to reject a direct production dependency"
    ]
    ++ lib.optionals (targetFindings == []) [
      "harness dependency regression failed to reject a target-specific build dependency"
    ]
    ++ lib.optionals (workspaceFindings == []) [
      "harness dependency regression failed to reject a workspace-inherited production dependency"
    ];

  failures =
    componentFailures
    ++ harnessNormalDependencyFailures
    ++ dependencyRegressionFailures
    ++ harnessDependencyFailuresFor workspaceDependencies realManifests;
in
  if failures != []
  then throw "crucible phase1 harness-components lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-harness-components";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.harnessComponents
            tasks=T-CRATE-11
            components=fingerprint,divergence,replay_oracle,abi,adversarial
            dev_dependency_only=true
            RESULT
          '';
        }
      ];
    }
