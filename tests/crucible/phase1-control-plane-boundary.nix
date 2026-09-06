{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;

  readManifest = package: builtins.fromTOML (builtins.readFile (cratesDir + "/${package}/Cargo.toml"));

  workspaceManifest = builtins.fromTOML (builtins.readFile (cratesDir + "/Cargo.toml"));
  workspaceDependencies =
    if workspaceManifest ? workspace && workspaceManifest.workspace ? dependencies
    then workspaceManifest.workspace.dependencies
    else {};

  dependencyPackageName = workspaceDeps: name: value:
    if builtins.isAttrs value && value ? workspace && value.workspace == true
    then
      if builtins.hasAttr name workspaceDeps && builtins.isAttrs workspaceDeps.${name} && workspaceDeps.${name} ? package
      then workspaceDeps.${name}.package
      else name
    else if builtins.isAttrs value && value ? package
    then value.package
    else name;

  dependencySpecs = workspaceDeps: manifest: let
    dependencyTableSpecs = scope: dependencies:
      lib.mapAttrsToList (name: value: {
        inherit name scope;
        package = dependencyPackageName workspaceDeps name value;
      })
      dependencies;
    direct =
      if manifest ? dependencies
      then dependencyTableSpecs "dependencies" manifest.dependencies
      else [];
    target =
      if manifest ? target
      then
        lib.concatMap (
          targetName: let
            targetSpec = manifest.target.${targetName};
          in
            if targetSpec ? dependencies
            then dependencyTableSpecs "target.${targetName}.dependencies" targetSpec.dependencies
            else []
        ) (builtins.attrNames manifest.target)
      else [];
  in
    direct ++ target;

  allowedEntrypoints = ["crucible-api" "crucible-session" "crucible-daemon"];
  # RFC-0020 04a: the daemon owns the sole-writer actor and the local
  # executor, so it hosts the engine directly like the session actor.
  engineHosts = ["crucible-session" "crucible-daemon"];
  # Crates below the engine: data models, stores, protocols, and QEMU
  # process control. Depending on one of them reaches no engine.
  substrateCrates = [
    "crucible-assert"
    "crucible-campaign"
    "crucible-cas"
    "crucible-debug-gateway"
    "crucible-device"
    "crucible-guest"
    "crucible-harness"
    "crucible-linux-resource"
    "crucible-protocol"
    "crucible-qemu"
    "crucible-qemu-plugin"
    "crucible-s3-store"
    "crucible-shmem"
    "crucible-sim"
  ];

  findingsFor = workspaceDeps: manifests: packages:
    lib.concatMap (
      package: let
        manifest = manifests.${package};
      in
        lib.concatMap (
          dependency:
            if dependency.package == "crucible" && !(builtins.elem package engineHosts)
            then [
              "${package} has direct dependency `${dependency.name}` on the engine crate in ${dependency.scope}"
            ]
            else if
              lib.hasPrefix "crucible-" dependency.package
              && !(builtins.elem dependency.package allowedEntrypoints)
              && !(builtins.elem dependency.package substrateCrates)
            then [
              "${package} may reach the engine only through crucible-api/crucible-session, found `${dependency.package}`"
            ]
            else []
        )
        (dependencySpecs workspaceDeps manifest)
    )
    packages;

  controlPlaneCrates = ["crucible-cli" "crucible-daemon"];

  realManifests = builtins.listToAttrs (
    map (package: {
      name = package;
      value = readManifest package;
    })
    controlPlaneCrates
  );

  regressionFailures = let
    findings = findingsFor workspaceDependencies {
      crucible-cli = {
        dependencies.engine = {
          package = "crucible";
        };
      };
    } ["crucible-cli"];
  in
    if findings != []
    then []
    else [
      "control-plane boundary regression failed to reject direct engine dependency"
    ];

  targetRegressionFailures = let
    findings = findingsFor workspaceDependencies {
      crucible-cli = {
        target."cfg(unix)".dependencies.engine = {
          package = "crucible";
        };
      };
    } ["crucible-cli"];
  in
    if findings != []
    then []
    else [
      "control-plane boundary regression failed to reject target-specific engine dependency"
    ];

  workspaceRegressionFailures = let
    findings = findingsFor (workspaceDependencies
      // {
        engine = {
          package = "crucible";
        };
      }) {
      crucible-cli = {
        dependencies.engine.workspace = true;
      };
    } ["crucible-cli"];
  in
    if findings != []
    then []
    else [
      "control-plane boundary regression failed to reject workspace-inherited engine dependency"
    ];

  allowedRegressionFailures = let
    findings = findingsFor workspaceDependencies {
      crucible-daemon = {
        dependencies = {
          crucible-api = {};
          session.package = "crucible-session";
        };
      };
    } ["crucible-daemon"];
  in
    if findings == []
    then []
    else [
      "control-plane boundary regression rejected allowed API/session dependencies: ${builtins.concatStringsSep "; " findings}"
    ];

  failures =
    findingsFor workspaceDependencies realManifests controlPlaneCrates
    ++ regressionFailures
    ++ targetRegressionFailures
    ++ workspaceRegressionFailures
    ++ allowedRegressionFailures;
in
  if failures != []
  then throw "crucible phase1 control-plane boundary lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-control-plane-boundary";
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
            check=checks.crucible.phase1.controlPlaneBoundary
            gate=gate:control-responsive
            tasks=T-CRATE-9
            rust_test=crucible-harness::control_plane_boundary
            RESULT
          '';
        }
      ];
    }
