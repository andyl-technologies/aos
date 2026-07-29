{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;

  packages = [
    "crucible-cas"
    "crucible-sim"
    "crucible-assert"
    "crucible-shmem"
    "crucible-protocol"
    "crucible-device"
    "crucible-qemu"
    "crucible-qemu-plugin"
    "crucible-guest"
    "crucible"
    "crucible-session"
    "crucible-api"
    "crucible-daemon"
    "crucible-cli"
    "crucible-harness"
  ];

  forbiddenPrefixes = ["ratchet-" "aos-nix-"];
  forbiddenExactNames = ["ratchet" "aos-nix"];
  hasForbiddenPrefix = name:
    builtins.elem name forbiddenExactNames
    || builtins.any (prefix: lib.hasPrefix prefix name) forbiddenPrefixes;

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

  dependencyTableSpecs = workspaceDeps: scope: dependencies:
    lib.mapAttrsToList (name: value: {
      inherit name scope;
      package = dependencyPackageName workspaceDeps name value;
    })
    dependencies;

  optionalTable = workspaceDeps: manifest: scope: attr:
    if builtins.hasAttr attr manifest
    then dependencyTableSpecs workspaceDeps scope manifest.${attr}
    else [];

  dependencySpecs = workspaceDeps: manifest: let
    direct =
      optionalTable workspaceDeps manifest "dependencies" "dependencies"
      ++ optionalTable workspaceDeps manifest "dev-dependencies" "dev-dependencies"
      ++ optionalTable workspaceDeps manifest "build-dependencies" "build-dependencies";
    target =
      if manifest ? target
      then
        lib.concatMap (
          targetName: let
            targetSpec = manifest.target.${targetName};
          in
            optionalTable workspaceDeps targetSpec "target.${targetName}.dependencies" "dependencies"
            ++ optionalTable workspaceDeps targetSpec "target.${targetName}.dev-dependencies" "dev-dependencies"
            ++ optionalTable workspaceDeps targetSpec "target.${targetName}.build-dependencies" "build-dependencies"
        ) (builtins.attrNames manifest.target)
      else [];
  in
    direct ++ target;

  findingsFor = workspaceDeps: manifests:
    lib.concatMap (
      package:
        lib.concatMap (
          dependency:
            lib.optionals (hasForbiddenPrefix dependency.name || hasForbiddenPrefix dependency.package) [
              "${package} has forbidden dependency `${dependency.name}` resolved as `${dependency.package}` in ${dependency.scope}"
            ]
        )
        (dependencySpecs workspaceDeps manifests.${package})
    )
    (builtins.attrNames manifests);

  realManifests =
    builtins.listToAttrs (
      map (package: {
        name = package;
        value = readManifest package;
      })
      packages
    );

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  simSource = builtins.readFile (cratesDir + "/crucible-sim/src/lib.rs");
  seamFailures =
    lib.optionals (!(hasInfix "FUTURE_RATCHET_INTEGRATION_SEAM" simSource)) [
      "crucible-sim: missing FUTURE_RATCHET_INTEGRATION_SEAM marker"
    ]
    ++ lib.optionals (!(hasInfix "crucible-sim::content-addressing" simSource)) [
      "crucible-sim: missing content-addressing seam value"
    ]
    ++ lib.optionals (!(hasInfix "no Crucible crate may depend on `ratchet-*` or `aos-nix-*`" simSource)) [
      "crucible-sim: missing standalone dependency rule documentation near seam marker"
    ];

  regressionFailures = let
    directFindings = findingsFor workspaceDependencies {
      crucible-sim = {
        dependencies.ratchet = "0.1";
      };
    };
    aliasFindings = findingsFor workspaceDependencies {
      crucible = {
        dependencies.graph.package = "aos-nix-graph";
      };
    };
    workspaceFindings = findingsFor (workspaceDependencies // {
      ratchet-store.package = "ratchet-cache";
    }) {
      crucible-api = {
        dev-dependencies.ratchet-store.workspace = true;
      };
    };
    targetFindings = findingsFor workspaceDependencies {
      crucible-qemu = {
        target."cfg(unix)".build-dependencies.helper.package = "aos-nix-helper";
      };
    };
    hasFinding = needle: findings:
      builtins.any (finding: hasInfix needle finding) findings;
  in
    lib.optionals (!(hasFinding "ratchet" directFindings)) [
      "standalone dependency regression failed to reject direct exact ratchet dependency"
    ]
    ++ lib.optionals (!(hasFinding "aos-nix-graph" aliasFindings)) [
      "standalone dependency regression failed to reject package-renamed aos-nix dependency"
    ]
    ++ lib.optionals (!(hasFinding "ratchet-cache" workspaceFindings)) [
      "standalone dependency regression failed to reject workspace-inherited ratchet dependency"
    ]
    ++ lib.optionals (!(hasFinding "target.cfg(unix).build-dependencies" targetFindings)) [
      "standalone dependency regression failed to reject target build-dependency"
    ];

  failures =
    findingsFor workspaceDependencies realManifests
    ++ seamFailures
    ++ regressionFailures;
in
  if failures != []
  then throw "crucible phase1 standalone dependency lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-standalone-dependencies";
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
            check=checks.crucible.phase1.standaloneDependencies
            gate=gate:harness-lint
            tasks=T-CRATE-15
            forbidden_prefixes=ratchet-,aos-nix-
            seam=crucible-sim::content-addressing
            RESULT
          '';
        }
      ];
    }
