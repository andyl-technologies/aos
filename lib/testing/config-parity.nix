# lib/testing/config-parity.nix - expose flat/module migration parity.
#
# This gate has two independent halves:
#
# 1. Nix evaluates the migrated fixture through the typed expose
#    module and compares that projection to metadata emitted by the live legacy
#    `_expose-renderer.nix` path.  This catches schema/default/action drift.
# 2. `golden_config_artifact.rs` consumes the exact JSON projection pinned here
#    and renders both paths through production serialization, comparing bytes
#    and reload/restart sets.  It also exercises mixed, shuffled, and tampered
#    projections.
{
  pkgs,
  lib,
}: let
  exposeModule = import ../../pkgs/build-support/_expose-module.nix {inherit lib;};
  moduleFixture = ./fixtures/expose-parity/module.nix;
  moduleProjectionFile = ../../crates/aos-package/tests/fixtures/golden_config_artifact/web.module-eval.json;
  golden = ../../crates/aos-package/tests/fixtures/golden_config_artifact/web.golden;

  evaluated = lib.evalModules {
    modules = [
      {
        options.packageExpose = exposeModule.exposeOptions;
        options.parityDesired = lib.mkOption {
          type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
          default = {};
        };
        config._module.strict = true;
      }
      moduleFixture
    ];
    inherit lib;
  };
  moduleProjection = {
    artifacts = builtins.map
      (artifact: builtins.removeAttrs artifact ["_module"])
      evaluated.config.packageExpose.config.artifacts;
    desired = evaluated.config.parityDesired;
  };
  pinnedProjection = builtins.fromJSON (builtins.readFile moduleProjectionFile);

  legacyPackage = pkgs.mkDerivation {
    pname = "config-parity-web";
    version = "0";
    src = null;
    phases = [{
      name = "install";
      script = ''
        mkdir -p "$out"
      '';
    }];
    expose = {
      units."web.service" = {
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.coreutils}/bin/true";
        };
      };
      config.artifacts = pinnedProjection.artifacts;
    };
  };
  flatArtifacts = legacyPackage.expose.passthru.manifest.expose.config.artifacts;

  actionsFor = artifacts: {
    reload = lib.sort builtins.lessThan (lib.unique (lib.concatMap
      (artifact:
        if artifact.reload == "reload"
        then artifact.units
        else [])
      artifacts));
    restart = lib.sort builtins.lessThan (lib.unique (lib.concatMap
      (artifact:
        if artifact.reload == "restart"
        then artifact.units
        else [])
      artifacts));
  };
  flatActions = actionsFor flatArtifacts;
  moduleActions = actionsFor moduleProjection.artifacts;

  tamperedArtifacts = builtins.map
    (artifact:
      if artifact.name == "env"
      then artifact // {reload = "restart";}
      else artifact)
    moduleProjection.artifacts;
  tamperDetected = actionsFor tamperedArtifacts != flatActions;

  # A mixed generation contains a migrated package and a non-migrated flat
  # package.  Their final namespaces and action sets are disjoint, so union is
  # deterministic regardless of evaluation/input order.
  flatOnlyArtifacts = [{
    name = "legacy";
    path = "/etc/aos/packages/legacy/legacy.env";
    format = "env";
    required = [];
    optional = ["VALUE"];
    units = ["legacy.service"];
    reload = "restart";
  }];
  mixedPaths = lib.sort builtins.lessThan (
    (builtins.map (artifact: artifact.path) moduleProjection.artifacts)
    ++ (builtins.map (artifact: artifact.path) flatOnlyArtifacts)
  );
  mixedActions = {
    reload = lib.unique (moduleActions.reload ++ (actionsFor flatOnlyArtifacts).reload);
    restart = lib.unique (moduleActions.restart ++ (actionsFor flatOnlyArtifacts).restart);
  };
  reversedMixedPaths = lib.sort builtins.lessThan (
    (builtins.map (artifact: artifact.path) (lib.reverseList flatOnlyArtifacts))
    ++ (builtins.map (artifact: artifact.path) (lib.reverseList moduleProjection.artifacts))
  );

  fixtureHasNoAuthoredRequires =
    builtins.all
    (line: builtins.match ".*expose[.]requires.*" line == null)
    (lib.splitString "\n" (builtins.readFile moduleFixture));
  assertions =
    lib.throwIfNot
    (moduleProjection == pinnedProjection)
    "config-parity: module evaluation diverges from the projection consumed by the Rust byte oracle"
    (lib.throwIfNot
      (flatArtifacts == moduleProjection.artifacts)
      "config-parity: module-evaluated artifact metadata differs from the live legacy expose renderer"
      (lib.throwIfNot
        (flatActions == moduleActions)
        "config-parity: module-evaluated reload/restart sets differ from the legacy expose renderer"
        (lib.throwIfNot tamperDetected
          "config-parity: policy tampering did not make the parity oracle fail"
          (lib.throwIfNot
            (mixedPaths == reversedMixedPaths
              && mixedActions == {
                reload = ["web.service"];
                restart = ["legacy.service"];
              })
            "config-parity: mixed migrated/flat projection is order-dependent"
            (lib.throwIfNot fixtureHasNoAuthoredRequires
              "config-parity: migration fixture must not hand-author expose.requires"
              true)))));
in
  pkgs.mkDerivation {
    pname = "config-parity-check";
    version = "0";
    src = null;
    inherit assertions;
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          : "$assertions"
          mkdir -p "$out"
          cp ${golden} "$out/web.golden"
          cp ${moduleProjectionFile} "$out/web.module-eval.json"
          printf '%s\n' 'module projection == live flat metadata/actions: OK' > "$out/result"
        '';
      }
    ];
  }
