{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;
  harnessPackage = "crucible-harness";

  runtimeSpecs = [
    {
      package = "crucible-sim";
      layer = 0;
      inVm = false;
    }
    {
      package = "crucible-assert";
      layer = 0;
      inVm = false;
    }
    {
      package = "crucible-shmem";
      layer = 1;
      inVm = false;
    }
    {
      package = "crucible-protocol";
      layer = 1;
      inVm = false;
    }
    {
      package = "crucible-device";
      layer = 1;
      inVm = false;
    }
    {
      package = "crucible-qemu";
      layer = 2;
      inVm = false;
    }
    {
      package = "crucible-qemu-plugin";
      layer = 2;
      inVm = true;
    }
    {
      package = "crucible-debug-gateway";
      layer = 2;
      inVm = false;
    }
    {
      package = "crucible-guest";
      layer = 2;
      inVm = true;
    }
    {
      package = "crucible";
      layer = 3;
      inVm = false;
    }
    {
      package = "crucible-cas";
      layer = 3;
      inVm = false;
    }
    {
      package = "crucible-session";
      layer = 4;
      inVm = false;
    }
    {
      package = "crucible-api";
      layer = 4;
      inVm = false;
    }
    {
      package = "crucible-daemon";
      layer = 4;
      inVm = false;
    }
    {
      package = "crucible-cli";
      layer = 4;
      inVm = false;
    }
  ];

  runtimePackages = map (spec: spec.package) runtimeSpecs;
  expectedPackages = lib.sort builtins.lessThan (runtimePackages ++ [harnessPackage]);
  foundPackages = lib.sort builtins.lessThan (
    builtins.filter (
      name:
        lib.hasPrefix "crucible" name
        && builtins.pathExists (cratesDir + "/${name}/Cargo.toml")
    ) (builtins.attrNames (builtins.readDir cratesDir))
  );

  specByPackage = builtins.listToAttrs (
    map (spec: {
      name = spec.package;
      value = spec;
    })
    runtimeSpecs
  );
  layerByPackage = builtins.listToAttrs (
    map (spec: {
      name = spec.package;
      value = spec.layer;
    })
    runtimeSpecs
  );
  hostAdapterUpwardEdgeExceptions = [
    {
      from = "crucible-qemu";
      to = "crucible";
    }
  ];
  isHostAdapterUpwardEdgeException = edge:
    builtins.any (exception: exception.from == edge.from && exception.to == edge.to) hostAdapterUpwardEdgeExceptions;

  dependencyPackageName = name: value:
    if builtins.isAttrs value && value ? package
    then value.package
    else name;

  manifestCrucibleDeps = package: let
    manifest = builtins.fromTOML (builtins.readFile (cratesDir + "/${package}/Cargo.toml"));
    dependencies =
      if manifest ? dependencies
      then manifest.dependencies
      else {};
  in
    builtins.filter (name: lib.hasPrefix "crucible" name) (
      lib.mapAttrsToList dependencyPackageName dependencies
    );

  manifestEdges =
    lib.concatMap (
      spec:
        map (to: {
          from = spec.package;
          inherit to;
        })
        (manifestCrucibleDeps spec.package)
    )
    runtimeSpecs;

  depsOf = edges: from:
    map (edge: edge.to) (
      builtins.filter (
        edge:
          edge.from
          == from
          && builtins.hasAttr edge.to layerByPackage
      )
      edges
    );

  reachable = edges: from: target: seen:
    if builtins.elem from seen
    then false
    else
      builtins.any (
        dependency:
          dependency
          == target
          || reachable edges dependency target (seen ++ [from])
      ) (depsOf edges from);

  analyzeEdges = edges: let
    edgeFailures =
      lib.concatMap (
        edge: let
          fromSpec = specByPackage.${edge.from};
        in
          if edge.to == harnessPackage
          then [
            "runtime crate `${edge.from}` must not depend on test-only `${harnessPackage}`"
          ]
          else if !(builtins.hasAttr edge.to layerByPackage)
          then []
          else let
            toLayer = layerByPackage.${edge.to};
          in
            if fromSpec.inVm && toLayer != 1
            then [
              "in-VM L2 crate `${edge.from}` may depend directly only on L1 crates, found `${edge.to}` in L${builtins.toString toLayer}"
            ]
            else if (!fromSpec.inVm) && toLayer > fromSpec.layer && !(isHostAdapterUpwardEdgeException edge)
            then [
              "upward dependency `${edge.from}` (L${builtins.toString fromSpec.layer}) -> `${edge.to}` (L${builtins.toString toLayer})"
            ]
            else []
      )
      edges;

    cycleFailures = builtins.filter (failure: failure != null) (
      map (
        package:
          if reachable edges package package []
          then "dependency cycle reaches `${package}`"
          else null
      )
      runtimePackages
    );
  in
    edgeFailures ++ cycleFailures;

  packageSetFailures =
    if foundPackages == expectedPackages
    then []
    else [
      "crucible package set mismatch: expected [${builtins.concatStringsSep ", " expectedPackages}], found [${builtins.concatStringsSep ", " foundPackages}]"
    ];

  regressionFailures = let
    findings = analyzeEdges [
      {
        from = "crucible-sim";
        to = "crucible";
      }
      {
        from = "crucible-qemu-plugin";
        to = "crucible-sim";
      }
      {
        from = "crucible-api";
        to = harnessPackage;
      }
      {
        from = "crucible-protocol";
        to = "crucible-device";
      }
      {
        from = "crucible-device";
        to = "crucible-protocol";
      }
    ];
    hasFinding = needle:
      builtins.any (finding: (builtins.match ".*${needle}.*" finding) != null) findings;
  in
    if
      hasFinding "upward dependency"
      && hasFinding "in-VM L2 crate"
      && hasFinding "test-only"
      && hasFinding "dependency cycle"
    then []
    else [
      "layer-graph regression expected upward, in-VM, harness, and cycle findings; got [${builtins.concatStringsSep "; " findings}]"
    ];

  failures = packageSetFailures ++ regressionFailures ++ analyzeEdges manifestEdges;
in
  if failures != []
  then throw "crucible phase1 crate layer-graph lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-crate-layer-graph";
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
            check=checks.crucible.phase1.crateLayerGraph
            gate=gate:harness-lint
            tasks=T-ARCH-2,T-CRATE-3
            runtime_crates=14
            test_only_crates=1
            upward_edges=0
            host_adapter_upward_edge_exceptions=1
            dependency_cycles=0
            in_vm_non_l1_direct_edges=0
            RESULT
          '';
        }
      ];
    }
