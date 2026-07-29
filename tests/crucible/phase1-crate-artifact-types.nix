{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;

  specs = [
    {
      package = "crucible-sim";
      expected = "library";
    }
    {
      package = "crucible-assert";
      expected = "library";
    }
    {
      package = "crucible-cas";
      expected = "fleet-store-binary";
    }
    {
      package = "crucible-shmem";
      expected = "library";
    }
    {
      package = "crucible-protocol";
      expected = "library";
    }
    {
      package = "crucible-device";
      expected = "library";
    }
    {
      package = "crucible-qemu";
      expected = "library";
    }
    {
      package = "crucible-qemu-plugin";
      expected = "cdylib-plugin";
    }
    {
      package = "crucible-guest";
      expected = "guest-emitter";
    }
    {
      package = "crucible";
      expected = "library";
    }
    {
      package = "crucible-session";
      expected = "library";
    }
    {
      package = "crucible-api";
      expected = "library";
    }
    {
      package = "crucible-daemon";
      expected = "library";
    }
    {
      package = "crucible-cli";
      expected = "cli-binary";
    }
    {
      package = "crucible-harness";
      expected = "library";
    }
  ];

  expectedPackages = lib.sort builtins.lessThan (map (spec: spec.package) specs);
  foundPackages = lib.sort builtins.lessThan (
    builtins.filter (
      name:
        lib.hasPrefix "crucible" name
        && builtins.pathExists (cratesDir + "/${name}/Cargo.toml")
    ) (builtins.attrNames (builtins.readDir cratesDir))
  );

  packageSetFailures =
    if foundPackages == expectedPackages
    then []
    else [
      "crucible package set mismatch: expected [${builtins.concatStringsSep ", " expectedPackages}], found [${builtins.concatStringsSep ", " foundPackages}]"
    ];

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  readManifest = package: builtins.fromTOML (builtins.readFile (cratesDir + "/${package}/Cargo.toml"));

  packageLayout = package: let
    srcDir = cratesDir + "/${package}/src";
  in {
    hasLibRs = builtins.pathExists (srcDir + "/lib.rs");
    hasMainRs = builtins.pathExists (srcDir + "/main.rs");
    hasSrcBinDir = builtins.pathExists (srcDir + "/bin");
  };

  manifestPackageName = manifest:
    if manifest ? package && manifest.package ? name
    then manifest.package.name
    else "<missing package.name>";

  crateTypes = manifest:
    if manifest ? lib && manifest.lib ? "crate-type"
    then manifest.lib."crate-type"
    else [];

  binTargets = manifest:
    if manifest ? bin
    then manifest.bin
    else [];

  declaresOrImpliesLibTarget = manifest: layout: manifest ? lib || layout.hasLibRs;

  forbiddenBinaryFailures = package: manifest: layout:
    lib.optionals (binTargets manifest != []) [
      "${package}: library/plugin package must not declare [[bin]] targets"
    ]
    ++ lib.optionals layout.hasMainRs [
      "${package}: library/plugin package must not have an implicit binary target at src/main.rs"
    ]
    ++ lib.optionals layout.hasSrcBinDir [
      "${package}: library/plugin package must not have implicit binary targets under src/bin"
    ];

  checkArtifact = spec: manifest: layout: let
    package = manifestPackageName manifest;
    packageNameFailures =
      lib.optionals (package != spec.package) [
        "${spec.package}: manifest package.name must be `${spec.package}`"
      ];
  in
    packageNameFailures
    ++ (
      if spec.expected == "cdylib-plugin"
      then
        lib.optionals (crateTypes manifest != ["cdylib"]) [
          "${spec.package}: plugin must declare exactly [\"cdylib\"] in [lib].crate-type, found [${builtins.concatStringsSep ", " (crateTypes manifest)}]"
        ]
        ++ lib.optionals (!(declaresOrImpliesLibTarget manifest layout)) [
          "${spec.package}: plugin must expose a library target"
        ]
        ++ forbiddenBinaryFailures spec.package manifest layout
      else if spec.expected == "cli-binary"
      then let
        bins = binTargets manifest;
        binCount = builtins.length bins;
        bin =
          if binCount == 1
          then builtins.elemAt bins 0
          else {};
      in
        lib.optionals (binCount != 1) [
          "${spec.package}: CLI must declare exactly one [[bin]] target, found ${builtins.toString binCount}"
        ]
        ++ lib.optionals (binCount == 1 && (!(bin ? name) || bin.name != "crucible")) [
          "${spec.package}: CLI [[bin]] name must be `crucible`"
        ]
        ++ lib.optionals (binCount == 1 && (!(bin ? path) || bin.path != "src/main.rs")) [
          "${spec.package}: CLI [[bin]] path must be `src/main.rs`"
        ]
        ++ lib.optionals (!layout.hasMainRs) [
          "${spec.package}: CLI target must have src/main.rs"
        ]
        ++ lib.optionals (declaresOrImpliesLibTarget manifest layout) [
          "${spec.package}: CLI must not expose a library target"
        ]
        ++ lib.optionals layout.hasSrcBinDir [
          "${spec.package}: CLI must not add extra implicit binary targets under src/bin"
        ]
      else if spec.expected == "guest-emitter"
      then let
        bins = binTargets manifest;
        binCount = builtins.length bins;
        bin =
          if binCount == 1
          then builtins.elemAt bins 0
          else {};
      in
        lib.optionals (!(declaresOrImpliesLibTarget manifest layout)) [
          "${spec.package}: guest emitter must expose a library target"
        ]
        ++ lib.concatMap (
          crateType:
            lib.optionals (!(builtins.elem crateType ["lib" "rlib"])) [
              "${spec.package}: forbidden crate-type `${crateType}` for guest emitter library target"
            ]
        ) (crateTypes manifest)
        ++ lib.optionals (binCount != 1) [
          "${spec.package}: guest emitter must declare exactly one [[bin]] target, found ${builtins.toString binCount}"
        ]
        ++ lib.optionals (binCount == 1 && (!(bin ? name) || bin.name != "crucible-guest")) [
          "${spec.package}: guest emitter [[bin]] name must be `crucible-guest`"
        ]
        ++ lib.optionals (binCount == 1 && (!(bin ? path) || bin.path != "src/main.rs")) [
          "${spec.package}: guest emitter [[bin]] path must be `src/main.rs`"
        ]
        ++ lib.optionals (!layout.hasMainRs) [
          "${spec.package}: guest emitter target must have src/main.rs"
        ]
        ++ lib.optionals layout.hasSrcBinDir [
          "${spec.package}: guest emitter must not add extra implicit binary targets under src/bin"
        ]
      else if spec.expected == "fleet-store-binary"
      then let
        bins = binTargets manifest;
        binCount = builtins.length bins;
        bin =
          if binCount == 1
          then builtins.elemAt bins 0
          else {};
      in
        lib.optionals (!(declaresOrImpliesLibTarget manifest layout)) [
          "${spec.package}: fleet-store package must expose a library target"
        ]
        ++ lib.concatMap (
          crateType:
            lib.optionals (!(builtins.elem crateType ["lib" "rlib"])) [
              "${spec.package}: forbidden crate-type `${crateType}` for fleet-store library target"
            ]
        ) (crateTypes manifest)
        ++ lib.optionals (binCount != 1) [
          "${spec.package}: fleet-store package must declare exactly one [[bin]] target, found ${builtins.toString binCount}"
        ]
        ++ lib.optionals (binCount == 1 && (!(bin ? name) || bin.name != "crucible-fleet-store")) [
          "${spec.package}: fleet-store [[bin]] name must be `crucible-fleet-store`"
        ]
        ++ lib.optionals (binCount == 1 && (!(bin ? path) || bin.path != "src/bin/crucible-fleet-store.rs")) [
          "${spec.package}: fleet-store [[bin]] path must be `src/bin/crucible-fleet-store.rs`"
        ]
        ++ lib.optionals layout.hasMainRs [
          "${spec.package}: fleet-store package must not have an implicit binary target at src/main.rs"
        ]
        ++ lib.optionals (!layout.hasSrcBinDir) [
          "${spec.package}: fleet-store package must keep its binary under src/bin"
        ]
      else
        lib.optionals (!(declaresOrImpliesLibTarget manifest layout)) [
          "${spec.package}: package must expose a library target"
        ]
        ++ lib.concatMap (
          crateType:
            lib.optionals (!(builtins.elem crateType ["lib" "rlib"])) [
              "${spec.package}: forbidden crate-type `${crateType}` for library package"
            ]
        ) (crateTypes manifest)
        ++ forbiddenBinaryFailures spec.package manifest layout
    );

  realFailures =
    lib.concatMap (
      spec:
        checkArtifact spec (readManifest spec.package) (packageLayout spec.package)
    )
    specs;

  regressionFailures = let
    pluginFindings = checkArtifact {
      package = "crucible-qemu-plugin";
      expected = "cdylib-plugin";
    } {
      package.name = "crucible-qemu-plugin";
      lib."crate-type" = ["rlib"];
    } {
      hasLibRs = true;
      hasMainRs = false;
      hasSrcBinDir = false;
    };
    libraryFindings = checkArtifact {
      package = "crucible-session";
      expected = "library";
    } {
      package.name = "crucible-session";
      lib."crate-type" = ["rlib" "cdylib"];
    } {
      hasLibRs = true;
      hasMainRs = false;
      hasSrcBinDir = false;
    };
    cliFindings = checkArtifact {
      package = "crucible-cli";
      expected = "cli-binary";
    } {
      package.name = "crucible-cli";
      bin = [
        {
          name = "crucible";
          path = "src/main.rs";
        }
        {
          name = "crucible-debug";
          path = "src/bin/debug.rs";
        }
      ];
    } {
      hasLibRs = false;
      hasMainRs = true;
      hasSrcBinDir = false;
    };
    implicitBinFindings = checkArtifact {
      package = "crucible-api";
      expected = "library";
    } {
      package.name = "crucible-api";
    } {
      hasLibRs = true;
      hasMainRs = true;
      hasSrcBinDir = false;
    };
    hasFinding = needle: findings:
      builtins.any (finding: hasInfix needle finding) findings;
  in
    lib.optionals (!(hasFinding "exactly [\"cdylib\"]" pluginFindings)) [
      "artifact-type regression failed to reject plugin without exact cdylib crate-type"
    ]
    ++ lib.optionals (!(hasFinding "forbidden crate-type" libraryFindings)) [
      "artifact-type regression failed to reject cdylib crate-type in a library crate"
    ]
    ++ lib.optionals (!(hasFinding "exactly one [[bin]]" cliFindings)) [
      "artifact-type regression failed to reject an extra CLI binary"
    ]
    ++ lib.optionals (!(hasFinding "implicit binary target" implicitBinFindings)) [
      "artifact-type regression failed to reject a library src/main.rs implicit binary"
    ];

  failures = packageSetFailures ++ regressionFailures ++ realFailures;
in
  if failures != []
  then throw "crucible phase1 crate artifact-type lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-crate-artifact-types";
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
            check=checks.crucible.phase1.crateArtifactTypes
            tasks=T-CRATE-10
            cdylib_package=crucible-qemu-plugin
            binary_package=crucible-cli
            binary_name=crucible
            RESULT
          '';
        }
      ];
    }
