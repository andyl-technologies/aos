##! Immutable Nix seed tree and separate finalized descriptor DATA.
##!
##! initialRoots must include every recipe-specific source, lock, derivation
##! and known output needed by its later approved bootstrap. The default only
##! supplies the complete selected Nix runtime; neither output admits G0.
{
  mkDerivation,
  lib,
  nix,
  stdenv,
  buildPackages,
  initialRoots ? [],
  emitPortableSeedGraph ? false,
}: let
  declaredRoots = [nix.out] ++ initialRoots;
  validRoots =
    builtins.isList initialRoots
    && lib.all (root: builtins.isAttrs root && (root.type or "") == "derivation") declaredRoots;
  rootPaths = builtins.sort (left: right: builtins.toString left < builtins.toString right) declaredRoots;
  mkReferenceGraph = import ../../lib/build/reference-graph.nix {
    inherit lib;
    inherit (buildPackages) mkDerivation coreutils jq;
  };
  graph = mkReferenceGraph {
    inherit rootPaths;
    subtractPaths = [];
    pname = "aos-nix-generation-seed-reference-graph";
  };
  nativeBuilder = buildPackages.aos-nix-generation-seed-builder;
  builderProgram = "${nativeBuilder}/libexec/aos-nix-generation-seed-builder";
  targetSystem = stdenv.hostPlatform.system;
  selectedNixPath = "${nix}/bin/nix";

  seedTree = mkDerivation {
    pname = "aos-sandbox-nix-generation-template";
    version = "1";
    src = null;
    buildDeps = [nativeBuilder buildPackages.coreutils];
    runtimeDeps = declaredRoots;
    propagatedDeps = [];

    # Copied package bytes and the upstream-generated DB must not be rewritten
    # by generic ELF fixup or reference scrubbing after their full checks.
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "populate";
        script = ''
          set -eu
          mkdir -p "$out"
          ${builderProgram} build "$out/root" ${graph} \
            ${lib.escapeShellArg targetSystem} ${lib.escapeShellArg selectedNixPath}
        '';
      }
    ];

    passthru = {
      inherit rootPaths graph targetSystem seedMeasurement;
      seedDescriptor = seedMeasurement;
      seedRootRelativePath = "root";
      seedDescriptorRelativePath = "seed280";
      evidenceSources = [./aos-sandbox-nix-generation-template.nix];
    } // lib.optionalAttrs emitPortableSeedGraph {
      inherit portableSeedGraph;
    };

    meta = {
      description = "Complete private Nix seed tree DATA, without G0 authority";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  };

  # This dependency sees the actual finalized store object and attributes.
  # It never feeds its descriptor back into the tree being measured.
  seedMeasurement = buildPackages.mkDerivation {
    pname = "aos-nix-generation-seed-measurement";
    version = "1";
    src = null;
    buildDeps = [nativeBuilder buildPackages.coreutils];
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "measure";
        script = ''
          set -eu
          mkdir -p "$out"
          ${builderProgram} measure ${seedTree}/root "$out" \
            ${lib.escapeShellArg targetSystem} ${lib.escapeShellArg selectedNixPath}
        '';
      }
    ];
    meta = {
      description = "Finalized Nix seed descriptor and observed counter DATA";
      license = "Apache-2.0";
    };
  };

  # This third DATA output sees the same finalized target bytes, but runs only
  # a native AOS-built tool. No descriptor/graph is fed back into its seed root.
  portableSeedGraph = buildPackages.mkDerivation {
    pname = "aos-sandbox-nix-seed-portable-graph";
    version = "1";
    src = null;
    buildDeps = [buildPackages.aos-sandbox-zfs-worker buildPackages.coreutils];
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "measure-complete-graph";
        script = ''
          set -eu
          test -s ${seedMeasurement}/seed280
          mkdir -p "$out"
          ${buildPackages.aos-sandbox-zfs-worker}/bin/aos-sandbox-nix-seed-tree \
            ${seedTree}/root "$out"
        '';
      }
    ];
    meta = {
      description = "Complete original Nix seed Core graph DATA, without signature or G0 authority";
      license = "Apache-2.0";
    };
  };
in
  assert validRoots;
  assert builtins.elem targetSystem ["x86_64-linux" "aarch64-linux"];
  assert nix.version == "2.24.12";
    seedTree
