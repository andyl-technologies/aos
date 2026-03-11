##! ANDYL OS — Package set composition.
##! Imports all package definitions and wires dependencies together.
##! The stdenv argument provides the production toolchain (GCC 14.3.0) and all
##! build infrastructure. All packages are built hermetically from source — no nixpkgs.
{
  lib,
  stdenv,
}:
let
  fetchurl = lib.fetchurl;

  # Use stdenv's mkDerivation (includes cc-wrapper and tools in PATH)
  mkDerivation = stdenv.mkDerivation;

  # The stdenv cc-wrapper provides gcc/g++/ld/ar/etc.
  bootstrapTools = stdenv.cc;

  # Import phase generators from stdenv/phases.nix
  phases = import ../stdenv/phases.nix;

  # Wire fetchers with AOS toolchains (using lazy self-reference)
  fetchCargoDeps =
    args:
    lib.fetchCargoDeps (
      args
      // {
        cargo = self.rust;
        inherit bootstrapTools;
        extraLibPaths = [
          self.openssl
          self.zlib
        ]
        ++ (args.extraLibPaths or [ ]);
      }
    );

  fetchGoModules =
    args:
    lib.fetchGoModules (
      args
      // {
        go = self.go;
        inherit bootstrapTools;
        extraPaths = [
          stdenv.coreutils
          stdenv.tar
          stdenv.gzip
          stdenv.bash
        ];
      }
    );

  # Attrs that mkCargoPackage consumes (not passed to mkDerivation)
  cargoSpecificAttrs = [
    "cargoDeps"
    "cargoFlags"
    "buildType"
    "checkType"
    "cargoTestFlags"
    "buildFeatures"
    "buildNoDefaultFeatures"
    "installBins"
    "installLibs"
    "doCheck"
    "doParallelCheck"
    "gitDeps"
  ];

  # Attrs that mkGoPackage consumes (not passed to mkDerivation)
  goSpecificAttrs = [
    "goModules"
    "goPackage"
    "goOutput"
    "cgoEnabled"
    "ldflags"
    "tags"
    "doCheck"
    "goTestFlags"
    "doParallelCheck"
  ];

  # Attrs that mkBazelPackage consumes (not passed to mkDerivation)
  bazelSpecificAttrs = [
    "bazelDeps"
    "bazel"
    "jdk"
    "tools"
    "caCertificates"
    "bazelTarget"
    "bazelFlags"
    "bazelBuildFlags"
    "bazelFetchFlags"
    "scrubMap"
    "depsHash"
    "fetchPostPatch"
    "fetchEnv"
    "postFetch"
    "removeRepos"
    "populateBCR"
    "installPhase"
    "preBazelBuild"
  ];

  mkCargoPackage =
    args:
    let
      # Extract cargo-specific attrs for the phase generator
      cargoArgs = builtins.intersectAttrs (builtins.listToAttrs (
        builtins.map (n: {
          name = n;
          value = true;
        }) cargoSpecificAttrs
      )) args;
      # Remove cargo-specific attrs before passing to mkDerivation
      restArgs = builtins.removeAttrs args cargoSpecificAttrs;
    in
    mkDerivation (
      restArgs
      // {
        buildDeps = [ self.rust ] ++ (args.buildDeps or [ ]);
        phases = phases.cargoPhases cargoArgs;
      }
    );

  mkGoPackage =
    args:
    let
      goArgs = builtins.intersectAttrs (builtins.listToAttrs (
        builtins.map (n: {
          name = n;
          value = true;
        }) goSpecificAttrs
      )) args;
      # Default goOutput to pname when not explicitly set
      goArgsWithDefaults = goArgs // {
        goOutput = args.goOutput or args.pname or (throw "mkGoPackage: goOutput or pname required");
      };
      restArgs = builtins.removeAttrs args goSpecificAttrs;
    in
    mkDerivation (
      restArgs
      // {
        buildDeps = [ self.go ] ++ (args.buildDeps or [ ]);
        phases = phases.goPhases goArgsWithDefaults;
      }
    );

  # Wire fetchBazelDeps with AOS-specific defaults
  fetchBazelDeps =
    args:
    lib.fetchBazelDeps (
      args
      // {
        inherit bootstrapTools;
        caCertificates = args.caCertificates or self.ca-certificates;
      }
    );

  mkBazelPackage =
    args:
    let
      # Extract bazel-specific parameters
      bazel = args.bazel or self.bazel;
      jdk = args.jdk or self.openjdk;
      tools = args.tools or [ ];
      caCerts = args.caCertificates or self.ca-certificates;
      bazelTarget = args.bazelTarget or (throw "mkBazelPackage: bazelTarget required");
      bazelFlags = args.bazelFlags or [ ];
      bazelBuildFlags = args.bazelBuildFlags or [ ];
      scrubMap = args.scrubMap or { };
      installPhase = args.installPhase or (throw "mkBazelPackage: installPhase required");

      # Create or use provided deps FOD
      deps =
        args.bazelDeps or (fetchBazelDeps {
          name = "${args.pname or "bazel"}-deps-${args.version or "0"}";
          inherit (args) src;
          hash = args.depsHash or lib.fakeHash;
          inherit bazel jdk tools;
          caCertificates = caCerts;
          postPatch = args.postPatch or "";
          fetchPostPatch = args.fetchPostPatch or "";
          inherit bazelTarget bazelFlags;
          bazelFetchFlags = args.bazelFetchFlags or [ ];
          env = args.fetchEnv or { };
          inherit scrubMap;
          postFetch = args.postFetch or "";
          removeRepos = args.removeRepos or [
            "bazel_tools"
            "embedded_jdk"
            "local_config_cc"
            "local_jdk"
          ];
          populateBCR = args.populateBCR or true;
        });

      # Remove bazel-specific attrs before passing to mkDerivation
      restArgs = builtins.removeAttrs args bazelSpecificAttrs;
    in
    mkDerivation (
      restArgs
      // {
        buildDeps =
          [
            bazel
            jdk
            self.patchelf
          ]
          ++ tools
          ++ (args.buildDeps or [ ]);
        phases = phases.bazelPhases {
          bazelDeps = deps;
          inherit bazel jdk tools;
          inherit bootstrapTools;
          patchelf = self.patchelf;
          bash = stdenv.bash;
          caCertificates = caCerts;
          inherit bazelTarget bazelFlags bazelBuildFlags;
          inherit scrubMap;
          preBuild = args.preBazelBuild or "";
          inherit installPhase;
        };
      }
    );

  # callPackage: import a package file and auto-fill its arguments from `self`.
  # The package file is a function whose formals are introspected via
  # builtins.functionArgs, then satisfied from the package set plus the
  # always-available helpers (mkDerivation, fetchurl).
  callPackage =
    path: overrides:
    let
      fn = import path;
      auto = builtins.intersectAttrs (builtins.functionArgs fn) (
        self
        // {
          inherit mkDerivation fetchurl;
        }
      );
    in
    fn (auto // overrides);

  # Shared Linux kernel source (single tarball for linux and linux-headers)
  linuxSource = import ./kernel/_source.nix { inherit fetchurl; };

  # Shared Kubernetes source (single tarball for kubelet, kubectl)
  kubeSource = import ./kubernetes/_source.nix { inherit fetchurl; };

  # Shared KubeEdge source (single tarball for cloudcore, edgecore)
  kubeedgeSource = import ./iot/_kubeedge-source.nix { inherit fetchurl; };

  # Auto-discover packages from subdirectories.
  # Recursively scans for .nix files, skipping default.nix and _-prefixed
  # files/directories (used for shared resources like _source.nix).
  discoverPackages =
    dir:
    let
      entries = builtins.readDir dir;
      names = builtins.attrNames entries;

      # .nix files → packages (skip default.nix and _-prefixed)
      nixFiles = builtins.filter (
        name:
        entries.${name} == "regular"
        && lib.hasSuffix ".nix" name
        && name != "default.nix"
        && builtins.substring 0 1 name != "_"
      ) names;

      # Subdirectories to recurse into (skip _-prefixed)
      subdirs = builtins.filter (
        name: entries.${name} == "directory" && builtins.substring 0 1 name != "_"
      ) names;

      filePackages = builtins.listToAttrs (
        builtins.map (name: {
          name = lib.removeSuffix ".nix" name;
          value = callPackage (dir + "/${name}") { };
        }) nixFiles
      );

      subdirPackages = builtins.foldl' (
        acc: subdir: acc // discoverPackages (dir + "/${subdir}")
      ) { } subdirs;
    in
    filePackages // subdirPackages;

  self = {
    # --- Plumbing ---
    inherit mkDerivation fetchurl lib;
    inherit mkCargoPackage mkGoPackage mkBazelPackage;
    inherit fetchCargoDeps fetchGoModules fetchBazelDeps;
    inherit bootstrapTools;
    fakeHash = lib.fakeHash;
    # --- Build infrastructure ---
    inherit stdenv;
  }
  // discoverPackages ./.
  // {
    # --- Explicit overrides for packages needing non-standard arguments ---
    linux = callPackage ./kernel/linux.nix { inherit linuxSource; };
    linux-headers = callPackage ./kernel/linux-headers.nix { inherit linuxSource; };

    kubelet = callPackage ./kubernetes/kubelet.nix { inherit kubeSource; };
    kubectl = callPackage ./kubernetes/kubectl.nix { inherit kubeSource; };

    cloudcore = callPackage ./iot/cloudcore.nix { inherit kubeedgeSource; };
    edgecore = callPackage ./iot/edgecore.nix { inherit kubeedgeSource; };

    # --- stdenv packages (linked, not rebuilt) ---
    gcc = stdenv.gcc;
    glibc = stdenv.glibc;
    binutils = stdenv.binutils;
    bash = stdenv.bash;
    coreutils = stdenv.coreutils;
    gnumake = stdenv.gnumake;
    sed = stdenv.sed;
    grep = stdenv.grep;
    findutils = stdenv.findutils;
    gawk = stdenv.gawk;
    diffutils = stdenv.diffutils;
    tar = stdenv.tar;
    gzip = stdenv.gzip;
    patch = stdenv.patch;
  };
in
self
