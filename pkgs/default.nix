##! ANDYL OS — Package set composition.
##! Imports all package definitions and wires dependencies together.
##! The stdenv argument provides the production toolchain (GCC 14.3.0) and all
##! build infrastructure. All packages are built hermetically from source — no nixpkgs.
{
  lib,
  stdenv,
}: let
  fetchurl = lib.fetchurl;

  # Raw stdenv.mkDerivation, without nuke-references injected. Used by
  # nuke-references itself (to break the self-referential cycle).
  rawMkDerivation = stdenv.mkDerivation;

  exposeRenderer = import ./build-support/_expose-renderer.nix {
    inherit lib;
    pkgs = self;
  };

  # Turn a package-authored `configModule`
  # arg into the package's second `config` output (a pure-data store path
  # carrying `module.nix` + a declared-interface manifest). Wired into
  # mkDerivation below the same way `expose` is.
  configModuleRenderer = import ./build-support/_config-module-renderer.nix {
    inherit lib;
    pkgs = self;
  };

  # Use stdenv's mkDerivation (includes cc-wrapper and tools in PATH),
  # wrapped to inject nuke-references into every package's buildDeps so
  # the scrubPhase from lib/derivations.nix can rewrite build-toolchain
  # store paths out of the output (matches nixpkgs nuke-refs idiom).
  mkDerivation = args: let
    packageName =
      args.pname
      or args.name
      or (throw "mkDerivation: package must set pname or name");
    renderedExpose =
      if args ? expose
      then
        exposeRenderer.render {
          inherit packageName drv;
          expose = args.expose;
        }
      else null;
    exposeAttrs =
      if args ? expose
      then {expose = renderedExpose;}
      else {};
    renderedConfigModule =
      if args ? configModule
      then
        configModuleRenderer.render {
          inherit packageName;
          configModule = args.configModule;
        }
      else null;
    configModuleAttrs =
      if args ? configModule
      then {configModule = renderedConfigModule;}
      else {};
    lowerArgs =
      # `configModule` is an mkDerivation-level arg consumed here, not passed
      # down to the raw builder (mirrors how `expose` is handled).
      (builtins.removeAttrs args ["configModule"])
      // {
        buildDeps = (args.buildDeps or []) ++ [self.nuke-references];
        passthru = (args.passthru or {}) // exposeAttrs // configModuleAttrs;
      }
      // exposeAttrs;
    drv = rawMkDerivation lowerArgs;
    exposeCheck =
      if args ? expose
      then
        self.runCommand "expose-payload-closure-check-${packageName}" {
          payload = drv;
          exposePath = renderedExpose;
          disallowedRequisites = [renderedExpose];
          preferLocalBuild = true;
          allowSubstitutes = false;
        } ''
          set -eu
          ln -s "$payload" "$out"
        ''
      else null;
    result =
      drv
      // (
        if args ? expose
        then {
          inherit exposeCheck;
          passthru = drv.passthru // {inherit exposeCheck;};
        }
        else {}
      );
  in
    addBuilderOverrides mkDerivation args result;

  # The stdenv cc-wrapper provides gcc/g++/ld/ar/etc.
  bootstrapTools = stdenv.cc;

  # Import phase generators from stdenv/phases.nix
  phases = import ../stdenv/phases.nix;

  # Wire fetchers with AOS toolchains (using lazy self-reference)
  fetchCargoDeps = args:
    lib.fetchCargoDeps (
      args
      // {
        cargo = self.rust;
        inherit bootstrapTools;
        extraPaths = [
          stdenv.coreutils
          stdenv.tar
          stdenv.gzip
          stdenv.bash
        ];
        extraLibPaths =
          [
            self.openssl
            self.zlib
          ]
          ++ (args.extraLibPaths or []);
      }
    );

  fetchCargoVendor = args:
    lib.fetchCargoVendor (
      args
      // {
        cargo = self.rust;
        python3 = self.python3;
        git = self.git;
        caCertificates = self.ca-certificates;
        inherit bootstrapTools;
        extraPaths = [
          stdenv.coreutils
          stdenv.tar
          stdenv.gzip
          stdenv.bash
        ];
        extraLibPaths =
          [
            self.openssl
            self.zlib
          ]
          ++ (args.extraLibPaths or []);
      }
    );

  fetchGoModules = args:
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

  fetchNpmDeps = args:
    lib.fetchNpmDeps (
      args
      // {
        nodejs = self.nodejs;
        python3 = self.python3;
        caCertificates = self.ca-certificates;
        inherit bootstrapTools;
        extraPaths = [
          stdenv.coreutils
          stdenv.tar
          stdenv.gzip
          stdenv.bash
          stdenv.gnumake
          stdenv.sed
          stdenv.grep
          stdenv.gawk
          stdenv.findutils
          self.git
        ];
        extraLibPaths =
          [
            self.openssl
            self.zlib
          ]
          ++ (args.extraLibPaths or []);
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

  # Re-thread `overrideAttrs` (and `override`) through a language wrapper
  # (mkCargoPackage, mkGoPackage, mkBazelPackage) so that wrapper-level args
  # take effect when overridden — `doCheck`, `cargoTestFlags`, `goTestFlags`,
  # `bazelTarget`, and the rest of cargo/go/bazelSpecificAttrs.
  #
  # `overrideAttrs` is the right tool here: those attrs are arguments to the
  # *builder* (the layer nixpkgs calls overrideAttrs over — stdenv.mkDerivation
  # there, our wrapper here), not formals of the package function (the layer
  # `override`/callPackage covers). Re-running the wrapper with merged args is
  # the exact analog of nixpkgs' stdenv.mkDerivation.overrideAttrs, which
  # re-invokes mkDerivation with `prev // (f prev)`.
  #
  # The override mechanism inherited from mkDerivation can't do this: the
  # wrapper has already consumed its specific attrs (e.g. `doCheck`) and frozen
  # the phases list (cargoPhases resolves `doCheck` at eval time, omitting the
  # check phase entirely), so overriding them through the inherited hook is a
  # silent no-op. nixpkgs avoids the problem differently — its check phase is
  # static and `doCheck` is a build-time env var read by the generic builder —
  # but AOS selects phases at eval time, so the wrapper must re-run.
  #
  # `prevArgs` is the wrapper's argument set (matching nixpkgs, where
  # overrideAttrs' `prev` is the args passed to the builder, not the computed
  # derivation). Both hooks accept either an attrset or a `prevArgs: {...}`
  # function; the attrset form is an AOS ergonomic extension (nixpkgs'
  # overrideAttrs is strictly a function).
  addBuilderOverrides = builder: args: drv:
    drv
    // {
      override = f:
        builder (
          if builtins.isFunction f
          then f args
          else args // f
        );
      overrideAttrs = f:
        builder (
          args
          // (
            if builtins.isFunction f
            then f args
            else f
          )
        );
    };

  mkCargoPackage = args: let
    # Extract cargo-specific attrs for the phase generator
    cargoArgs =
      builtins.intersectAttrs (builtins.listToAttrs (
        map (n: {
          name = n;
          value = true;
        })
        cargoSpecificAttrs
      ))
      args;
    # Remove cargo-specific attrs before passing to mkDerivation
    restArgs = removeAttrs args cargoSpecificAttrs;
  in
    addBuilderOverrides mkCargoPackage args (
      mkDerivation (
        restArgs
        // {
          buildDeps = [self.rust] ++ (args.buildDeps or []);
          phases = phases.cargoPhases cargoArgs;
        }
      )
    );

  mkGoPackage = args: let
    goArgs =
      builtins.intersectAttrs (builtins.listToAttrs (
        map (n: {
          name = n;
          value = true;
        })
        goSpecificAttrs
      ))
      args;
    # Default goOutput to pname when not explicitly set
    goArgsWithDefaults =
      goArgs
      // {
        goOutput = args.goOutput or args.pname or (throw "mkGoPackage: goOutput or pname required");
      };
    restArgs = removeAttrs args goSpecificAttrs;
  in
    addBuilderOverrides mkGoPackage args (
      mkDerivation (
        restArgs
        // {
          buildDeps = [self.go] ++ (args.buildDeps or []);
          phases = phases.goPhases goArgsWithDefaults;
          # Guard: the Go toolchain must not leak into the runtime closure.
          # -trimpath (in goPhases) prevents source-path embedding; this
          # disallowedReferences catches any residual leak at build time.
          # Matches nixpkgs' buildGoModule pattern.
          disallowedReferences = args.disallowedReferences or [self.go];
        }
      )
    );

  # Wire fetchBazelDeps with AOS-specific defaults
  fetchBazelDeps = args:
    lib.fetchBazelDeps (
      args
      // {
        inherit bootstrapTools;
        caCertificates = args.caCertificates or self.ca-certificates;
      }
    );

  mkBazelPackage = args: let
    # Extract bazel-specific parameters
    bazel = args.bazel or self.bazel;
    jdk = args.jdk or self.openjdk;
    tools = args.tools or [];
    caCerts = args.caCertificates or self.ca-certificates;
    bazelTarget = args.bazelTarget or (throw "mkBazelPackage: bazelTarget required");
    bazelFlags = args.bazelFlags or [];
    bazelBuildFlags = args.bazelBuildFlags or [];
    scrubMap = args.scrubMap or {};
    installPhase = args.installPhase or (throw "mkBazelPackage: installPhase required");

    # Create or use provided deps FOD
    deps =
      args.bazelDeps
      or (fetchBazelDeps {
        name = "${args.pname or "bazel"}-deps-${args.version or "0"}";
        inherit (args) src;
        hash = args.depsHash or lib.fakeHash;
        inherit bazel jdk tools;
        caCertificates = caCerts;
        postPatch = args.postPatch or "";
        fetchPostPatch = args.fetchPostPatch or "";
        inherit bazelTarget bazelFlags;
        bazelFetchFlags = args.bazelFetchFlags or [];
        env = args.fetchEnv or {};
        inherit scrubMap;
        postFetch = args.postFetch or "";
        removeRepos =
          args.removeRepos
          or [
            "bazel_tools"
            "embedded_jdk"
            "local_config_cc"
            "local_jdk"
          ];
        populateBCR = args.populateBCR or true;
      });

    # Remove bazel-specific attrs before passing to mkDerivation
    restArgs = removeAttrs args bazelSpecificAttrs;
  in
    addBuilderOverrides mkBazelPackage args (
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
            ++ (args.buildDeps or []);
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
      )
    );

  # callPackage: import a package file and auto-fill its arguments from `self`.
  # The package file is a function whose formals are introspected via
  # builtins.functionArgs, then satisfied from the package set plus the
  # always-available helpers (mkDerivation, fetchurl).
  callPackage = path: overrides: let
    fn = import path;
    auto = builtins.intersectAttrs (builtins.functionArgs fn) (
      self
      // {
        inherit mkDerivation fetchurl callPackage;
      }
    );
  in
    fn (auto // overrides);

  # Shared Linux kernel source (single tarball for linux and linux-headers)
  linuxSource = import ./kernel/_source.nix {inherit fetchurl;};

  # Shared Kubernetes source (single tarball for kubelet, kubectl)
  kubeSource = import ./kubernetes/_source.nix {inherit fetchurl;};

  # Shared KubeEdge source (single tarball for cloudcore, edgecore)
  kubeedgeSource = import ./kubernetes/_kubeedge-source.nix {inherit fetchurl;};

  # Auto-discover packages from subdirectories.
  # Recursively scans for .nix files, skipping default.nix and _-prefixed
  # files/directories (used for shared resources like _source.nix).
  discoverPackages = dir: let
    entries = builtins.readDir dir;
    names = builtins.attrNames entries;

    # .nix files → packages (skip default.nix and _-prefixed)
    nixFiles =
      builtins.filter (
        name:
          entries.${name}
          == "regular"
          && lib.hasSuffix ".nix" name
          && name != "default.nix"
          && builtins.substring 0 1 name != "_"
      )
      names;

    # Subdirectories to recurse into (skip _-prefixed)
    subdirs =
      builtins.filter (
        name: entries.${name} == "directory" && builtins.substring 0 1 name != "_"
      )
      names;

    filePackages = builtins.listToAttrs (
      map (name: {
        name = lib.removeSuffix ".nix" name;
        value = callPackage (dir + "/${name}") {};
      })
      nixFiles
    );

    subdirPackages =
      builtins.foldl' (
        acc: subdir: acc // discoverPackages (dir + "/${subdir}")
      ) {}
      subdirs;
  in
    filePackages // subdirPackages;

  self =
    {
      # --- Plumbing ---
      inherit mkDerivation fetchurl lib;
      inherit mkCargoPackage mkGoPackage mkBazelPackage;
      inherit fetchCargoDeps fetchCargoVendor fetchGoModules fetchNpmDeps fetchBazelDeps;
      inherit bootstrapTools;
      fakeHash = lib.fakeHash;
      # --- Build infrastructure ---
      inherit stdenv;

      # nuke-references uses the raw (un-wrapped) mkDerivation so it can't
      # depend on itself. Every other package gets nuke-references injected
      # into buildDeps automatically via the wrapped mkDerivation above.
      nuke-references = import ../lib/build-support/nuke-references {
        mkDerivation = rawMkDerivation;
        inherit (self) bash gawk sed;
      };
    }
    // discoverPackages ./.
    // {
      # --- Explicit overrides for packages needing non-standard arguments ---
      linux = callPackage ./kernel/linux.nix {inherit linuxSource;};
      # Build a kernel variant with extra kconfig appended. Use this — not
      # `linux.override { extraConfig = …; }` — for deployment kernels:
      # `extraConfig` is a linux.nix function arg consumed before
      # mkDerivation, so the inherited `.override` hook can't reach it
      # (silent no-op). callPackage threads it directly. (RFC-0006 lockdown.)
      linuxWith = extraConfig:
        callPackage ./kernel/linux.nix {inherit linuxSource extraConfig;};
      linux-headers = callPackage ./kernel/linux-headers.nix {inherit linuxSource;};

      # Interpreter-free git for the system image (shares git.nix's source and
      # version). Used by apm/apr's runtimeTools and the server profile so the
      # image carries no Perl on git's behalf. `pkgs.git` remains the full build.
      git-minimal = callPackage ./tools/git.nix {minimal = true;};

      kubelet = callPackage ./kubernetes/kubelet.nix {inherit kubeSource;};
      kubectl = callPackage ./kubernetes/kubectl.nix {inherit kubeSource;};

      cloudcore = callPackage ./kubernetes/cloudcore.nix {inherit kubeedgeSource;};
      edgecore = callPackage ./kubernetes/edgecore.nix {inherit kubeedgeSource;};

      # --- stdenv packages (linked, not rebuilt) ---
      gcc = stdenv.gcc;
      glibc = stdenv.glibc;
      binutils = stdenv.binutils;
      cc = stdenv.cc;
      # The unwrapped gcc-14.3.0-stage2. `pkgs.gcc` is the wrapped
      # gcc-14.3.0-wrapped; the perl Config scrub needs to substitute
      # and block the unwrapped one, since that's what Configure
      # records via specs/PATH.
      gccUnwrapped = stdenv.gccStage2;
      getent = lib.getOutput "getent" stdenv.glibc;
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
    }
    # --- Trivial builders, exposed flat on the package set ---
    # The file at pkgs/build-support/trivial-builders.nix is also picked up
    # by discoverPackages as `self.trivial-builders`; here we re-inherit the
    # four primitives into the top level so consumers can call
    # `pkgs.writeTextFile` / `pkgs.runCommand` etc. directly, matching the
    # nixpkgs convention that the ported systemd library expects.
    // (
      let
        tb = self.trivial-builders;
      in {
        inherit
          (tb)
          writeTextFile
          writeShellScriptBin
          runtimeShell
          runCommand
          ;
      }
    );
in
  self
