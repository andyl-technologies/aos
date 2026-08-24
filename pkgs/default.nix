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
  defaultMaintainers = ["Andyl, Inc."];

  withDistributionMeta = extra: drv:
    drv
    // {
      meta =
        (drv.meta or {})
        // {
          maintainers = drv.meta.maintainers or defaultMaintainers;
        }
        // extra;
    };
  withDefaultMaintainers = withDistributionMeta {};

  exposeRenderer = import ./build-support/_expose-renderer.nix {
    inherit lib;
    pkgs = self;
  };
  cargoArtifactsSupport = import ./build-support/_cargo-artifacts.nix {
    inherit lib mkDerivation;
  };

  # Turn a package-authored `configModule` arg into the package's logical
  # `config` output (a pure-data store path carrying `module.nix` plus a
  # declared-interface manifest). A fixed companion derivation builds it so
  # package-authored phases cannot skip or mutate its validation boundary.
  configModuleRenderer = import ./build-support/_config-module-renderer.nix {inherit lib;};

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
    hasGeneratedExposeConfig = args ? expose;
    generatedExposeDeclares = [
      "${packageName}._aosExposeConfigProjection"
      "${packageName}.config"
      "${packageName}.credentials"
    ];
    generatedExposeConfigFile =
      if hasGeneratedExposeConfig
      then
        builtins.toFile "expose-config-${packageName}.json" (builtins.toJSON {
          package = packageName;
          config = exposeRenderer.normalizeConfig packageName (args.expose.config or {});
        })
      else null;
    generatedConfigSource =
      if hasGeneratedExposeConfig
      then
        rawMkDerivation {
          pname = "${packageName}-generated-config-source";
          version = args.version or "0";
          src = null;
          phases = [
            {
              name = "install";
              script = ''
                mkdir -p "$out"
                cp ${./build-support/_generated-expose-config-module.nix} "$out/module.nix"
                cp ${generatedExposeConfigFile} "$out/expose-config.json"
              '';
            }
          ];
          preferLocalBuild = true;
          allowSubstitutes = false;
        }
      else null;
    authoredConfigModule = args.configModule or null;
    preparedAuthoredConfigModule =
      if authoredConfigModule != null
      then
        configModuleRenderer.prepare {
          inherit packageName;
          configModule = authoredConfigModule;
        }
      else null;
    authoredConfigMeta =
      if preparedAuthoredConfigModule != null
      then builtins.fromJSON preparedAuthoredConfigModule.metaJson
      else null;
    composedModuleFile = builtins.toFile "composed-config-module-${packageName}.nix" ''
      { ... }: {
        imports = [
          ./authored/module.nix
          ./generated/module.nix
        ];
      }
    '';
    composedConfigSource =
      if authoredConfigModule != null && hasGeneratedExposeConfig
      then
        rawMkDerivation {
          pname = "${packageName}-composed-config-source";
          version = args.version or "0";
          src = null;
          phases = [
            {
              name = "install";
              script = ''
                mkdir -p "$out/authored" "$out/generated"
                cp -R ${preparedAuthoredConfigModule.src}/. "$out/authored/"
                cp -R ${generatedConfigSource}/. "$out/generated/"
                cp ${composedModuleFile} "$out/module.nix"
              '';
            }
          ];
          preferLocalBuild = true;
          allowSubstitutes = false;
        }
      else null;
    effectiveConfigModule =
      if authoredConfigModule != null
      then authoredConfigModule
      else if hasGeneratedExposeConfig
      then {
        src = generatedConfigSource;
        moduleAbiCompat = {
          min = 1;
          max = 1;
        };
        declares = generatedExposeDeclares;
      }
      else null;
    hasConfigModule = effectiveConfigModule != null;
    preparedConfigModule =
      if authoredConfigModule != null && hasGeneratedExposeConfig
      then {
        src = composedConfigSource;
        metaJson = builtins.toJSON (authoredConfigMeta
          // {
            declares = lib.unique (authoredConfigMeta.declares ++ generatedExposeDeclares);
          });
        dependencyOutputs = preparedAuthoredConfigModule.dependencyOutputs;
      }
      else if hasGeneratedExposeConfig
      then {
        src = generatedConfigSource;
        metaJson = builtins.toJSON {
          schema = "aos.config-module-meta/v1";
          module_abi_compat = {
            min = 1;
            max = 1;
          };
          declares = effectiveConfigModule.declares;
          owns_roots = [];
          contributes = [];
          provides_capabilities = [];
          dependencies = [];
        };
        dependencyOutputs = {};
      }
      else if hasConfigModule
      then preparedAuthoredConfigModule
      else null;
    configModuleMetaFile =
      if hasConfigModule
      then builtins.toFile "config-meta-${packageName}.json" preparedConfigModule.metaJson
      else null;
    existingOutputs = args.outputs or ["out"];
    configStoreDir = args.storeDir or "/nix/store";
    configArtifact =
      if hasConfigModule
      then
        lib.throwIfNot
        (!(builtins.elem "config" existingOutputs))
        "mkDerivation configModule for package '${packageName}' reserves the 'config' output name"
        (rawMkDerivation {
          pname = "${packageName}-config";
          version = args.version or "0";
          src = preparedConfigModule.src;
          outputs = ["config"];
          buildDeps = [self.nix];
          phases = [
            {
              name = "install";
              script = ''
                ${stdenv.coreutils}/bin/env -i TMPDIR=/build \
                  ${stdenv.bash}/bin/bash --noprofile --norc -euo pipefail -c ${
                  lib.escapeShellArg ''
                    output=$1
                    source=$2
                    authored_meta=$(${stdenv.findutils}/bin/find "$source" -name config-meta.json -print -quit)
                    if [[ -n "$authored_meta" ]]; then
                      echo "config module for '${packageName}' must not author config-meta.json" >&2
                      exit 1
                    fi

                    ${stdenv.coreutils}/bin/mkdir -p "$output"
                    ${stdenv.coreutils}/bin/cp -R "$source/." "$output/"
                    ${stdenv.coreutils}/bin/chmod -R u+w "$output"
                    ${stdenv.coreutils}/bin/cp "${configModuleMetaFile}" "$output/config-meta.json"

                    invalid_entry=$(${stdenv.findutils}/bin/find "$output" ! -type d ! -type f -print -quit)
                    if [[ -n "$invalid_entry" ]]; then
                      echo "config module for '${packageName}' contains a non-regular entry: $invalid_entry" >&2
                      exit 1
                    fi
                    if [[ ! -f "$output/module.nix" ]]; then
                      echo "config module for '${packageName}' must contain a regular module.nix" >&2
                      exit 1
                    fi
                    invalid_helper=$(${stdenv.findutils}/bin/find "$output" -type f ! -name '*.nix' ! -path "$output/config-meta.json" ${lib.optionalString hasGeneratedExposeConfig ''! -path "$output/expose-config.json" ! -path "$output/generated/expose-config.json"''} -print -quit)
                    if [[ -n "$invalid_helper" ]]; then
                      echo "config module for '${packageName}' contains a non-Nix helper: $invalid_helper" >&2
                      exit 1
                    fi
                    if ! ${stdenv.diffutils}/bin/cmp -s "${configModuleMetaFile}" "$output/config-meta.json"; then
                      echo "config module for '${packageName}' did not retain the generated metadata bytes" >&2
                      exit 1
                    fi
                    ${stdenv.findutils}/bin/find "$output" -type f -name '*.nix' \
                      -exec ${self.nix}/bin/nix-instantiate --store dummy:// --parse {} \; >/dev/null
                      # Reject direct store literals and builtins.storeDir. The
                      # evaluated manifest validator is the semantic boundary for
                      # paths assembled by otherwise ordinary Nix expressions.
                      if ${stdenv.grep}/bin/grep -R -n -F "${configStoreDir}/" "$output" \
                        || ${stdenv.grep}/bin/grep -R -n -E 'builtins\.storeDir' "$output"; then
                      echo "config module for '${packageName}' contains a Nix store-path construction" >&2
                      exit 1
                    fi
                  ''
                } _ "$config" "$src"
              '';
            }
          ];
          outputChecks.config.allowedReferences = [];
          preferLocalBuild = true;
          allowSubstitutes = false;
        })
      else null;
    configModuleAttrs =
      if hasConfigModule
      then {
        config = configArtifact;
        configModule = configArtifact;
        configModuleDependencies = preparedConfigModule.dependencyOutputs;
      }
      else {};
    lowerArgs =
      # `configModule` is an mkDerivation-level arg consumed here, not passed
      # down to the raw builder (mirrors how `expose` is handled).
      (builtins.removeAttrs args ["configModule"])
      // {
        meta =
          (args.meta or {})
          // {
            maintainers = args.meta.maintainers or defaultMaintainers;
          };
        buildDeps =
          (args.buildDeps or [])
          ++ [self.nuke-references];
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
      // configModuleAttrs
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
  bootstrapTools =
    withDistributionMeta {
      description = "AOS bootstrap compiler and core build tools";
      license = "GPL-3.0-or-later WITH GCC-exception-3.1";
    }
    stdenv.cc;

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
    "cargoArtifacts"
    "cargoRoot"
    "cargoEnv"
    "cargoBuildCommands"
    "installCargoArtifacts"
    "cargoArtifactContract"
    "cargoNextest"
    "cargoNextestOpenFilesLimit"
    "nextestFlags"
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
    cargoArtifactContract =
      {
        schema = "aos.cargo-artifact-contract/v1";
        system = stdenv.hostPlatform.system;
        rust = builtins.unsafeDiscardStringContext (toString self.rust);
        buildType = args.buildType or "release";
        checkType = args.checkType or (args.buildType or "release");
        buildFeatures = args.buildFeatures or [];
        buildNoDefaultFeatures = args.buildNoDefaultFeatures or false;
        cargoEnv = args.cargoEnv or {};
        nativeInputs =
          map
          (dep: builtins.unsafeDiscardStringContext (toString dep))
          ((args.buildDeps or []) ++ (args.runtimeDeps or []));
      }
      // (args.cargoArtifactContract or {});
    inheritedArtifacts = args.cargoArtifacts or null;
    cargoBuildOnlyReferences =
      [args.cargoDeps self.rust]
      ++ lib.optional (inheritedArtifacts != null) inheritedArtifacts;
    artifactsCompatible =
      inheritedArtifacts
      == null
      || !(inheritedArtifacts ? passthru.cargoArtifactContract)
      || inheritedArtifacts.passthru.cargoArtifactContract == cargoArtifactContract;
    # Extract cargo-specific attrs for the phase generator
    cargoArgs =
      builtins.intersectAttrs (builtins.listToAttrs (
        map (n: {
          name = n;
          value = true;
        })
        cargoSpecificAttrs
      ))
      (args // {inherit cargoArtifactContract;});
    # Remove cargo-specific attrs before passing to mkDerivation
    restArgs = removeAttrs args cargoSpecificAttrs;
  in
    if !artifactsCompatible
    then throw "mkCargoPackage (${args.pname or args.name or "unnamed"}): cargoArtifacts compatibility contract does not match the consumer"
    else
      addBuilderOverrides mkCargoPackage args (
        mkDerivation (
          restArgs
          // {
            buildDeps =
              [self.rust self.jq]
              ++ (
                if args.cargoNextest or false
                then [self.cargo-nextest]
                else []
              )
              ++ (args.buildDeps or []);
            phases = phases.cargoPhases cargoArgs;
            passthru = (args.passthru or {}) // {inherit cargoArtifactContract;};
            # Cargo's JSON messages and restored target metadata contain
            # source paths by design. None of those build-only roots may
            # survive in an ordinary package output. Keep artifact-producing
            # derivations exempt: their entire purpose is to retain reusable
            # compiler state outside runtime closures.
            disallowedReferences =
              (args.disallowedReferences or [])
              ++ lib.optionals (!(args.installCargoArtifacts or false)) cargoBuildOnlyReferences;
          }
        )
      );

  # Builds a reusable Cargo target directory from a manifest-only dummy
  # workspace. The caller owns dummy-source construction so ordinary Rust
  # implementation edits do not alter this derivation's identity.
  mkCargoArtifacts = args:
    mkCargoPackage (
      args
      // {
        pname = args.pname or "cargo-artifacts";
        installBins = false;
        installLibs = false;
        installCargoArtifacts = true;
        doCheck = false;
        dontStrip = true;
        dontPatchELF = true;
        dontNukeRefs = true;
      }
    );

  mkCargoNextestCheck = args:
    mkCargoPackage (
      args
      // {
        pname = args.pname or "cargo-nextest-check";
        cargoNextest = true;
        installBins = false;
        installLibs = false;
        doCheck = true;
        buildDeps = args.buildDeps or [];
      }
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

  discoveredPackages = discoverPackages ./.;
  # Discovered factory modules are callable package constructors, not
  # derivations. Keep them in `pkgs` for their consumers, but never advertise
  # them as buildable `pkg-*` flake outputs or aggregate build dependencies.
  # This explicit structural inventory preserves lazy package enumeration:
  # probing every value with tryEval would execute unrelated IFDs.
  packageFactories = [
    "aos-uki"
    "dbus-conf"
  ];
  packageNames = builtins.attrNames (
    builtins.removeAttrs discoveredPackages (["trivial-builders"] ++ packageFactories)
    // {
      nuke-references = null;
      qemu-crucible = null;
      qemu-crucible-reference = null;
      crucible-controller = null;
      git-minimal = null;
      gcc = null;
      glibc = null;
      binutils = null;
      cc = null;
      gccUnwrapped = null;
      getent = null;
      bash = null;
      coreutils = null;
      gnumake = null;
      sed = null;
      grep = null;
      findutils = null;
      gawk = null;
      diffutils = null;
      tar = null;
      gzip = null;
      patch = null;
    }
  );

  self =
    {
      # --- Plumbing ---
      inherit mkDerivation fetchurl lib packageNames;
      inherit mkCargoPackage mkCargoArtifacts mkCargoNextestCheck mkGoPackage mkBazelPackage;
      inherit (cargoArtifactsSupport) mkCargoDummySource;
      inherit fetchCargoDeps fetchCargoVendor fetchGoModules fetchNpmDeps fetchBazelDeps;
      inherit bootstrapTools;
      fakeHash = lib.fakeHash;
      # --- Build infrastructure ---
      inherit stdenv;

      # nuke-references uses the raw (un-wrapped) mkDerivation so it can't
      # depend on itself. Every other package gets nuke-references injected
      # into buildDeps automatically via the wrapped mkDerivation above.
      nuke-references = import ../lib/build-support/nuke-references {
        mkDerivation = args:
          withDefaultMaintainers (rawMkDerivation args);
        inherit (self) bash gawk sed;
      };
    }
    // discoveredPackages
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
      zfsForKernel = kernel:
        callPackage ./filesystem/zfs.nix {inherit kernel;};
      nvidiaOpenForKernel = kernel:
        callPackage ./kernel/nvidia-open.nix {inherit kernel;};

      qemu-crucible = callPackage ./emulation/qemu.nix {
        pname = "qemu-crucible";
        enablePlugins = true;
        applyCruciblePatches = true;
      };
      qemu-crucible-reference = callPackage ./emulation/qemu.nix {
        pname = "qemu-crucible-reference";
        enablePlugins = true;
        applyCruciblePatches = false;
      };
      # Focused compatibility gates build an explicitly selected tracked patch
      # prefix. Keeping construction here preserves the same hermetic package
      # dependency injection as the published full-series QEMU package.
      qemuCrucibleNonDistributableTestPrefix = {
        pname,
        series,
        testOnlyPostPatch ? null,
      }:
        callPackage ./emulation/qemu.nix {
          inherit pname series testOnlyPostPatch;
          enablePlugins = true;
          applyCruciblePatches = true;
          testOnlyNonDistributable = true;
        };
      crucibleQemuPluginFor = qemuPackage:
        callPackage ./emulation/crucible-qemu-plugin.nix {
          qemu-crucible = qemuPackage;
        };
      crucible-controller = callPackage ./tools/crucible/crucible.nix {
        controllerOnly = true;
      };

      # Interpreter-free git for the system image (shares git.nix's source and
      # version). Used by apm/apr's runtimeTools and the server profile so the
      # image carries no Perl on git's behalf. `pkgs.git` remains the full build.
      git-minimal = callPackage ./tools/git.nix {minimal = true;};

      kubelet = callPackage ./kubernetes/kubelet.nix {inherit kubeSource;};
      kubectl = callPackage ./kubernetes/kubectl.nix {inherit kubeSource;};

      cloudcore = callPackage ./kubernetes/cloudcore.nix {inherit kubeedgeSource;};
      edgecore = callPackage ./kubernetes/edgecore.nix {inherit kubeedgeSource;};

      # --- stdenv packages (linked, not rebuilt) ---
      gcc =
        withDistributionMeta {
          description = "GNU Compiler Collection with AOS target and runtime defaults";
          license = "GPL-3.0-or-later WITH GCC-exception-3.1";
        }
        stdenv.gcc;
      glibc = withDefaultMaintainers stdenv.glibc;
      binutils = withDefaultMaintainers stdenv.binutils;
      cc =
        withDistributionMeta {
          description = "AOS C and C++ compiler wrapper toolchain";
          license = "GPL-3.0-or-later WITH GCC-exception-3.1";
        }
        stdenv.cc;
      # The unwrapped gcc-14.3.0-stage2. `pkgs.gcc` is the wrapped
      # gcc-14.3.0-wrapped; the perl Config scrub needs to substitute
      # and block the unwrapped one, since that's what Configure
      # records via specs/PATH.
      gccUnwrapped = withDefaultMaintainers stdenv.gccStage2;
      getent = withDistributionMeta {
        description = "Name service database lookup utility from GNU C Library";
        license = "LGPL-2.1-or-later";
      } (lib.getOutput "getent" stdenv.glibc);
      bash = withDefaultMaintainers stdenv.bash;
      coreutils = withDefaultMaintainers stdenv.coreutils;
      gnumake = withDefaultMaintainers stdenv.gnumake;
      sed = withDefaultMaintainers stdenv.sed;
      grep = withDefaultMaintainers stdenv.grep;
      findutils = withDefaultMaintainers stdenv.findutils;
      gawk = withDefaultMaintainers stdenv.gawk;
      diffutils = withDefaultMaintainers stdenv.diffutils;
      tar = withDefaultMaintainers stdenv.tar;
      gzip = withDefaultMaintainers stdenv.gzip;
      patch = withDefaultMaintainers stdenv.patch;
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
