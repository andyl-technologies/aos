##! ANDYL OS — Package set composition.
##! Imports all package definitions and wires dependencies together.
##! The stdenv argument provides the production toolchain (GCC 14.3.0) and all
##! build infrastructure. All packages are built hermetically from source — no nixpkgs.
{
  lib,
  stdenv,
  buildPackages ? null,
  firmwarePackages ? null,
  targetPackages ? null,
}: let
  fetchurl = lib.fetchurl;
  mkUpstream = import ./build-support/_upstream.nix {
    inherit lib fetchurl;
    platform = stdenv.hostPlatform.system;
  };
  mkGithubUpstream = import ./build-support/_github-upstream.nix {
    inherit mkUpstream;
  };
  mkManualUpstream = import ./build-support/_manual-upstream.nix {
    platform = stdenv.hostPlatform.system;
  };
  platformSupport = import ./_platform-support.nix;

  # Cross package-set roles. `self` is the host package set: its outputs run
  # on stdenv.hostPlatform. Build tools must be selected from buildPackages so
  # they execute on stdenv.buildPlatform, while targetPackages is available to
  # compiler packages whose code-generation target differs from their host.
  # Native evaluation collapses all three roles to the same fixed point.
  resolvedBuildPackages =
    if buildPackages != null
    then buildPackages
    else self;
  resolvedTargetPackages =
    if targetPackages != null
    then targetPackages
    else self;
  packageSets = {
    build = resolvedBuildPackages;
    host = self;
    target = resolvedTargetPackages;
  };

  # Existing package recipes historically referred to one package fixed point
  # for both tools and target libraries. Preserve their authored buildDeps API
  # while resolving each identifiable executable dependency through the native
  # build package set. A version mismatch is left untouched so constraint
  # validation fails visibly instead of silently substituting another tool.
  buildDependencyAliases = {
    make = "gnumake";
    node = "nodejs";
    pkgconf = "pkg-config";
    python = "python3";
    jdk = "openjdk";
  };
  spliceBuildDependency = dep:
    if !builtins.isAttrs dep
    then dep
    else let
      pname = dep.pname or null;
      mainProgram = dep.meta.mainProgram or null;
      version = dep.version or null;
      versionParts =
        if version != null
        then builtins.match "([0-9]+)\\.([0-9]+).*" version
        else null;
      major =
        if versionParts != null
        then builtins.elemAt versionParts 0
        else null;
      minor =
        if versionParts != null
        then builtins.elemAt versionParts 1
        else null;
      aliasKey =
        if pname != null && builtins.hasAttr pname buildDependencyAliases
        then pname
        else if mainProgram != null && builtins.hasAttr mainProgram buildDependencyAliases
        then mainProgram
        else null;
      candidateNames = lib.unique (
        lib.optionals (pname != null && major != null && minor != null) [
          "${pname}-${major}_${minor}"
        ]
        ++ lib.optionals (pname != null && major != null) ["${pname}-${major}"]
        ++ lib.optional (pname != null) pname
        ++ lib.optional (mainProgram != null) mainProgram
        ++ lib.optional (aliasKey != null) buildDependencyAliases.${aliasKey}
      );
      candidates = builtins.map (name: resolvedBuildPackages.${name}) (
        builtins.filter (name: builtins.hasAttr name resolvedBuildPackages) candidateNames
      );
      matchingCandidates =
        builtins.filter (
          candidate:
            version
            == null
            || !(candidate ? version)
            || version == candidate.version
        )
        candidates;
      selectedOutput = dep.outputName or null;
      selectedCandidate =
        if matchingCandidates != []
        then builtins.head matchingCandidates
        else null;
    in
      if selectedCandidate != null
      then
        if selectedOutput != null && builtins.hasAttr selectedOutput selectedCandidate
        then builtins.getAttr selectedOutput selectedCandidate
        else selectedCandidate
      else dep;

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
          buildDeps = [resolvedBuildPackages.nix];
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
                    # Directory derivations carry an AOS target marker. Nested
                    # generated inputs are module content here, not separately
                    # publishable outputs, so discard their copied metadata.
                    ${stdenv.findutils}/bin/find "$output" -path '*/nix-support/aos-target-platform' -delete
                    ${stdenv.findutils}/bin/find "$output" -type d -name nix-support -empty -delete
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
                      -exec ${resolvedBuildPackages.nix}/bin/nix-instantiate --store dummy:// --parse {} \; >/dev/null
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
    darwinCrossPhases = builtins.map (
      phase:
        if builtins.isAttrs phase && (phase.name or null) == "fixup"
        then phases.darwinCrossFixupPhase
        else phase
    ) (args.phases or []);
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
          builtins.map spliceBuildDependency (args.buildDeps or [])
          ++ [resolvedBuildPackages.nuke-references];
        passthru = (args.passthru or {}) // exposeAttrs // configModuleAttrs;
      }
      // lib.optionalAttrs (
        args
        ? phases
        && stdenv.buildPlatform.system != stdenv.hostPlatform.system
        && stdenv.hostPlatform.objectFormat == "macho"
      ) {
        phases = darwinCrossPhases;
      }
      // exposeAttrs;
    drv = rawMkDerivation lowerArgs;
    exposeCheck =
      if args ? expose
      then
        resolvedBuildPackages.runCommand "expose-payload-closure-check-${packageName}" {
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
    secondaryOutputAttrs = builtins.listToAttrs (
      builtins.map (outputName: {
        name = outputName;
        value =
          (builtins.getAttr outputName drv)
          // {
            pname = args.pname or packageName;
            meta = drv.meta or {};
          }
          // lib.optionalAttrs (args ? version) {inherit (args) version;};
      }) (builtins.filter (outputName: outputName != drv.outputName) drv.outputs)
    );
    result =
      drv
      // secondaryOutputAttrs
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
        cargo = resolvedBuildPackages.rust;
        inherit bootstrapTools;
        extraPaths = [
          stdenv.coreutils
          stdenv.tar
          stdenv.gzip
          stdenv.bash
        ];
        extraLibPaths =
          [
            resolvedBuildPackages.openssl
            resolvedBuildPackages.zlib
          ]
          ++ (args.extraLibPaths or []);
      }
    );

  fetchCargoVendor = args:
    lib.fetchCargoVendor (
      args
      // {
        cargo = resolvedBuildPackages.rust;
        python3 = resolvedBuildPackages.python3;
        git = resolvedBuildPackages.git;
        caCertificates = resolvedBuildPackages.ca-certificates;
        inherit bootstrapTools;
        extraPaths = [
          stdenv.coreutils
          stdenv.tar
          stdenv.gzip
          stdenv.bash
        ];
        extraLibPaths =
          [
            resolvedBuildPackages.openssl
            resolvedBuildPackages.zlib
          ]
          ++ (args.extraLibPaths or []);
      }
    );

  fetchGoModules = args:
    lib.fetchGoModules (
      args
      // {
        go = resolvedBuildPackages.go;
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
        nodejs = resolvedBuildPackages.nodejs;
        python3 = resolvedBuildPackages.python3;
        caCertificates = resolvedBuildPackages.ca-certificates;
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
          resolvedBuildPackages.git
        ];
        extraLibPaths =
          [
            resolvedBuildPackages.openssl
            resolvedBuildPackages.zlib
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
    "cargoNextestMaxTestThreads"
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
    # Cross-building a Rust package needs a compiler that executes on the
    # Linux builder while carrying the selected target standard library.
    # `pkgs.rust.buildTool` is that explicit role; it is distinct from both a
    # target-hosted compiler and the native compiler without the target sysroot.
    cargoBuildTool =
      if stdenv.isCross
      then
        if self.rust ? passthru && self.rust.passthru ? buildTool
        then self.rust.passthru.buildTool
        else throw "mkCargoPackage: cross Rust package does not expose passthru.buildTool"
      else resolvedBuildPackages.rust;
    cargoBuildTargetPrefix =
      lib.toUpper (builtins.replaceStrings ["-"] ["_"] stdenv.buildPlatform.config);
    cargoBuildCcPrefix = builtins.replaceStrings ["-"] ["_"] stdenv.buildPlatform.config;
    cargoTargetPrefix =
      lib.toUpper (builtins.replaceStrings ["-"] ["_"] stdenv.hostPlatform.config);
    cargoTargetRustflagsName = "CARGO_TARGET_${cargoTargetPrefix}_RUSTFLAGS";
    cargoEffectiveEnv =
      (args.cargoEnv or {})
      // lib.optionalAttrs (stdenv.isCross && stdenv.hostPlatform.isDarwin) {
        "${cargoTargetRustflagsName}" = builtins.concatStringsSep " " (
          builtins.filter
          (flag: flag != "")
          [
            (args.${cargoTargetRustflagsName} or "")
            ((args.cargoEnv or {}).${cargoTargetRustflagsName} or "")
            (args.RUSTFLAGS or "")
            "--remap-path-prefix=/build=."
          ]
        );
      };
    cargoBuildToolchain =
      if stdenv.isCross
      then
        resolvedBuildPackages.mkDerivation {
          pname = "cargo-native-build-toolchain";
          version = "0";
          src = null;
          runtimeDeps = [resolvedBuildPackages.cc];
          phases = [
            {
              name = "install";
              script = ''
                mkdir -p "$out/bin"

                write_wrapper() {
                  tool=$1
                  wrapper=$2
                  {
                    printf '%s\n' '#!${resolvedBuildPackages.bash}/bin/bash'
                    printf '%s\n' \
                      'unset AOS_CROSS_COMPILING AOS_GOARCH AOS_GOOS' \
                      'unset AOS_HARDENING_DISABLE AOS_HARDENING_ENABLE' \
                      'unset AOS_OBJECT_FORMAT AOS_RUST_TARGET' \
                      'unset AOS_TARGET_ARCH AOS_TARGET_PLATFORM' \
                      'unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH' \
                      'unset LIBRARY_PATH MACOSX_DEPLOYMENT_TARGET SDKROOT' \
                      'unset NIX_CFLAGS_COMPILE NIX_CFLAGS_LINK NIX_LDFLAGS'
                    printf 'exec %s "$@"\n' "$tool"
                  } > "$out/bin/$wrapper"
                  chmod +x "$out/bin/$wrapper"
                }

                write_wrapper ${resolvedBuildPackages.cc}/bin/cc cc
                write_wrapper ${resolvedBuildPackages.cc}/bin/c++ c++
                write_wrapper ${resolvedBuildPackages.cc}/bin/ar ar
                write_wrapper ${resolvedBuildPackages.cc}/bin/ranlib ranlib
              '';
            }
          ];
        }
      else resolvedBuildPackages.cc;
    # Cargo build scripts and proc macros execute on buildPlatform even when
    # their package is compiled for hostPlatform. Give the `cc` crate explicit
    # native tools for that role; the target-specific linker variables exported
    # by the cross stdenv continue to select the cross compiler for host output.
    cargoBuildToolchainEnv = lib.optionalAttrs stdenv.isCross {
      "CARGO_TARGET_${cargoBuildTargetPrefix}_LINKER" = "${cargoBuildToolchain}/bin/cc";
      "CARGO_TARGET_${cargoBuildTargetPrefix}_AR" = "${cargoBuildToolchain}/bin/ar";
      "CC_${cargoBuildCcPrefix}" = "${cargoBuildToolchain}/bin/cc";
      "CXX_${cargoBuildCcPrefix}" = "${cargoBuildToolchain}/bin/c++";
      "AR_${cargoBuildCcPrefix}" = "${cargoBuildToolchain}/bin/ar";
      "RANLIB_${cargoBuildCcPrefix}" = "${cargoBuildToolchain}/bin/ranlib";
    };
    cargoArtifactContract =
      {
        schema = "aos.cargo-artifact-contract/v1";
        system = stdenv.hostPlatform.system;
        rust = builtins.unsafeDiscardStringContext (toString cargoBuildTool);
        buildType = args.buildType or "release";
        checkType = args.checkType or (args.buildType or "release");
        buildFeatures = args.buildFeatures or [];
        buildNoDefaultFeatures = args.buildNoDefaultFeatures or false;
        cargoEnv = cargoEffectiveEnv;
        nativeInputs =
          map
          (dep: builtins.unsafeDiscardStringContext (toString dep))
          (
            builtins.map spliceBuildDependency (args.buildDeps or [])
            ++ (args.runtimeDeps or [])
          );
      }
      // (args.cargoArtifactContract or {});
    inheritedArtifacts = args.cargoArtifacts or null;
    cargoBuildOnlyReferences =
      [args.cargoDeps cargoBuildTool]
      ++ lib.optional stdenv.isCross cargoBuildToolchain
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
      (args
        // {
          inherit cargoArtifactContract;
          cargoEnv = cargoEffectiveEnv;
        });
    # Remove cargo-specific attrs before passing to mkDerivation
    restArgs = removeAttrs args cargoSpecificAttrs;
  in
    if !artifactsCompatible
    then throw "mkCargoPackage (${args.pname or args.name or "unnamed"}): cargoArtifacts compatibility contract does not match the consumer"
    else
      addBuilderOverrides mkCargoPackage args (
        mkDerivation (
          restArgs
          // cargoBuildToolchainEnv
          // {
            buildDeps =
              [cargoBuildTool resolvedBuildPackages.jq]
              ++ (
                if args.cargoNextest or false
                then [resolvedBuildPackages.cargo-nextest]
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
          buildDeps = [resolvedBuildPackages.go] ++ (args.buildDeps or []);
          phases = phases.goPhases goArgsWithDefaults;
          # Guard: the Go toolchain must not leak into the runtime closure.
          # -trimpath (in goPhases) prevents source-path embedding; this
          # disallowedReferences catches any residual leak at build time.
          # Matches nixpkgs' buildGoModule pattern.
          disallowedReferences = args.disallowedReferences or [resolvedBuildPackages.go];
        }
      )
    );

  # Bazel repository helpers and downloaded executable repair always run on the
  # build machine.  In a cross package set, the ordinary bootstrapTools is the
  # target compiler wrapper (and Darwin intentionally has no ELF interpreter
  # metadata), so use the native wrapper for these build-time operations.
  bazelBootstrapTools =
    if stdenv.isCross
    then resolvedBuildPackages.cc
    else bootstrapTools;

  # Wire fetchBazelDeps with AOS-specific defaults
  fetchBazelDeps = args:
    lib.fetchBazelDeps (
      args
      // {
        bootstrapTools = bazelBootstrapTools;
        caCertificates = args.caCertificates or resolvedBuildPackages.ca-certificates;
      }
    );

  mkBazelPackage = args: let
    # Extract bazel-specific parameters
    bazel = args.bazel or resolvedBuildPackages.bazel;
    jdk = args.jdk or resolvedBuildPackages.openjdk;
    tools = args.tools or [];
    caCerts = args.caCertificates or resolvedBuildPackages.ca-certificates;
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
              resolvedBuildPackages.patchelf
            ]
            ++ tools
            ++ (args.buildDeps or []);
          phases = phases.bazelPhases {
            bazelDeps = deps;
            inherit bazel jdk tools;
            bootstrapTools = bazelBootstrapTools;
            patchelf = resolvedBuildPackages.patchelf;
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

  # Lightweight package arguments break cycles introduced when foundational
  # tools are themselves target packages. Build-dependency splicing can read
  # the stable pname without forcing the target derivation; uses in runtime
  # dependencies or string interpolation still resolve the real target output.
  targetToolArgumentNames = [
    "bash"
    "coreutils"
    "gnumake"
    "sed"
    "grep"
    "findutils"
    "gawk"
    "diffutils"
    "tar"
    "gzip"
    "patch"
    "cmake"
  ];
  targetPackageArgumentProxy = name: {
    type = "derivation";
    inherit name;
    pname = name;
    outputs = ["out"];
    outputName = "out";
    outPath = self.${name}.outPath;
    drvPath = self.${name}.drvPath;
    meta = {};
    __toString = _: builtins.toString self.${name};
  };
  packageArgumentScope =
    self
    // {inherit firmwarePackages;}
    // lib.optionalAttrs stdenv.hostPlatform.isDarwin (
      builtins.listToAttrs (
        builtins.map (name: {
          inherit name;
          value = targetPackageArgumentProxy name;
        })
        targetToolArgumentNames
      )
    );

  # callPackage: import a package file and auto-fill its arguments from `self`.
  # The package file is a function whose formals are introspected via
  # builtins.functionArgs, then satisfied from the package set plus the
  # always-available helpers (mkDerivation, fetchurl).
  callPackage = path: overrides: let
    fn = import path;
    auto = builtins.intersectAttrs (builtins.functionArgs fn) (
      packageArgumentScope
      // {
        inherit mkDerivation fetchurl mkUpstream mkGithubUpstream mkManualUpstream callPackage;
      }
    );
  in
    fn (auto // overrides);

  # Shared Linux kernel source (single tarball for linux and linux-headers)
  linuxSource = import ./kernel/_source.nix {inherit fetchurl mkManualUpstream;};

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

  # Preserve an explicit source-owner association for every auto-discovered
  # package root. This is structural discovery of AOS source, not an upstream
  # name or URL heuristic. Reviewed mkUpstream metadata supersedes this
  # fail-closed manual census entry.
  discoverPackageOwners = dir: let
    entries = builtins.readDir dir;
    names = builtins.attrNames entries;
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
    subdirs =
      builtins.filter (
        name: entries.${name} == "directory" && builtins.substring 0 1 name != "_"
      )
      names;
    root = (builtins.toString ./.) + "/";
    fileOwners = builtins.listToAttrs (
      builtins.map (name: {
        name = lib.removeSuffix ".nix" name;
        value = "pkgs/${lib.removePrefix root (builtins.toString (dir + "/${name}"))}";
      })
      nixFiles
    );
    subdirOwners =
      builtins.foldl' (
        acc: subdir: acc // discoverPackageOwners (dir + "/${subdir}")
      ) {}
      subdirs;
  in
    fileOwners // subdirOwners;

  discoveredPackages = discoverPackages ./.;
  discoveredPackageOwners = discoverPackageOwners ./.;
  darwinGcc = import ./darwin/_darwin-gcc.nix {
    inherit lib mkDerivation fetchurl stdenv buildPackages;
    bash = self.bash;
    llvm = self.llvm;
    zlib = self.zlib;
  };
  darwinCc = import ./darwin/_darwin-cc.nix {
    inherit mkDerivation stdenv;
    bash = self.bash;
    llvm = self.llvm;
  };
  darwinBinutils = import ./darwin/_darwin-binutils.nix {
    inherit mkDerivation fetchurl stdenv buildPackages;
    bash = self.bash;
    zlib = self.zlib;
  };
  darwinDtraceCompiler = import ./darwin/_darwin-dtrace-compiler.nix {
    inherit mkDerivation fetchurl;
    llvm = resolvedBuildPackages.llvm;
    gcc = resolvedBuildPackages.gcc;
    glibc = resolvedBuildPackages.glibc;
    zlib = resolvedBuildPackages.zlib;
  };
  appleLibTapi = import ./darwin/_apple-libtapi.nix {
    inherit mkDerivation fetchurl;
    cmake = resolvedBuildPackages.cmake;
    ninja = resolvedBuildPackages.ninja;
    python3 = resolvedBuildPackages.python3;
  };
  darwinCctoolsLinker = import ./darwin/_darwin-cctools-linker.nix {
    inherit mkDerivation fetchurl;
    gnumake = resolvedBuildPackages.gnumake;
    llvm = resolvedBuildPackages.llvm;
    gcc = resolvedBuildPackages.gcc;
    glibc = resolvedBuildPackages.glibc;
    appleLibTapi = resolvedBuildPackages.appleLibTapi;
    darwinDtraceCompiler = resolvedBuildPackages.darwinDtraceCompiler;
    libbsd = resolvedBuildPackages.libbsd;
    util-linux = resolvedBuildPackages.util-linux;
  };
  # Discovered factory modules are callable package constructors, not
  # derivations. Keep them in `pkgs` for their consumers, but never advertise
  # them as buildable `pkg-*` flake outputs or aggregate build dependencies.
  # This explicit structural inventory preserves lazy package enumeration:
  # probing every value with tryEval would execute unrelated IFDs.
  packageFactories = [
    "aos-uki"
    "dbus-conf"
  ];
  uncheckedPackageNames = builtins.attrNames (
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
  allPackageNames = assert platformSupport.validate uncheckedPackageNames; uncheckedPackageNames;
  packageNames = platformSupport.targetPackageNames stdenv.hostPlatform.system allPackageNames;
  targetPackageNamesFor = targetSystem:
    platformSupport.targetPackageNames targetSystem allPackageNames;
  targetPackagesFor = targetSystem:
    builtins.mapAttrs platformSupport.annotate (
      platformSupport.selectTargetPackages targetSystem self allPackageNames
    );
  localMaintenanceRoots = [
    "aos"
    "aos-agent-rpc"
    "aos-boot-identity"
    "aos-ebpf-lsm-policy"
    "aos-ebpf-net-policy"
    "aos-hub"
    "aos-hub-cloudflare"
    "aos-hub-console-dist"
    "aos-hub-dialect-tests"
    "aos-hub-e2e"
    "aos-hub-worker-dist"
    "aos-hub-worker-do-e2e"
    "aos-landlock"
    "aos-recovery"
    "aos-registry-server"
    "aos-secret-reference-test"
    "aos-selinux-run"
    "aos-service-root"
    "aos-system-image-e2e-fixture"
    "aos-test-agent"
    "aos-test-driver"
    "aos-var-policy-migrate"
    "aos-verity-root-guard"
    "aos-vm"
    "apm-systemd-client-test"
    "config-module-smoke"
    "crucible"
    "crucible-controller"
    "crucible-fixtures"
    "crucible-fleet-store"
    "crucible-guest"
    "crucible-qemu-plugin"
    "crucible-qemu-trace-plugin"
    "desired-config-test"
    "desired-prune-test"
    "expose-smoke"
    "test-http-server"
    "test-static-cache-server"
  ];
  frozenMaintenanceRoots = [
    "ant-bootstrap"
    "bazel-bootstrap"
    "classpath-0_93"
    "classpath-0_99"
    "ecj-bootstrap"
    "fastjar"
    "gcc-bootstrap"
    "openjdk-bootstrap"
    "rust-1_74"
  ];
  fallbackMaintenanceUnit = name: package: let
    rawVersion = package.version or package.name or "unknown";
    version =
      if builtins.isString rawVersion && rawVersion != ""
      then rawVersion
      else "unknown";
    local = builtins.elem name localMaintenanceRoots;
    frozen = builtins.elem name frozenMaintenanceRoots;
  in
    {
      unitId = name;
      family = name;
      stream = "manual";
      classification =
        if local
        then "local"
        else if frozen
        then "frozen"
        else "manual";
      package =
        if local
        then null
        else {
          currentVersion = version;
          versionProjection = {
            kind = "component-field";
            component = "main";
            field = "comparisonVersion";
          };
        };
      components =
        if local
        then {}
        else {
          main = {
            current = {
              upstreamId = version;
              comparisonVersion = version;
            };
            primary = null;
            advisors = [];
            releasePolicy = {
              strategy = "channel";
              versionScheme = "provider";
              seriesMajor = null;
              allowPrerelease = false;
              minimumAgeDays = 0;
            };
            sources = {};
          };
        };
      artifacts = {};
      owner = discoveredPackageOwners.${name} or "pkgs/default.nix";
      members = [name];
      platforms = [stdenv.hostPlatform.system];
      policy = {
        lifecycle =
          if frozen
          then "frozen"
          else "supported";
        riskFloor =
          if local
          then "low"
          else "high";
        repairScope = [];
      };
    }
    // lib.optionalAttrs (!local) {
      reason =
        if frozen
        then "Historical bootstrap input is intentionally pinned pending explicit bootstrap-chain review."
        else "No reviewed typed upstream contract is declared; updates require a maintainer-authored plan.";
    }
    // lib.optionalAttrs frozen {
      reviewAfter = "2027-01-01";
    };
  unmergedMaintenanceUnits =
    builtins.map (
      name: let
        package = self.${name};
        declared =
          if
            builtins.isAttrs package
            && package ? passthru.aos.maintenance
          then builtins.removeAttrs package.passthru.aos.maintenance ["schema"]
          else fallbackMaintenanceUnit name package;
        eligiblePlatforms = builtins.sort builtins.lessThan (builtins.filter (
            system:
              builtins.all (member: platformSupport.supportsTarget system member) declared.members
          )
          platformSupport.canonicalSystems);
      in
        declared // {platforms = eligiblePlatforms;}
    )
    packageNames;
  maintenanceUnitIndex =
    builtins.foldl' (
      units: unit: let
        existing = units.${unit.unitId} or null;
        comparable = value: builtins.removeAttrs value ["members" "platforms"];
        merged =
          if existing == null
          then unit
          else if comparable existing != comparable unit
          then throw "maintenance unit '${unit.unitId}' has conflicting member metadata"
          else
            existing
            // {
              members = builtins.sort builtins.lessThan (lib.unique (existing.members ++ unit.members));
              platforms = builtins.sort builtins.lessThan (lib.unique (existing.platforms ++ unit.platforms));
            };
      in
        units // {${unit.unitId} = merged;}
    ) {}
    unmergedMaintenanceUnits;
  maintenanceUnits = builtins.attrValues maintenanceUnitIndex;
  maintenanceInventory = {
    schema = "aos.maintenance-inventory/v1";
    units = builtins.sort (left: right: left.unitId < right.unitId) maintenanceUnits;
  };

  self =
    {
      # --- Plumbing ---
      inherit mkDerivation fetchurl mkUpstream mkGithubUpstream mkManualUpstream lib packageNames allPackageNames;
      inherit maintenanceInventory;
      inherit platformSupport targetPackageNamesFor targetPackagesFor;
      inherit mkCargoPackage mkCargoArtifacts mkCargoNextestCheck mkGoPackage mkBazelPackage;
      inherit (cargoArtifactsSupport) mkCargoDummySource;
      inherit fetchCargoDeps fetchCargoVendor fetchGoModules fetchNpmDeps fetchBazelDeps;
      inherit bootstrapTools;
      buildPackages = resolvedBuildPackages;
      hostPackages = self;
      targetPackages = resolvedTargetPackages;
      inherit packageSets;
      inherit spliceBuildDependency;
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
      # GLib bootstraps GObject Introspection, while downstream consumers need
      # GLib's GIR metadata. Rebuild this internal variant after the bootstrap
      # scanner exists to break that dependency cycle cleanly.
      glibWithIntrospection = callPackage ./libs/glib.nix {
        enableIntrospection = true;
        gobject-introspection = self.gobject-introspection;
      };
      linux = callPackage ./kernel/linux.nix {inherit linuxSource;};
      # Build a kernel variant with extra kconfig appended. Use this — not
      # `linux.override { extraConfig = …; }` — for deployment kernels:
      # `extraConfig` is a linux.nix function arg consumed before
      # mkDerivation, so the inherited `.override` hook can't reach it
      # (silent no-op). callPackage threads it directly. (RFC-0006 lockdown.)
      linuxWith = extraConfig:
        callPackage ./kernel/linux.nix {inherit linuxSource extraConfig;};
      # Fixture kernels may deliberately omit facilities required by deployed
      # systems. Keep that exception explicit and unavailable through linuxWith.
      linuxFixtureWith = extraConfig:
        callPackage ./kernel/linux.nix {
          inherit linuxSource extraConfig;
          enforceRequiredConfig = false;
        };
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

      # The cross stdenv keeps a native-built SDK internally for bootstrapping.
      # The public package is rebuilt through the host package set so APR sees
      # the selected Darwin target marker rather than the Linux scheduler.
      darwin-sdk = discoveredPackages.darwin-sdk;
      darwinSdk = self.darwin-sdk;
      darwin-runtimes =
        if stdenv.hostPlatform.isDarwin
        then withDefaultMaintainers stdenv.darwinRuntimes
        else null;
      darwinRuntimes = self.darwin-runtimes;
      java-native-foundation =
        if stdenv.hostPlatform.isDarwin
        then discoveredPackages.java-native-foundation
        else null;

      # --- stdenv packages (linked, not rebuilt) ---
      gcc =
        (withDistributionMeta {
            description = "GNU Compiler Collection with AOS target and runtime defaults";
            license = "GPL-3.0-or-later WITH GCC-exception-3.1";
          }
          (
            if stdenv.hostPlatform.isDarwin
            then darwinGcc
            else stdenv.gcc
          ))
        // {version = "14.3.0";};
      glibc =
        (withDistributionMeta {
            description = "GNU C Library for the AOS target runtime";
            license = "LGPL-2.1-or-later";
          }
          (
            stdenv.glibc
            // lib.optionalAttrs stdenv.hostPlatform.isDarwin {
              dev = stdenv.glibc;
              static = stdenv.glibc;
            }
          ))
        // {version = "2.39.0";};
      binutils =
        (withDistributionMeta {
            description = "GNU binary utilities for the AOS target toolchain";
            license = "GPL-3.0-or-later";
          }
          (
            if stdenv.hostPlatform.isDarwin
            then darwinBinutils
            else stdenv.binutils
          ))
        // {version = "2.41.0";};
      inherit darwinDtraceCompiler;
      inherit appleLibTapi;
      inherit darwinCctoolsLinker;
      cc =
        (withDistributionMeta {
            description = "AOS C and C++ compiler wrapper toolchain";
            license = "GPL-3.0-or-later WITH GCC-exception-3.1";
          }
          (
            if stdenv.hostPlatform.isDarwin
            then darwinCc
            else stdenv.cc
          ))
        // {version = "0.1.0";};
      # The unwrapped gcc-14.3.0-stage2. `pkgs.gcc` is the wrapped
      # gcc-14.3.0-wrapped; the perl Config scrub needs to substitute
      # and block the unwrapped one, since that's what Configure
      # records via specs/PATH.
      gccUnwrapped =
        (withDistributionMeta {
            description = "Unwrapped GNU Compiler Collection for the AOS target toolchain";
            license = "GPL-3.0-or-later WITH GCC-exception-3.1";
          }
          (
            if stdenv.hostPlatform.isDarwin
            then darwinGcc
            else if stdenv ? gccStage2
            then stdenv.gccStage2
            else stdenv.gcc
          ))
        // {version = "14.3.0";};
      gcc-libs =
        if stdenv.hostPlatform.isDarwin
        then withDefaultMaintainers darwinGcc
        else discoveredPackages.gcc-libs;
      getent =
        (withDistributionMeta {
            description = "Name service database lookup utility from GNU C Library";
            license = "LGPL-2.1-or-later";
          }
          (lib.getOutput "getent" stdenv.glibc))
        // {version = "2.39.0";};
      # Native package sets retain the final stdenv tools. Darwin package roots
      # must be actual target builds; Linux build tools remain available only
      # through buildPackages and build-dependency splicing.
      bash = withDefaultMaintainers (
        if stdenv.hostPlatform.isDarwin
        then discoveredPackages.bash
        else stdenv.bash
      );
      coreutils = withDefaultMaintainers (
        if stdenv.hostPlatform.isDarwin
        then discoveredPackages.coreutils
        else stdenv.coreutils
      );
      gnumake = withDefaultMaintainers (
        if stdenv.hostPlatform.isDarwin
        then discoveredPackages.gnumake
        else stdenv.gnumake
      );
      sed = withDefaultMaintainers (
        if stdenv.hostPlatform.isDarwin
        then discoveredPackages.sed
        else stdenv.sed
      );
      grep = withDefaultMaintainers (
        if stdenv.hostPlatform.isDarwin
        then discoveredPackages.grep
        else stdenv.grep
      );
      findutils = withDefaultMaintainers (
        if stdenv.hostPlatform.isDarwin
        then discoveredPackages.findutils
        else stdenv.findutils
      );
      gawk = withDefaultMaintainers (
        if stdenv.hostPlatform.isDarwin
        then discoveredPackages.gawk
        else stdenv.gawk
      );
      diffutils = withDefaultMaintainers (
        if stdenv.hostPlatform.isDarwin
        then discoveredPackages.diffutils
        else stdenv.diffutils
      );
      tar = withDefaultMaintainers (
        if stdenv.hostPlatform.isDarwin
        then discoveredPackages.tar
        else stdenv.tar
      );
      gzip = withDefaultMaintainers (
        if stdenv.hostPlatform.isDarwin
        then discoveredPackages.gzip
        else stdenv.gzip
      );
      patch = withDefaultMaintainers (
        if stdenv.hostPlatform.isDarwin
        then discoveredPackages.patch
        else stdenv.patch
      );
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
