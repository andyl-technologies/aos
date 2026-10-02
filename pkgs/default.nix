##! ANDYL OS — Package set composition.
##! Imports all package definitions and wires dependencies together.
##! The stdenv argument provides the production toolchain (GCC 16.2.0) and all
##! build infrastructure. All packages are built hermetically from source — no nixpkgs.
{
  lib,
  stdenv,
  buildPackages ? null,
  firmwarePackages ? null,
  targetPackages ? null,
  releasePlatforms ? [stdenv.hostPlatform],
  sharedGoCacheDir ? null,
  sharedBazelCacheDir ? null,
  sharedRustTargetDir ? null,
  sharedRustIncremental ? false,
  sharedAccacheDir ? null,
  sharedAccacheStateDir ? null,
  ordinaryToolchainPackages ? null,
}:
assert (sharedAccacheDir == null) == (sharedAccacheStateDir == null); let
  anySharedCache =
    sharedGoCacheDir
    != null
    || sharedBazelCacheDir != null
    || sharedRustTargetDir != null
    || sharedRustIncremental
    || sharedAccacheDir != null;
  fetchurl = lib.fetchurl;
  fetchgit = lib.fetchgit;
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
  declarationPackages =
    if buildPackages != null
    then buildPackages
    else self;
  platformSupport = import ./_target-policy.nix {
    inherit lib releasePlatforms;
    # Package declarations are invariant across splices. Reading them from
    # the native package set avoids evaluating an unsupported cross package
    # merely to decide that its host constraint excludes it.
    packages = declarationPackages;
  };

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
  # Companion metadata is an artifact of a package, not another installable
  # package. Using the public builder here would recursively attach companions.
  # Compiler inputs can make inert catalog locators become scanned references.
  # Keep these builders limited to text tools; explicit text contexts still
  # retain module sources and qualification-selected payloads normally.
  artifactBuilders.writeTextFile = lib.build.writeArtifact {
    inherit (resolvedBuildPackages) bash coreutils;
    system = stdenv.buildPlatform.system;
  };
  qualificationArtifactsFor = package:
    lib.optionalAttrs (package ? qualification) (let
      packageName = package.catalogName or package.pname or package.name;
      projected = lib.qualification.projectPackageProbe {
        owner = packageName;
        probe = package.qualification.packageProbe;
      };
      dependencies = builtins.genericClosure {
        startSet = [
          {
            key = builtins.toString package;
            value = package;
          }
        ];
        operator = item:
          map (dependency: {
            key = builtins.toString dependency;
            value = dependency;
          }) ((item.value.runtimeDeps or [])
            ++ (item.value.buildDeps or [])
            ++ (item.value.propagatedDeps or [])
            ++ (map (import ../lib/packages/module-dependencies.nix).seed (item.value.moduleDeps or [])));
      };
      retainOutput = item: knownOutputs: output: let
        selector = {
          package = item.value.catalogName or item.value.pname or item.value.name;
          inherit output;
        };
        key = builtins.toJSON selector;
        path = builtins.toString (item.value.${output} or item.value);
      in
        if !(builtins.elem selector projected.selectors)
        then knownOutputs
        # A package qualifies its own outputs, even when building or testing
        # it needs an earlier variant of that same package. Dependency
        # selectors still require a unique artifact in the declared closure.
        else if selector.package == packageName && item.key != builtins.toString package
        then knownOutputs
        else if knownOutputs ? ${key} && knownOutputs.${key} != path
        then throw "Package '${packageName}' qualification selects conflicting artifacts for ${key}."
        else knownOutputs // {${key} = path;};
      outputs = builtins.foldl' (known: item:
        builtins.foldl' (retainOutput item) known (item.value.outputs or ["out"])) {}
      dependencies;
      artifacts =
        map (selector: let
          key = builtins.toJSON selector;
        in {
          inherit selector;
          path = outputs.${key} or (throw "Package '${packageName}' qualification selector ${key} is outside its declared dependency closure.");
        })
        projected.selectors;
      document = {
        schema = "aos.package.qualification";
        package = {
          name = packageName;
          version = package.version or "0";
        };
        inherit (projected) selectors;
        inherit artifacts;
        probe = projected.value;
      };
    in {
      qualificationDocument = document;
      qualificationArtifact = artifactBuilders.writeTextFile {
        name = "${packageName}-qualification";
        destination = "/qualification.json";
        text = builtins.toJSON document;
      };
    });

  packageVersions = import ../lib/packages/version.nix;
  artifactLib = import ../lib/packages/artifacts.nix {};
  nativeArtifactsFor = package: let
    deploymentLib = import ../lib {system = stdenv.hostPlatform.system;};
    compatibility = import ../lib/packages/release-compatibility.nix {lib = deploymentLib;};
    packageName = artifactLib.nameFor package;
    deployment = assert compatibility.checkSeeds [package]; artifactLib.envelope package;
    documentation =
      (deploymentLib.evalPackageModules {
        scope = ["package" packageName];
        packages = [package];
      }).documentation;
    documentationSources =
      builtins.map (record: record.configRoot)
      (deploymentLib.packageModules.closure [package]);
    # Documentation can describe available payloads without selecting them.
    # Only its authenticated module source locations carry retention contexts.
    documentationText =
      builtins.appendContext
      (builtins.unsafeDiscardStringContext (builtins.toJSON documentation))
      (builtins.getContext (builtins.toJSON documentationSources));
  in {
    inherit deployment documentation;
    deploymentArtifact = artifactBuilders.writeTextFile {
      name = "${packageName}-${package.outputName or "out"}-deployment";
      destination = "/deployment.json";
      text = builtins.toJSON deployment;
    };
    documentationArtifact = artifactBuilders.writeTextFile {
      name = "${packageName}-documentation";
      destination = "/options.json";
      text = documentationText;
    };
  };

  # Audited bootstrap payloads keep their derivations while receiving the same
  # source-independent publication companions as ordinary packages.
  withNativeArtifacts = package: let
    actualOutput = package.outputName or "out";
    primaryOutput =
      if builtins.elem actualOutput (package.outputs or ["out"])
      then actualOutput
      else "out";
    common =
      builtins.intersectAttrs {
        pname = null;
        catalogName = null;
        version = null;
        versionRequirement = null;
        meta = null;
        module = null;
        moduleDeps = null;
        runtimeDeps = null;
        system = null;
        targetSystem = null;
        platformSupport = null;
        qualification = null;
        qualificationDocument = null;
        qualificationArtifact = null;
      }
      package;
    views = builtins.listToAttrs (builtins.map (output: {
      name = output;
      value =
        if output == primaryOutput
        then result
        else let
          selected = (package.${output} or package) // common // views // nativeArtifactsFor selected;
        in
          selected;
    }) (package.outputs or [primaryOutput]));
    result = package // views // {${actualOutput} = result;} // nativeArtifactsFor result;
  in
    if package ? deploymentArtifact
    then package
    else result;

  defaultMaintainers = ["Andyl, Inc."];

  # Keep public compiler and language-toolchain attrs on their ordinary
  # outputs. Some recipes name target libraries as runtime inputs, so merely
  # disabling wrappers on their final derivation is not enough to preserve
  # the whole ladder's identity.
  isToolchainName = name:
    builtins.elem name ["gcc" "gcc-libs" "binutils" "bazel-bootstrap" "openjdk-bootstrap"]
    || builtins.match "(rust|go|llvm|openjdk|bazel)(-.*)?" name != null;

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
  withPlatformSupport = declaration: package:
    withNativeArtifacts (package
      // {
        inherit (declaration) platformSupport;
      });

  # Bootstrap tools retain their audited derivations, but need the same public
  # metadata as their target builds. Never attach a different source version.
  withBootstrapPublication = name: let
    # Read only the declaration: realizing the target derivation here would
    # recurse through the very bootstrap tools whose metadata we are filling.
    package = callPackage (./base + "/${name}.nix") {
      mkDerivation = attrs: attrs;
    };
    release = packageVersions.normalize package.version;
    bootstrap = stdenv.${name};
    version = (builtins.parseDrvName bootstrap.name).version;
    annotated =
      (withDistributionMeta package.meta bootstrap)
      // {
        inherit version;
        inherit (release) versionRequirement;
        pname = name;
        catalogName = name;
      };
  in
    assert version == release.version;
      if !(package ? qualification)
      then annotated
      else
        withQualification {
          packageName = name;
          version = package.version;
          packageProbe = package.qualification.packageProbe;
        }
        annotated;

  cargoArtifactsSupport = import ./build-support/_cargo-artifacts.nix {
    inherit lib mkDerivation;
  };

  # The selected OCI backend owns its artifact constructors. Package recipes
  # receive this API through callPackage instead of importing backend-private
  # implementation files or rebuilding the tool splice themselves.
  mkOciTools = {
    buildPackages ? resolvedBuildPackages,
    mkReferenceGraph ?
      lib.build.referenceGraph {
        inherit (buildPackages) mkDerivation coreutils jq;
      },
  }:
    import ./containers/_aos-oci-backend/oci {
      inherit lib mkReferenceGraph;
      runArtifact = lib.build.runArtifact {pkgs = buildPackages;};
      deploymentChecker = buildPackages.aos-deployment-check;
      inherit (buildPackages) mkDerivation coreutils findutils gzip jq tar;
    };
  ociTools = mkOciTools {};
  mkOciMultiPlatformContainer = args:
    import ./containers/_aos-oci-backend/container/multi-platform.nix (
      args
      // {
        inherit lib;
        pkgs = self;
        oci = ociTools;
      }
    );
  mkOciPackageEvidence = {packageSet ? self, ...} @ args:
    import ./containers/_aos-oci-backend/container/package-evidence.nix (
      (builtins.removeAttrs args ["packageSet"])
      // {
        inherit lib;
        pkgs = packageSet;
      }
    );

  # Qualification metadata is independent of the package deployment interface.
  withQualification = {
    packageName,
    version,
    packageProbe,
    platformSupport ? null,
  }: package: let
    release = packageVersions.normalize version;
    normalized = lib.qualification.normalizePackageProbe packageProbe;
    # Giving a selected derivation output its own public package coordinate
    # creates one logical payload, rather than borrowing its parent's siblings.
    selectedAlias =
      (package.outputName or "out")
      != "out"
      && packageName != (package.catalogName or package.pname or package.name);
    payload =
      if selectedAlias
      then
        (builtins.removeAttrs package (package.outputs or []))
        // {
          outputs = ["out"];
          out = package;
        }
      else package;
    authored =
      payload
      // {
        catalogName = packageName;
        inherit (release) version versionRequirement;
        qualification.packageProbe = normalized;
      };
    result =
      authored
      // qualificationArtifactsFor authored
      // lib.optionalAttrs (platformSupport != null) {
        platformSupport = lib.packagePlatform.normalize "package '${packageName}' platformSupport" platformSupport;
      };
  in
    # A qualified alias may start from a package that already has companions.
    # Regenerate them with this alias's release policy and identity.
    builtins.deepSeq normalized (withNativeArtifacts (builtins.removeAttrs result [
      "deployment"
      "documentation"
      "deploymentArtifact"
      "documentationArtifact"
    ]));

  # Use stdenv's mkDerivation (includes cc-wrapper and tools in PATH),
  # wrapped to inject nuke-references into every package's buildDeps so
  # the scrubPhase from lib/derivations.nix can rewrite build-toolchain
  # store paths out of the output (matches nixpkgs nuke-refs idiom).
  mkDerivation = args: let
    release = packageVersions.normalize (args.version or "0");
    packageName =
      args.catalogName
      or args.pname
      or args.name
      or (throw "mkDerivation: package must set pname or name");
    packagePlatformSupport =
      if (args.platformSupport or null) == null
      then null
      else lib.packagePlatform.normalize "package '${packageName}' platformSupport" args.platformSupport;
    moduleArtifact = import ../lib/packages/module-source.nix {
      name = packageName;
      source = args.module or null;
    };
    moduleDeps = args.moduleDeps or [];
    checkedQualification =
      if !(args ? qualification)
      then null
      else if !builtins.isAttrs args.qualification || builtins.attrNames args.qualification != ["packageProbe"]
      then throw "Package '${packageName}' qualification must contain exactly packageProbe."
      else {packageProbe = lib.qualification.normalizePackageProbe args.qualification.packageProbe;};
    qualificationMetadata =
      if checkedQualification == null
      then {}
      else
        qualificationArtifactsFor (drv
          // {
            catalogName = packageName;
            version = release.version;
            qualification = checkedQualification;
            inherit moduleDeps;
            buildDeps = args.buildDeps or [];
            runtimeDeps = artifactLib.dependencyValues (args.runtimeDeps or []);
            propagatedDeps = args.propagatedDeps or [];
          });
    nativeArtifacts =
      if args ? abilities || args ? configModule
      then throw "Package '${packageName}' must migrate to module/moduleDeps."
      else nativeArtifactsFor (result // {runtimeDeps = args.runtimeDeps or [];});
    crossFixupPhase =
      if stdenv.hostPlatform.objectFormat == "macho"
      then phases.darwinCrossFixupPhase
      else phases.crossElfFixupPhase;
    crossPhases = builtins.map (
      phase:
        if
          builtins.isAttrs phase
          && (phase.name or null) == "fixup"
          && (phase.script or null) == phases.fixupPhase.script
        then crossFixupPhase
        else phase
    ) (args.phases or []);
    # CMake application recipes opt in explicitly. Injecting launchers into
    # every package would change bootstrap and language-toolchain identities.
    cacheCCompilers =
      sharedAccacheDir
      != null
      && sharedAccacheStateDir != null
      && (args.cacheCCompilers or false)
      && (args.sharedBuildCache or true)
      && !isToolchainName packageName;
    cCompilerCacheEnvironment = mkAccacheEnvironment {
      compilers = {
        "${builtins.unsafeDiscardStringContext (toString stdenv.cc)}/bin/cc" = "c";
        "${builtins.unsafeDiscardStringContext (toString stdenv.cc)}/bin/gcc" = "c";
        "${builtins.unsafeDiscardStringContext (toString stdenv.cc)}/bin/c++" = "c";
        "${builtins.unsafeDiscardStringContext (toString stdenv.cc)}/bin/g++" = "c";
      };
      roots =
        [stdenv.cc]
        ++ builtins.map spliceBuildDependency (args.buildDeps or [])
        ++ artifactLib.dependencyValues (args.runtimeDeps or [])
        ++ (args.propagatedDeps or []);
      cacheDir = sharedAccacheDir;
      stateDir = sharedAccacheStateDir;
      llvmOptions = args.accacheLlvmOptions or {};
    };
    lowerArgs =
      # Deployment modules are retained as source artifacts, never evaluated by
      # the payload builder or passed as low-level derivation attributes.
      (builtins.removeAttrs args ["abilities" "module" "moduleDeps" "catalogName" "platformSupport" "qualification" "configModule" "sharedBuildCache" "cacheCCompilers" "accacheLlvmOptions"])
      // lib.optionalAttrs (args ? version) {inherit (release) version;}
      // lib.optionalAttrs cacheCCompilers (builtins.removeAttrs cCompilerCacheEnvironment ["RUSTC_WRAPPER"])
      // {
        meta =
          (args.meta or {})
          // {
            maintainers = args.meta.maintainers or defaultMaintainers;
          };
        buildDeps =
          builtins.map spliceBuildDependency (args.buildDeps or [])
          ++ [resolvedBuildPackages.nuke-references];
        runtimeDeps = artifactLib.dependencyValues (args.runtimeDeps or []);
        passthru = args.passthru or {};
      }
      // lib.optionalAttrs (
        args
        ? phases
        && stdenv.buildPlatform.system != stdenv.hostPlatform.system
      ) {
        # Phase-generating language builders embed the shared fixup record.
        # Replace only that exact implementation so package-authored phases
        # that happen to use the same name retain their behavior.
        phases = crossPhases;
      };
    drv = rawMkDerivation lowerArgs;
    deploymentAttrs =
      {
        catalogName = packageName;
        inherit (release) versionRequirement;
        inherit moduleDeps;
        inherit (nativeArtifacts) deployment documentation deploymentArtifact documentationArtifact;
        targetSystem = stdenv.hostPlatform.system;
      }
      // lib.optionalAttrs (moduleArtifact != null) {
        module = moduleArtifact;
      }
      // lib.optionalAttrs (checkedQualification != null) {
        qualification = checkedQualification;
        inherit (qualificationMetadata) qualificationDocument qualificationArtifact;
      };
    platformAttrs = lib.optionalAttrs (packagePlatformSupport != null) {
      platformSupport = packagePlatformSupport;
    };
    secondaryOutputAttrs = builtins.listToAttrs (
      builtins.map (outputName: {
        name = outputName;
        value = let
          selected =
            addBuilderOverrides
            (updatedArgs: builtins.getAttr outputName (mkDerivation updatedArgs))
            args
            (
              (builtins.getAttr outputName drv)
              // {
                pname = args.pname or packageName;
                meta = drv.meta or {};
              }
              // lib.optionalAttrs (args ? version) {inherit (release) version;}
              // deploymentAttrs
              // platformAttrs
              // secondaryOutputAttrs
              // {${drv.outputName} = result;}
              // nativeArtifactsFor (selected // {runtimeDeps = args.runtimeDeps or [];})
            );
        in
          selected;
      }) (builtins.filter (outputName: outputName != drv.outputName) drv.outputs)
    );
    result = drv // secondaryOutputAttrs // {${drv.outputName} = result;} // deploymentAttrs // platformAttrs;
  in
    if args ? versionRequirement || args ? moduleCompatibility
    then throw "Package compatibility is derived from version; versionRequirement and moduleCompatibility cannot be authored."
    else builtins.deepSeq checkedQualification (addBuilderOverrides mkDerivation args result);

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
          resolvedBuildPackages.xz
          stdenv.patch
          stdenv.bash
        ];
        # Packaged fetch tools resolve their own runtime libraries. Retain an
        # explicit caller override without imposing one on every subprocess.
        extraLibPaths = args.extraLibPaths or [];
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
          stdenv.sed
          resolvedBuildPackages.xz
          stdenv.bash
        ];
        # Packaged fetch tools resolve their own runtime libraries. Retain an
        # explicit caller override without imposing one on every subprocess.
        extraLibPaths = args.extraLibPaths or [];
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
        extraPaths =
          [
            stdenv.coreutils
            stdenv.tar
            stdenv.gzip
            stdenv.bash
            stdenv.gnumake
            stdenv.sed
            stdenv.grep
            stdenv.gawk
            stdenv.findutils
          ]
          ++ lib.optional (args.requiresGit or true) resolvedBuildPackages.git;
        # Packaged fetch tools resolve their own runtime libraries. Retain an
        # explicit caller override without imposing one on every subprocess.
        extraLibPaths = args.extraLibPaths or [];
      }
    );

  # Explicit application opt-in for C/C++ builders. mkCargoPackage uses the
  # same manifest primitive below; toolchain packages never acquire a wrapper.
  mkAccacheEnvironment = import ./build-support/_accache.nix {
    inherit lib;
    mkDerivation = rawMkDerivation;
    jq = resolvedBuildPackages.jq;
    accache =
      if ordinaryToolchainPackages != null
      then ordinaryToolchainPackages.accache
      else resolvedBuildPackages.accache;
  };

  # Attrs that mkCargoPackage consumes (not passed to mkDerivation)
  cargoSpecificAttrs = [
    "cargoDeps"
    "cargoArtifacts"
    "cargoRoot"
    "cargoWorkspaceMembers"
    "cargoEnv"
    "cargoBuildCommands"
    "installCargoArtifacts"
    "cargoArtifactContract"
    "cargoNextest"
    "cargoNextestProfile"
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
    "captureModuleLock"
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

  # Language builders consume dependency source bundles in addition to the
  # package's primary source. Keep both in the release evidence contract even
  # though these evaluation-only attributes do not enter the runtime closure.
  appendEvidenceSources = passthru: sources:
    passthru
    // {
      evidenceSources = (passthru.evidenceSources or []) ++ sources;
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
            ++ artifactLib.dependencyValues (args.runtimeDeps or [])
          );
      }
      // (args.cargoArtifactContract or {});
    inheritedArtifacts = args.cargoArtifacts or null;
    # Development builds keep Cargo's own target directory across Nix
    # sandboxes. A contract-derived key separates toolchains, dependencies,
    # features, and compiler settings while source edits keep the same cache.
    sharedCargoTarget =
      sharedRustTargetDir
      != null
      && (args.sharedBuildCache or true)
      && !(args.installCargoArtifacts or false)
      && !isToolchainName (args.pname or args.name or "");
    cargoTargetKey = builtins.hashString "sha256" (builtins.toJSON {
      # Earlier trees can contain CMake directories whose modes defeat the
      # inherited ACL. Start a fresh tree when introducing exit-time repair.
      cachePermissionsVersion = 1;
      inherit cargoArtifactContract;
      cargoDeps = toString args.cargoDeps;
      cargoRoot = args.cargoRoot or ".";
      cargoFlags = args.cargoFlags or "";
      cargoBuildCommands = args.cargoBuildCommands or [];
      gitDeps = args.gitDeps or [];
      rustFlags = args.RUSTFLAGS or "";
      cc = toString stdenv.cc;
      inherit cargoBuildToolchainEnv;
    });
    cargoTargetDir = "${sharedRustTargetDir}/${args.pname or args.name or "cargo"}-${builtins.substring 0 20 cargoTargetKey}";
    cargoSourceId = builtins.hashString "sha256" (builtins.toJSON {
      source = toString args.src;
      patches = map toString (args.patches or []);
      postUnpack = args.postUnpack or "";
      prePatch = args.prePatch or "";
      postPatch = args.postPatch or "";
      preConfigure = args.preConfigure or "";
      postConfigure = args.postConfigure or "";
      preBuild = args.preBuild or "";
    });
    incrementalCargoBuild =
      sharedRustIncremental
      && (args.sharedBuildCache or true)
      && !(args.installCargoArtifacts or false)
      && !isToolchainName (args.pname or args.name or "");
    # The mutable target directory replaces the dummy-source artifact seed in
    # development mode. Do not extract that tarball into an active shared tree.
    effectiveArtifacts =
      if sharedCargoTarget
      then null
      else inheritedArtifacts;
    cacheRustActions =
      sharedAccacheDir
      != null
      && sharedAccacheStateDir != null
      && (args.sharedBuildCache or true)
      && !isToolchainName (args.pname or args.name or "")
      && (args.pname or "") != "accache";
    rustActionEnvironment = mkAccacheEnvironment {
      compilers = {"${builtins.unsafeDiscardStringContext (toString cargoBuildTool)}/bin/rustc" = "rust";};
      roots =
        [cargoBuildTool]
        ++ builtins.map spliceBuildDependency (args.buildDeps or [])
        ++ artifactLib.dependencyValues (args.runtimeDeps or []);
      cacheDir = sharedAccacheDir;
      stateDir = sharedAccacheStateDir;
      llvmOptions = args.accacheLlvmOptions or {};
    };
    cargoBuildOnlyReferences =
      [args.cargoDeps cargoBuildTool]
      ++ lib.optional stdenv.isCross cargoBuildToolchain
      ++ lib.optional (effectiveArtifacts != null) effectiveArtifacts;
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
          cargoArtifacts = effectiveArtifacts;
        })
      // lib.optionalAttrs sharedCargoTarget {
        inherit cargoSourceId;
        cargoCacheLock = resolvedBuildPackages.util-linux;
      };
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
          // lib.optionalAttrs cacheRustActions rustActionEnvironment
          // lib.optionalAttrs sharedCargoTarget {
            CARGO_TARGET_DIR = cargoTargetDir;
          }
          // lib.optionalAttrs incrementalCargoBuild {
            CARGO_INCREMENTAL = "1";
          }
          // {
            buildDeps =
              [cargoBuildTool resolvedBuildPackages.jq]
              ++ lib.optional sharedCargoTarget resolvedBuildPackages.util-linux
              ++ (
                if args.cargoNextest or false
                then [resolvedBuildPackages.cargo-nextest]
                else []
              )
              ++ (args.buildDeps or []);
            phases = phases.cargoPhases cargoArgs;
            passthru =
              appendEvidenceSources (args.passthru or {}) [
                args.src
                args.cargoDeps
              ]
              // {inherit cargoArtifactContract;};
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

  # AOS packages use their existing Cargo package selectors as the single
  # source of truth for the local workspace source they build and test.
  mkAosCargoPackage = args:
    if args ? src
    then throw "mkAosCargoPackage derives src from its Cargo package selectors"
    else
      addBuilderOverrides mkAosCargoPackage args (
        mkCargoPackage (
          (removeAttrs args ["aosWorkspaceIntegrationInputs"])
          // (removeAttrs (aosWorkspaceSliceFor args) ["configureWorkspace"])
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
        sharedBuildCache = false;
        passthru = (args.passthru or {}) // {isCargoArtifacts = true;};
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
    sharedGoBuild =
      sharedGoCacheDir
      != null
      && (args.sharedBuildCache or true)
      && !isToolchainName (args.pname or args.name or "");
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
        // lib.optionalAttrs sharedGoBuild {
          GOCACHE = sharedGoCacheDir;
        }
        // {
          buildDeps = [resolvedBuildPackages.go] ++ (args.buildDeps or []);
          phases = phases.goPhases goArgsWithDefaults;
          passthru = appendEvidenceSources (args.passthru or {}) (
            [args.src]
            ++ lib.optional ((args.goModules or null) != null) args.goModules
          );
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
    sharedBazelBuild =
      sharedBazelCacheDir
      != null
      && (args.sharedBuildCache or true)
      && !isToolchainName (args.pname or args.name or "");
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
        name = "${args.pname or "bazel"}-deps-${(packageVersions.normalize (args.version or "0")).version}";
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
        captureModuleLock = args.captureModuleLock or false;
      });

    # Remove bazel-specific attrs before passing to mkDerivation
    restArgs = removeAttrs args bazelSpecificAttrs;
  in
    addBuilderOverrides mkBazelPackage args (
      mkDerivation (
        restArgs
        // lib.optionalAttrs sharedBazelBuild {
          AOS_BAZEL_DISK_CACHE = sharedBazelCacheDir;
        }
        // {
          buildDeps =
            [
              bazel
              jdk
              resolvedBuildPackages.patchelf
            ]
            ++ tools
            ++ (args.buildDeps or []);
          passthru = appendEvidenceSources (args.passthru or {}) [
            args.src
            deps
          ];
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
    // {inherit firmwarePackages aosWorkspaceIntegrationSource aosWorkspaceSliceFor aosWorkspaceVendor;}
    // lib.optionalAttrs stdenv.isCross (
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
        inherit mkDerivation fetchurl fetchgit mkUpstream mkGithubUpstream mkManualUpstream callPackage;
        inherit withQualification;
      }
    );
  in
    fn (auto // overrides);
  trivialBuilders = callPackage ./build-support/_trivial-builders.nix {};

  # Shared Linux kernel source (single tarball for linux and linux-headers)
  linuxSource = import ./kernel/_source.nix {inherit fetchurl mkManualUpstream;};

  # Shared Kubernetes source (single tarball for kubelet, kubectl)
  kubeSource = import ./kubernetes/_source.nix {inherit fetchurl;};

  # Shared KubeEdge source (single tarball for cloudcore, edgecore)
  kubeedgeSource = import ./kubernetes/_kubeedge-source.nix {inherit fetchurl;};

  # Runtime Rust packages share the workspace-only source and vendor closure.
  # Repository-aware integration tests add Nix inputs without changing runtime
  # package identities when unrelated modules or package recipes change.
  aosWorkspaceIntegrationSource = import ./tools/aos/_workspace-source.nix {
    inherit lib;
    includeIntegrationInputs = true;
  };
  aosWorkspaceSliceFor = args:
    import ./tools/aos/_workspace-slice.nix {
      inherit lib;
      cargoFlags = args.cargoFlags or "";
      cargoTestFlags =
        if args.doCheck or true
        then args.cargoTestFlags or ""
        else "";
      cargoBuildCommands = args.cargoBuildCommands or [];
      includeIntegrationInputs = args.aosWorkspaceIntegrationInputs or false;
    };
  # Vendoring reads the lockfile alone. Keep source and test edits from
  # changing the vendor derivation for every Cargo package.
  aosWorkspaceVendorSource = builtins.path {
    path = ../crates;
    name = "aos-workspace-lockfile";
    filter = path: _: let
      cratesRoot = toString ../crates;
    in
      path == cratesRoot || path == "${cratesRoot}/Cargo.lock";
  };
  aosWorkspaceVendor = fetchCargoVendor {
    src = aosWorkspaceVendorSource;
    name = "aos-workspace-vendor";
    sourceRoot = "source";
    hash = "sha256-6o3yyHfoAulAknlgr6juP7QLfgkplcfmp2xZysTjTwI=";
  };

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
        # The catalog name comes from the recipe path. Versioned variants may
        # share a derivation pname but still need distinct contract identities.
        value = let
          path = dir + "/${name}";
          acceptsMkDerivation = (builtins.functionArgs (import path)) ? mkDerivation;
          # Recipes can build internal derivations. Stamp only the returned
          # package so those dependencies keep their own contract identities.
          package = callPackage path {};
        in
          if !acceptsMkDerivation
          then package
          else if package ? overrideAttrs
          then package.overrideAttrs {catalogName = lib.removeSuffix ".nix" name;}
          else throw "discovered package '${name}' cannot receive its catalog identity";
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
  linuxHostedBinutils = import ./toolchain/_linux-hosted-binutils.nix {
    inherit mkDerivation fetchurl stdenv buildPackages;
    bash = self.bash;
    zlib = self.zlib;
  };
  linuxHostedGlibc = import ./toolchain/_linux-hosted-glibc.nix {
    inherit mkDerivation stdenv buildPackages;
    inherit (self) bash perl;
  };
  linuxHostedGcc = import ./toolchain/_linux-hosted-gcc.nix {
    inherit mkDerivation stdenv buildPackages;
    bash = self.bash;
    binutils = linuxHostedBinutils;
  };
  linuxHostedCc = import ./toolchain/_linux-hosted-cc.nix {
    inherit lib stdenv buildPackages;
    bash = self.bash;
    gcc = linuxHostedGcc;
    binutils = linuxHostedBinutils;
  };
  linuxTargetGccLibs = mkDerivation {
    pname = "gcc-libs";
    inherit (stdenv.gccRuntime) version;
    src = null;
    runtimeDeps = [stdenv.gccRuntime];
    propagatedDeps = [];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          ln -s ${stdenv.gccRuntime}/lib "$out/lib"
        '';
      }
    ];
    passthru = {
      evidenceSources = stdenv.gccRuntime.passthru.evidenceSources;
      # The public package forwards these separately realized runtime libraries.
      evidenceRuntimePackages = [
        (stdenv.gccRuntime
          // {
            pname = "gcc-runtime";
            meta.license = "GPL-3.0-or-later WITH GCC-exception-3.1";
          })
      ];
    };
    meta = {
      description = "GCC runtime shared libraries (libstdc++.so, libgcc_s.so)";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-3.0-or-later WITH GCC-exception-3.1";
    };
  };
  darwinRuntimePlatformSupport = lib.packagePlatform.normalize "package 'darwin-runtimes' platformSupport" {
    build = [
      {
        abi = ["gnu"];
        os = ["linux"];
      }
    ];
    host = [
      {
        abi = ["darwin"];
        cpu = ["x86_64" "aarch64"];
        os = ["darwin"];
      }
    ];
    target = [];
    role = "public-package";
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
  uncheckedPackageNames = builtins.attrNames (
    discoveredPackages
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
    "ability-package-smoke"
    "aos-ability-boundary-observer"
    "ability-package-smoke-provider"
    "aos-ability-crucible"
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
    "aos-credential-delivery-test"
    "aos-release-signer"
    "aos-secret-reference-test"
    "aos-selinux-run"
    "aos-service-root"
    "aos-system-image-e2e-fixture"
    "aos-test-agent"
    "aos-test-driver"
    "aos-systemd-var-policy"
    "aos-verity-root-guard"
    "aos-vm"
    "crucible"
    "crucible-controller"
    "crucible-fixtures"
    "crucible-fleet-store"
    "crucible-guest"
    "crucible-qemu-plugin"
    "crucible-qemu-trace-plugin"
    "desired-config-test"
    "desired-prune-test"
    "test-http-server"
    "test-static-cache-server"
    "upgrade-transition-fixture"
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
          platformSupport.platforms);
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

  # All Linux QEMU variants enable compressed disk-image support when bzip2
  # is found. Retain that target library through runtime-reference scrubbing.
  mkQemuPackage = args: let
    package = callPackage ./emulation/qemu.nix args;
  in
    if stdenv.isCross && stdenv.hostPlatform.isLinux
    then package.overrideAttrs (previous: {runtimeDeps = previous.runtimeDeps ++ [self.bzip2];})
    else package;

  self =
    {
      # --- Plumbing ---
      inherit mkDerivation fetchurl mkUpstream mkGithubUpstream mkManualUpstream lib packageNames allPackageNames;
      inherit maintenanceInventory;
      inherit platformSupport targetPackageNamesFor targetPackagesFor;
      inherit mkAccacheEnvironment;
      inherit mkCargoPackage mkAosCargoPackage mkCargoArtifacts mkCargoNextestCheck mkGoPackage mkBazelPackage;
      inherit mkOciTools ociTools mkOciMultiPlatformContainer mkOciPackageEvidence;
      # Downstream flakes use the same package argument resolution as discovery.
      inherit callPackage;
      inherit (lib) mkShell;
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
      nuke-references =
        withQualification {
          packageName = "nuke-references";
          platformSupport = {
            build = [
              {
                abi = ["gnu"];
                os = ["linux"];
              }
            ];
            host = [
              {
                abi = ["gnu"];
                cpu = ["x86_64" "aarch64"];
                os = ["linux"];
              }
            ];
            target = [];
            role = "build-input";
          };
          version = "0";
          packageProbe = lib.qualification.commandProbe {
            "primary" = {
              "artifacts" = [
                {
                  "path" = "reference.txt";
                  "text" = "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-package/data\n";
                }
              ];
              "expected" = "The hash is replaced by 32 e characters while surrounding bytes remain unchanged.";
              "files" = {
                "reference.txt" = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package/data\n";
              };
              "input" = "Text containing one syntactically valid Nix store reference.";
              "operation" = "Rewrite the store hash through nuke-refs.";
              "steps" = [
                {
                  "argv" = [
                    "@out@/bin/nuke-refs"
                    "reference.txt"
                  ];
                  "exit_code" = 0;
                  "stderr" = {
                    "exact" = "";
                  };
                  "stdout" = {
                    "exact" = "";
                  };
                }
              ];
            };
            "badInput" = {
              "artifacts" = [];
              "expected" = "nuke-refs rejects the exclusion with status 1.";
              "files" = {
                "reference.txt" = "unchanged\n";
              };
              "input" = "An exclusion value that is not a complete Nix store path.";
              "operation" = "Parse the malformed exclusion through nuke-refs.";
              "steps" = [
                {
                  "argv" = [
                    "@out@/bin/nuke-refs"
                    "-e"
                    "not-a-store-path"
                    "reference.txt"
                  ];
                  "exit_code" = 1;
                  "observes_rejection" = true;
                  "stderr" = {
                    "exact" = "nuke-refs: -e needs a store path\n";
                  };
                  "stdout" = {
                    "exact" = "";
                  };
                }
              ];
            };
          };
        } (import ../lib/build-support/nuke-references {
          mkDerivation = args:
            withDefaultMaintainers (rawMkDerivation args);
          inherit (self) bash coreutils grep sed;
        });
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
      kernel-interface = callPackage ./kernel/kernel-interface.nix {};
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

      qemu = let
        package = mkQemuPackage {};
      in
        if stdenv.isCross && stdenv.hostPlatform.isLinux
        then
          package.overrideAttrs (previous: {
            # Linux-user emulation needs UAPI families such as sound/, beyond
            # the linux/ and asm/ headers exported by the target glibc output.
            # An explicit include preserves the target header identity instead
            # of treating these non-executable inputs as native build tools.
            phases = map (phase:
              if phase.name == "configure"
              then
                phase
                // {
                  script =
                    ''
                      export C_INCLUDE_PATH="${stdenv.linuxHeaders}/include''${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"
                    ''
                    + phase.script;
                }
              else phase)
            previous.phases;
          })
        else package;

      qemu-crucible = mkQemuPackage {
        pname = "qemu-crucible";
        qualification.packageProbe = lib.qualification.commandProbe {
          "primary" = {
            "artifacts" = [];
            "expected" = "qemu-img reports the two images as identical.";
            "files" = {
              "left.raw" = "AOS raw image payload\n";
              "right.raw" = "AOS raw image payload\n";
            };
            "input" = "Two raw disk-image byte streams with identical contents.";
            "operation" = "Compare the images byte for byte through qemu-img's raw-image reader.";
            "steps" = [
              {
                "argv" = [
                  "@out@/bin/qemu-img"
                  "compare"
                  "-f"
                  "raw"
                  "-F"
                  "raw"
                  "left.raw"
                  "right.raw"
                ];
                "exit_code" = 0;
                "stderr" = {
                  "exact" = "";
                };
                "stdout" = {
                  "exact" = "Images are identical.\n";
                };
              }
            ];
          };
          "badInput" = {
            "artifacts" = [];
            "expected" = "qemu-img identifies the content mismatch and returns its comparison status.";
            "files" = {
              "left.raw" = "answer=41\n";
              "right.raw" = "answer=42\n";
            };
            "input" = "Two raw disk-image byte streams that differ in one value.";
            "operation" = "Compare the mismatched images through qemu-img.";
            "steps" = [
              {
                "argv" = [
                  "@out@/bin/qemu-img"
                  "compare"
                  "-f"
                  "raw"
                  "-F"
                  "raw"
                  "left.raw"
                  "right.raw"
                ];
                "exit_code" = 1;
                "observes_rejection" = true;
              }
            ];
          };
        };

        enablePlugins = true;
        applyCruciblePatches = true;
      };
      qemu-crucible-reference = mkQemuPackage {
        pname = "qemu-crucible-reference";
        qualification.packageProbe = lib.qualification.commandProbe {
          "primary" = {
            "artifacts" = [];
            "expected" = "qemu-img reports the two images as identical.";
            "files" = {
              "left.raw" = "AOS raw image payload\n";
              "right.raw" = "AOS raw image payload\n";
            };
            "input" = "Two raw disk-image byte streams with identical contents.";
            "operation" = "Compare the images byte for byte through qemu-img's raw-image reader.";
            "steps" = [
              {
                "argv" = [
                  "@out@/bin/qemu-img"
                  "compare"
                  "-f"
                  "raw"
                  "-F"
                  "raw"
                  "left.raw"
                  "right.raw"
                ];
                "exit_code" = 0;
                "stderr" = {
                  "exact" = "";
                };
                "stdout" = {
                  "exact" = "Images are identical.\n";
                };
              }
            ];
          };
          "badInput" = {
            "artifacts" = [];
            "expected" = "qemu-img identifies the content mismatch and returns its comparison status.";
            "files" = {
              "left.raw" = "answer=41\n";
              "right.raw" = "answer=42\n";
            };
            "input" = "Two raw disk-image byte streams that differ in one value.";
            "operation" = "Compare the mismatched images through qemu-img.";
            "steps" = [
              {
                "argv" = [
                  "@out@/bin/qemu-img"
                  "compare"
                  "-f"
                  "raw"
                  "-F"
                  "raw"
                  "left.raw"
                  "right.raw"
                ];
                "exit_code" = 1;
                "observes_rejection" = true;
              }
            ];
          };
        };

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
        mkQemuPackage {
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
        then
          withQualification {
            packageName = "darwin-runtimes";
            platformSupport = darwinRuntimePlatformSupport;
            version = stdenv.darwinRuntimes.version or "0";
            packageProbe = lib.qualification.commandProbe {
              "primary" = {
                "artifacts" = [];
                "expected" = "All three public runtime libraries resolve to Mach-O binaries.";
                "files" = {};
                "input" = "The installed Darwin libc++, libc++abi, and libunwind libraries.";
                "operation" = "Resolve their dylinks and inspect the Mach-O library magic.";
                "steps" = [
                  {
                    "argv" = [
                      "@python@"
                      "-c"
                      "import pathlib\nroot = pathlib.Path(\"@out@\")\nmacho_magic = {bytes.fromhex(\"cffaedfe\"), bytes.fromhex(\"feedfacf\")}\nlibraries = [next(root.rglob(name)).resolve() for name in [\"libc++.dylib\", \"libc++abi.dylib\", \"libunwind.dylib\"]]\nassert all(library.read_bytes()[:4] in macho_magic for library in libraries)\nprint(\"darwin-runtimes data passed\")\n"
                    ];
                    "exit_code" = 0;
                    "stderr" = {
                      "exact" = "";
                    };
                    "stdout" = {
                      "exact" = "darwin-runtimes data passed\n";
                    };
                  }
                ];
              };
              "badInput" = {
                "artifacts" = [];
                "expected" = "The runtime set rejects the disabled sanitizer artifact.";
                "files" = {};
                "input" = "A request for the disabled AddressSanitizer Darwin runtime.";
                "operation" = "Resolve an undeclared sanitizer dynamic library.";
                "steps" = [
                  {
                    "argv" = [
                      "@python@"
                      "-c"
                      "import pathlib, sys\nif pathlib.Path(\"@out@/lib/libclang_rt.asan_osx_dynamic.dylib\").exists():\n    raise SystemExit(2)\nsys.stderr.write(\"darwin-runtimes rejected invalid input\\n\")\nraise SystemExit(7)\n"
                    ];
                    "exit_code" = 7;
                    "observes_rejection" = true;
                    "stderr" = {
                      "exact" = "darwin-runtimes rejected invalid input\n";
                    };
                    "stdout" = {
                      "exact" = "";
                    };
                  }
                ];
              };
            };
          }
          (withDistributionMeta {
              description = "LLVM runtime libraries for Darwin";
              homepage = "https://llvm.org/";
              license = "Apache-2.0 WITH LLVM-exception";
            }
            stdenv.darwinRuntimes)
        else {
          pname = "darwin-runtimes";
          platformSupport = darwinRuntimePlatformSupport;
          unavailable = true;
        };
      darwinRuntimes = self.darwin-runtimes;
      java-native-foundation =
        if stdenv.hostPlatform.isDarwin
        then discoveredPackages.java-native-foundation
        else callPackage ./toolchain/java/java-native-foundation.nix {declarationOnly = true;};

      # --- stdenv packages (linked, not rebuilt) ---
      gcc =
        withQualification {
          packageName = "gcc";
          platformSupport = {
            build = [
              {
                abi = ["gnu"];
                os = ["linux"];
              }
            ];
            host = [
              {
                abi = ["gnu"];
                cpu = ["x86_64" "aarch64"];
                os = ["linux"];
              }
              {
                abi = ["darwin"];
                cpu = ["x86_64" "aarch64"];
                os = ["darwin"];
              }
            ];
            target = [
              {
                abi = ["gnu"];
                cpu = ["x86_64" "aarch64"];
                os = ["linux"];
              }
              {
                abi = ["darwin"];
                cpu = ["x86_64" "aarch64"];
                os = ["darwin"];
              }
            ];
            role = "public-package";
          };
          version = "16.2.0";
          packageProbe = lib.qualification.commandProbe {
            "primary" = {
              "artifacts" = [];
              "expected" = "The compiler succeeds and the binary prints the fixed result.";
              "files" = {
                "valid.c" = "#include <stdio.h>\n\nint main(void) {\n    int values[] = {19, 23};\n    return printf(\"compiler result: %d\\n\", values[0] + values[1]) < 0;\n}\n";
              };
              "input" = "A C program that computes and prints an integer result.";
              "operation" = "Compile the program with gcc, then execute the generated binary.";
              "steps" = [
                {
                  "argv" = [
                    "@out@/bin/gcc"
                    "valid.c"
                    "-o"
                    "compiled-program"
                  ];
                  "exit_code" = 0;
                  "stderr" = {
                    "exact" = "";
                  };
                  "stdout" = {
                    "exact" = "";
                  };
                }
                {
                  "argv" = [
                    "@work@/primary/compiled-program"
                  ];
                  "exit_code" = 0;
                  "stderr" = {
                    "exact" = "";
                  };
                  "stdout" = {
                    "exact" = "compiler result: 42\n";
                  };
                }
              ];
            };
            "badInput" = {
              "artifacts" = [];
              "expected" = "The compiler rejects the syntax error with status 1.";
              "files" = {
                "invalid.c" = "int main(void) { int answer = ; return answer; }\n";
              };
              "input" = "A C translation unit with an incomplete initializer.";
              "operation" = "Ask gcc to compile the malformed source.";
              "steps" = [
                {
                  "argv" = [
                    "@out@/bin/gcc"
                    "invalid.c"
                    "-o"
                    "invalid-program"
                  ];
                  "exit_code" = 1;
                  "observes_rejection" = true;
                  "stdout" = {
                    "exact" = "";
                  };
                }
              ];
            };
          };
        } (
          (withDistributionMeta {
              description = "GNU Compiler Collection with AOS target and runtime defaults";
              homepage = "https://gcc.gnu.org/";
              license = "GPL-3.0-or-later WITH GCC-exception-3.1";
            }
            (
              if stdenv.hostPlatform.isDarwin
              then darwinGcc
              else if stdenv.isCross && stdenv.hostPlatform.isLinux
              # Preserve the public package identity so build dependencies
              # resolve to native GCC rather than the target-hosted wrapper.
              then linuxHostedCc // {pname = "gcc";}
              else stdenv.gcc
            ))
          // {version = "16.2.0";}
        );
      glibc =
        withQualification {
          packageName = "glibc";
          platformSupport = {
            build = [
              {
                abi = ["gnu"];
                os = ["linux"];
              }
            ];
            host = [
              {
                abi = ["gnu"];
                cpu = ["x86_64" "aarch64"];
                os = ["linux"];
              }
            ];
            target = [];
            role = "public-package";
          };
          # Public module compatibility stays at this release pending review.
          version = "=2.39.0";
          packageProbe = lib.qualification.commandProbe {
            "primary" = {
              "artifacts" = [];
              "expected" = "The AOS libc sorts the vector into the exact ascending sequence.";
              "files" = {
                "primary.c" = "#include <stdio.h>\n#include <stdlib.h>\n\nstatic int compare(const void *left, const void *right) {\n    int a = *(const int *)left;\n    int b = *(const int *)right;\n    return (a > b) - (a < b);\n}\n\nint main(void) {\n    int values[] = {23, 5, 42, 17};\n    qsort(values, 4, sizeof(values[0]), compare);\n    return printf(\"%d,%d,%d,%d\\n\", values[0], values[1], values[2], values[3]) < 0;\n}\n";
              };
              "input" = "A C program sorting a fixed integer vector with libc qsort.";
              "operation" = "Compile it and execute it through the packaged dynamic loader and libc.";
              "steps" = [
                {
                  "argv" = [
                    "@cc@"
                    "primary.c"
                    "-o"
                    "primary"
                  ];
                  "exit_code" = 0;
                  "stderr" = {
                    "exact" = "";
                  };
                  "stdout" = {
                    "exact" = "";
                  };
                }
                {
                  "argv" = [
                    "@python@"
                    "-c"
                    "import pathlib, subprocess\nloader = next(pathlib.Path(\"@out@/lib\").glob(\"ld-linux*.so*\"))\nresult = subprocess.run([str(loader), \"--library-path\", \"@out@/lib\", \"@work@/primary/primary\"], capture_output=True, text=True)\nassert result.returncode == 0 and result.stderr == \"\"\nprint(result.stdout, end=\"\")\n"
                  ];
                  "exit_code" = 0;
                  "stderr" = {
                    "exact" = "";
                  };
                  "stdout" = {
                    "exact" = "5,17,23,42\n";
                  };
                }
              ];
            };
            "badInput" = {
              "artifacts" = [];
              "expected" = "Glibc rejects the unknown conversion and sets EINVAL.";
              "files" = {
                "bad-input.c" = "#include <errno.h>\n#include <iconv.h>\n#include <stdio.h>\n\nint main(void) {\n    errno = 0;\n    iconv_t conversion = iconv_open(\"AOS-NOT-A-CHARSET\", \"UTF-8\");\n    if (conversion != (iconv_t)-1 || errno != EINVAL) {\n        if (conversion != (iconv_t)-1) {\n            iconv_close(conversion);\n        }\n        return 2;\n    }\n    fputs(\"glibc rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
              };
              "input" = "A request for a character-set conversion name that does not exist.";
              "operation" = "Call iconv_open through a program loaded by the packaged libc.";
              "steps" = [
                {
                  "argv" = [
                    "@cc@"
                    "bad-input.c"
                    "-o"
                    "bad-input"
                  ];
                  "exit_code" = 0;
                  "stderr" = {
                    "exact" = "";
                  };
                  "stdout" = {
                    "exact" = "";
                  };
                }
                {
                  "argv" = [
                    "@python@"
                    "-c"
                    "import pathlib, subprocess, sys\nloader = next(pathlib.Path(\"@out@/lib\").glob(\"ld-linux*.so*\"))\nresult = subprocess.run([str(loader), \"--library-path\", \"@out@/lib\", \"@work@/bad-input/bad-input\"], capture_output=True)\nif result.returncode != 7 or result.stderr != b\"glibc rejected invalid input\\n\":\n    raise SystemExit(2)\nsys.stderr.write(\"glibc rejected invalid input\\n\")\nraise SystemExit(7)\n"
                  ];
                  "exit_code" = 7;
                  "observes_rejection" = true;
                  "stderr" = {
                    "exact" = "glibc rejected invalid input\n";
                  };
                  "stdout" = {
                    "exact" = "";
                  };
                }
              ];
            };
          };
        } (
          (withDistributionMeta {
              description = "GNU C Library for the AOS target runtime";
              homepage = "https://www.gnu.org/software/libc/";
              license = "LGPL-2.1-or-later";
            }
            (
              (
                if stdenv.isCross && stdenv.hostPlatform.isLinux
                then linuxHostedGlibc
                else stdenv.glibc
              )
              // lib.optionalAttrs stdenv.hostPlatform.isDarwin {
                dev = stdenv.glibc;
                static = stdenv.glibc;
              }
            ))
          // {version = "2.39.0";}
        );
      binutils =
        withQualification {
          packageName = "binutils";
          platformSupport = {
            build = [
              {
                abi = ["gnu"];
                os = ["linux"];
              }
            ];
            host = [
              {
                abi = ["gnu"];
                cpu = ["x86_64" "aarch64"];
                os = ["linux"];
              }
              {
                abi = ["darwin"];
                cpu = ["x86_64" "aarch64"];
                os = ["darwin"];
              }
            ];
            target = [
              {
                abi = ["gnu"];
                cpu = ["x86_64" "aarch64"];
                os = ["linux"];
              }
              {
                abi = ["darwin"];
                cpu = ["x86_64" "aarch64"];
                os = ["darwin"];
              }
            ];
            role = "public-package";
          };
          # No broader interface guarantee is assumed for the tool suite.
          version = "=2.41.0";
          packageProbe = lib.qualification.commandProbe {
            "primary" = {
              "artifacts" = [];
              "expected" = "Strings emits exactly the two qualifying runs.";
              "files" = {
                "sample.bin" = "alpha\nxy\nbravo\n";
              };
              "input" = "Data containing printable runs above and below a five-byte threshold.";
              "operation" = "Extract printable runs of at least five bytes with GNU strings.";
              "steps" = [
                {
                  "argv" = [
                    "@out@/bin/strings"
                    "--bytes=5"
                    "@work@/primary/sample.bin"
                  ];
                  "exit_code" = 0;
                  "stderr" = {
                    "exact" = "";
                  };
                  "stdout" = {
                    "exact" = "alpha\nbravo\n";
                  };
                }
              ];
            };
            "badInput" = {
              "artifacts" = [];
              "expected" = "Strings rejects the bound with status 1.";
              "files" = {
                "sample.bin" = "alpha\n";
              };
              "input" = "A minimum string length of zero, outside the accepted positive range.";
              "operation" = "Invoke strings with the invalid length bound.";
              "steps" = [
                {
                  "argv" = [
                    "@out@/bin/strings"
                    "--bytes=0"
                    "@work@/bad-input/sample.bin"
                  ];
                  "exit_code" = 1;
                  "observes_rejection" = true;
                  "stdout" = {
                    "exact" = "";
                  };
                }
              ];
            };
          };
        } (
          (withDistributionMeta {
              description = "GNU binary utilities for the AOS target toolchain";
              license = "GPL-3.0-or-later";
            }
            (
              if stdenv.hostPlatform.isDarwin
              then darwinBinutils
              else if stdenv.isCross && stdenv.hostPlatform.isLinux
              then linuxHostedBinutils
              else stdenv.binutils
            ))
          // {version = "2.41.0";}
        );
      inherit darwinDtraceCompiler;
      inherit appleLibTapi;
      inherit darwinCctoolsLinker;
      cc =
        withQualification {
          packageName = "cc";
          platformSupport = {
            build = [
              {
                abi = ["gnu"];
                os = ["linux"];
              }
            ];
            host = [
              {
                abi = ["gnu"];
                cpu = ["x86_64" "aarch64"];
                os = ["linux"];
              }
              {
                abi = ["darwin"];
                cpu = ["x86_64" "aarch64"];
                os = ["darwin"];
              }
            ];
            target = [
              {
                abi = ["gnu"];
                cpu = ["x86_64" "aarch64"];
                os = ["linux"];
              }
              {
                abi = ["darwin"];
                cpu = ["x86_64" "aarch64"];
                os = ["darwin"];
              }
            ];
            role = "public-package";
          };
          version = "0.1.0";
          packageProbe = lib.qualification.commandProbe {
            "primary" = {
              "artifacts" = [];
              "expected" = "The compiler succeeds and the binary prints the fixed result.";
              "files" = {
                "valid.c" = "#include <stdio.h>\n\nint main(void) {\n    int values[] = {19, 23};\n    return printf(\"compiler result: %d\\n\", values[0] + values[1]) < 0;\n}\n";
              };
              "input" = "A C program that computes and prints an integer result.";
              "operation" = "Compile the program with cc, then execute the generated binary.";
              "steps" = [
                {
                  "argv" = [
                    "@out@/bin/cc"
                    "valid.c"
                    "-o"
                    "compiled-program"
                  ];
                  "exit_code" = 0;
                  "stderr" = {
                    "exact" = "";
                  };
                  "stdout" = {
                    "exact" = "";
                  };
                }
                {
                  "argv" = [
                    "@work@/primary/compiled-program"
                  ];
                  "exit_code" = 0;
                  "stderr" = {
                    "exact" = "";
                  };
                  "stdout" = {
                    "exact" = "compiler result: 42\n";
                  };
                }
              ];
            };
            "badInput" = {
              "artifacts" = [];
              "expected" = "The compiler rejects the syntax error with status 1.";
              "files" = {
                "invalid.c" = "int main(void) { int answer = ; return answer; }\n";
              };
              "input" = "A C translation unit with an incomplete initializer.";
              "operation" = "Ask cc to compile the malformed source.";
              "steps" = [
                {
                  "argv" = [
                    "@out@/bin/cc"
                    "invalid.c"
                    "-o"
                    "invalid-program"
                  ];
                  "exit_code" = 1;
                  "observes_rejection" = true;
                  "stdout" = {
                    "exact" = "";
                  };
                }
              ];
            };
          };
        } (
          (withDistributionMeta {
              description = "AOS C and C++ compiler wrapper toolchain";
              homepage = null;
              license = "GPL-3.0-or-later WITH GCC-exception-3.1";
            }
            (
              if stdenv.hostPlatform.isDarwin
              then darwinCc
              else if stdenv.isCross && stdenv.hostPlatform.isLinux
              then linuxHostedCc
              else stdenv.cc
            ))
          // {version = "0.1.0";}
        );
      # The unwrapped gcc-16.2.0-stage2. `pkgs.gcc` is the wrapped
      # gcc-16.2.0-wrapped; the perl Config scrub needs to substitute
      # and block the unwrapped one, since that's what Configure
      # records via specs/PATH.
      gccUnwrapped =
        withQualification {
          packageName = "gccUnwrapped";
          platformSupport = {
            build = [
              {
                abi = ["gnu"];
                os = ["linux"];
              }
            ];
            host = [
              {
                abi = ["gnu"];
                cpu = ["x86_64" "aarch64"];
                os = ["linux"];
              }
              {
                abi = ["darwin"];
                cpu = ["x86_64" "aarch64"];
                os = ["darwin"];
              }
            ];
            target = [
              {
                abi = ["gnu"];
                cpu = ["x86_64" "aarch64"];
                os = ["linux"];
              }
              {
                abi = ["darwin"];
                cpu = ["x86_64" "aarch64"];
                os = ["darwin"];
              }
            ];
            role = "public-package";
          };
          version =
            if stdenv.hostPlatform.isDarwin
            then darwinGcc.version
            else "16.2.0";
          packageProbe = lib.qualification.commandProbe {
            "primary" = {
              "artifacts" = [];
              "expected" = "The compiler succeeds and the binary prints the fixed result.";
              "files" = {
                "valid.c" = "#include <stdio.h>\n\nint main(void) {\n    int values[] = {19, 23};\n    return printf(\"compiler result: %d\\n\", values[0] + values[1]) < 0;\n}\n";
              };
              "input" = "A C program that computes and prints an integer result.";
              "operation" = "Compile the program with gcc, then execute the generated binary.";
              "steps" = [
                {
                  "argv" = [
                    "@out@/bin/gcc"
                    "valid.c"
                    "-o"
                    "compiled-program"
                  ];
                  "exit_code" = 0;
                  "stderr" = {
                    "exact" = "";
                  };
                  "stdout" = {
                    "exact" = "";
                  };
                }
                {
                  "argv" = [
                    "@work@/primary/compiled-program"
                  ];
                  "exit_code" = 0;
                  "stderr" = {
                    "exact" = "";
                  };
                  "stdout" = {
                    "exact" = "compiler result: 42\n";
                  };
                }
              ];
            };
            "badInput" = {
              "artifacts" = [];
              "expected" = "The compiler rejects the syntax error with status 1.";
              "files" = {
                "invalid.c" = "int main(void) { int answer = ; return answer; }\n";
              };
              "input" = "A C translation unit with an incomplete initializer.";
              "operation" = "Ask gcc to compile the malformed source.";
              "steps" = [
                {
                  "argv" = [
                    "@out@/bin/gcc"
                    "invalid.c"
                    "-o"
                    "invalid-program"
                  ];
                  "exit_code" = 1;
                  "observes_rejection" = true;
                  "stdout" = {
                    "exact" = "";
                  };
                }
              ];
            };
          };
        } (
          (withDistributionMeta {
              description = "Unwrapped GNU Compiler Collection for the AOS target toolchain";
              homepage = "https://gcc.gnu.org/";
              license = "GPL-3.0-or-later WITH GCC-exception-3.1";
            }
            (
              if stdenv.hostPlatform.isDarwin
              then darwinGcc
              else if stdenv.isCross && stdenv.hostPlatform.isLinux
              then linuxHostedGcc
              else if stdenv ? gccStage2
              then stdenv.gccStage2
              else stdenv.gcc
            ))
          // {
            version =
              if stdenv.hostPlatform.isDarwin
              then darwinGcc.version
              else "16.2.0";
          }
        );
      gcc-libs = withPlatformSupport discoveredPackages.gcc-libs (withDistributionMeta {
          description = "GCC runtime libraries";
          homepage = "https://gcc.gnu.org/";
          license = "GPL-3.0-or-later WITH GCC-exception-3.1";
        } (
          if stdenv.hostPlatform.isDarwin
          then darwinGcc
          else if stdenv.isCross && stdenv.hostPlatform.isLinux
          then linuxTargetGccLibs
          else discoveredPackages.gcc-libs
        ));
      getent =
        withQualification {
          packageName = "getent";
          platformSupport = {
            build = [
              {
                abi = ["gnu"];
                os = ["linux"];
              }
            ];
            host = [
              {
                abi = ["gnu"];
                cpu = ["x86_64" "aarch64"];
                os = ["linux"];
              }
            ];
            target = [];
            role = "public-package";
          };
          # The selected libc output inherits its owning package policy.
          version = self.glibc.versionRequirement;
          packageProbe = lib.qualification.commandProbe {
            "primary" = {
              "artifacts" = [];
              "expected" = "Getent returns the protocol number 6 record for TCP.";
              "files" = {};
              "input" = "The TCP protocol key in the files-backed protocols database.";
              "operation" = "Resolve the key through getent with the files service selected explicitly.";
              "steps" = [
                {
                  "argv" = [
                    "@python@"
                    "-c"
                    "import subprocess\nresult = subprocess.run([\"@out@/bin/getent\", \"--service=files\", \"protocols\", \"tcp\"], capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nfields = result.stdout.split()\nassert fields[0] == \"tcp\" and fields[1] == \"6\"\nprint(\"getent operation passed\")\n"
                  ];
                  "exit_code" = 0;
                  "stderr" = {
                    "exact" = "";
                  };
                  "stdout" = {
                    "exact" = "getent operation passed\n";
                  };
                }
              ];
            };
            "badInput" = {
              "artifacts" = [];
              "expected" = "Getent rejects the unknown database name.";
              "files" = {};
              "input" = "A database name that getent does not support.";
              "operation" = "Resolve a key through the unknown database.";
              "steps" = [
                {
                  "argv" = [
                    "@python@"
                    "-c"
                    "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/getent\", \"aos-unknown-database\", \"key\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"getent rejected invalid input\\n\")\nraise SystemExit(7)\n"
                  ];
                  "exit_code" = 7;
                  "observes_rejection" = true;
                  "stderr" = {
                    "exact" = "getent rejected invalid input\n";
                  };
                  "stdout" = {
                    "exact" = "";
                  };
                }
              ];
            };
          };
        } (
          (withDistributionMeta {
              description = "Name service database lookup utility from GNU C Library";
              homepage = "https://www.gnu.org/software/libc/";
              license = "LGPL-2.1-or-later";
            }
            (lib.getOutput "getent" stdenv.glibc))
          // {
            version = "2.39.0";
            passthru.evidenceSources = stdenv.glibc.passthru.evidenceSources;
          }
        );
      # Native package sets retain the final stdenv tools. Cross package roots
      # must be actual target builds; scheduler-native tools remain available
      # only through buildPackages and build-dependency splicing.
      bash = withPlatformSupport discoveredPackages.bash (withDefaultMaintainers (
        if stdenv.isCross
        then discoveredPackages.bash
        else withBootstrapPublication "bash"
      ));
      coreutils = withPlatformSupport discoveredPackages.coreutils (withDefaultMaintainers (
        if stdenv.isCross
        then discoveredPackages.coreutils
        else withBootstrapPublication "coreutils"
      ));
      gnumake = withPlatformSupport discoveredPackages.gnumake (withDefaultMaintainers (
        if stdenv.isCross
        then discoveredPackages.gnumake
        else withBootstrapPublication "gnumake"
      ));
      sed = withPlatformSupport discoveredPackages.sed (withDefaultMaintainers (
        if stdenv.isCross
        then discoveredPackages.sed
        else withBootstrapPublication "sed"
      ));
      grep = withPlatformSupport discoveredPackages.grep (withDefaultMaintainers (
        if stdenv.isCross
        then discoveredPackages.grep
        else withBootstrapPublication "grep"
      ));
      findutils = withPlatformSupport discoveredPackages.findutils (withDefaultMaintainers (
        if stdenv.isCross
        then discoveredPackages.findutils
        else withBootstrapPublication "findutils"
      ));
      gawk = withPlatformSupport discoveredPackages.gawk (withDefaultMaintainers (
        if stdenv.isCross
        then discoveredPackages.gawk
        else withBootstrapPublication "gawk"
      ));
      diffutils = withPlatformSupport discoveredPackages.diffutils (withDefaultMaintainers (
        if stdenv.isCross
        then discoveredPackages.diffutils
        else withBootstrapPublication "diffutils"
      ));
      tar = withPlatformSupport discoveredPackages.tar (withDefaultMaintainers (
        if stdenv.isCross
        then discoveredPackages.tar
        else withBootstrapPublication "tar"
      ));
      gzip = withPlatformSupport discoveredPackages.gzip (withDefaultMaintainers (
        if stdenv.isCross
        then discoveredPackages.gzip
        else withBootstrapPublication "gzip"
      ));
      patch = withPlatformSupport discoveredPackages.patch (withDefaultMaintainers (
        if stdenv.isCross
        then discoveredPackages.patch
        else withBootstrapPublication "patch"
      ));
    }
    # --- Trivial builders, exposed flat on the package set ---
    # The private builder module supplies four primitives at the top level,
    # so consumers can call `pkgs.writeTextFile` / `pkgs.runCommand`, matching the
    # nixpkgs convention that the ported systemd library expects.
    // (
      let
        tb = trivialBuilders;
      in {
        inherit
          (tb)
          writeTextFile
          writeShellScriptBin
          runtimeShell
          runCommand
          ;
      }
    )
    // lib.optionalAttrs (anySharedCache && ordinaryToolchainPackages != null) (
      builtins.listToAttrs (
        builtins.map (name: {
          inherit name;
          value = ordinaryToolchainPackages.${name};
        }) (builtins.filter isToolchainName (builtins.attrNames ordinaryToolchainPackages))
      )
    );
in
  self
