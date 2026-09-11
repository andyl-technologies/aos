##! Builds public native tools after the tier's private construction tools exist.
{
  privateTools,
  compiler ? privateTools.gcc,
  directory,
  gccVersion,
  manifestNames,
  extraToolNames ? [],
  compilerSource ? directory + "/gcc.nix",
  compilerToolOverrides ? {},
  binutilsBuildOverrides ? {},
  libcBuildOverrides ? {},
  publicScriptFilter ? null,
  manifestToolOverrides ? {},
  staticNoPie ? false,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}: let
  withRuntimeShell = import ./with-runtime-shell.nix;
  lib = import ../../../lib {
    system = buildPlatform.system;
    bash = exports.bash;
  };
  phases = import ../../phases.nix;
  mkTierStdenv = import ../../tier-stdenv.nix {
    inherit lib buildPlatform hostPlatform targetPlatform;
  };

  # The completed compiler stack must exist before Bash can be rebuilt against
  # it. Keep the construction shell for that transition, then use the rebuilt
  # Bash for every remaining public tool.
  buildTools = privateTools;
  platforms = {inherit buildPlatform hostPlatform targetPlatform;};
  call = scope: path: overrides: let
    function = import path;
    arguments = builtins.intersectAttrs (builtins.functionArgs function) scope;
  in
    function (arguments // overrides);
  finish = package:
    withRuntimeShell {
      inherit package buildTools;
      shell = "${exports.bash}/bin/bash";
    };
  finishFiltered = package:
    withRuntimeShell {
      inherit package buildTools;
      shell = "${exports.bash}/bin/bash";
      scriptFilterTool = publicScriptFilter;
    };
  finishConstruction = package:
    withRuntimeShell {
      inherit package buildTools;
      shell = "${privateTools.bash}/bin/bash";
      scriptFilterTool = publicScriptFilter;
    };

  libcBuildScope =
    buildTools
    // platforms
    // {
      prev = buildTools;
      this = buildTools // {gcc = compiler;};
      gcc = compiler;
      # libc installs Perl utilities. Use the tier's construction interpreter
      # so completing libc does not depend on the public Perl built against it.
      runtimePerl = privateTools.perl or null;
    };
  compilerForLibc = import ./retarget-compiler.nix {
    inherit compiler gccVersion buildTools buildPlatform hostPlatform staticNoPie;
    inherit (buildTools) binutils;
    glibc = exports.glibc;
  };
  compilerBuildTools =
    buildTools
    // {
      gcc = compilerForLibc;
      glibc = exports.glibc;
    };
  compilerBuildScope =
    compilerBuildTools
    // platforms
    // {
      prev = compilerBuildTools;
      this = compilerBuildTools;
    };

  publicCompilerTools =
    buildTools
    // {
      inherit (exports) gcc glibc binutils;
    };
  publicBuildScope =
    publicCompilerTools
    // platforms
    // {
      prev = publicCompilerTools;
      this = publicCompilerTools;
    };
  publicStdenv = mkTierStdenv {
    tc = publicCompilerTools;
    staticDefault = true;
    inherit staticNoPie;
  };
  mkTool = import ./mk-autotools-tool.nix {
    inherit lib phases buildPlatform hostPlatform;
    tierStdenv = publicStdenv;
  };
  manifestScope =
    publicBuildScope
    // exports
    // {
      # Perl's Cwd embeds the chosen pwd executable. Coreutils is constructed
      # first with private documentation tools, breaking the Perl/autotools cycle.
      prev = publicCompilerTools // {coreutils = exports.coreutils;};
    };
  manifest = call manifestScope (directory + "/manifest.nix") {};
  constructionManifest = call publicBuildScope (directory + "/manifest.nix") {};
  bashBuildTools =
    privateTools
    // {
      inherit (exports) gcc glibc binutils;
    };
  bashLib = import ../../../lib {
    system = buildPlatform.system;
    bash = privateTools.bash;
  };
  bashStdenv =
    (import ../../tier-stdenv.nix {
      lib = bashLib;
      inherit buildPlatform hostPlatform targetPlatform;
    }) {
      tc = bashBuildTools;
      staticDefault = true;
      inherit staticNoPie;
    };
  mkBash = import ./mk-autotools-tool.nix {
    lib = bashLib;
    inherit phases buildPlatform hostPlatform;
    tierStdenv = bashStdenv;
  };
  compileTool = spec:
    finishFiltered (mkTool (spec
      // {
        inherit gccVersion;
        runtimeShell = "${exports.bash}/bin/bash";
        sourceScriptFilter = publicScriptFilter;
      }));

  manifestTools = builtins.listToAttrs (map (name: {
    inherit name;
    value = compileTool (manifest.${name} // (manifestToolOverrides.${name} or {}));
  }) (builtins.filter (name: !(builtins.elem name ["bash" "coreutils"])) manifestNames));
  extraTools = builtins.listToAttrs (map (name: {
      inherit name;
      value = finish (call publicBuildScope (directory + "/${name}.nix") {});
    })
    extraToolNames);

  exports =
    manifestTools
    // extraTools
    // {
      bash = let
        package = withRuntimeShell {
          package = mkBash (constructionManifest.bash
            // {
              inherit gccVersion;
              runtimeShell = "$out/bin/bash";
              sourceScriptFilter = publicScriptFilter;
            });
          buildTools = bashBuildTools;
          shell = "$out/bin/bash";
        };
      in
        package
        // {
          passthru = (package.passthru or {}) // {evidenceRuntimePackages = [exports.glibc];};
        };
      inherit (privateTools) linuxHeaders;
      glibc = let
        package = finishConstruction (call libcBuildScope (directory + "/glibc.nix") libcBuildOverrides);
      in
        if privateTools ? perl
        then
          import ./finalize-libc.nix {
            inherit package buildTools;
            runtimePerl = exports.perl;
            constructionPerl = privateTools.perl;
          }
        else package;
      binutils = finishConstruction (call compilerBuildScope (directory + "/binutils.nix") binutilsBuildOverrides);
      gcc = finishConstruction (call (compilerBuildScope
        // {
          prev = compilerBuildTools // {binutils = exports.binutils;} // compilerToolOverrides;
          binutils = exports.binutils;
          gccStage1 = compilerForLibc;
        })
      compilerSource {});
      coreutils = compileTool (constructionManifest.coreutils // (manifestToolOverrides.coreutils or {}));
    };
in
  exports // lib.optionalAttrs (privateTools ? gccStage2) {gccStage2 = exports.gcc;}
