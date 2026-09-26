##! Explicit compiler-cache policy for application builders.
{
  lib,
  mkDerivation,
  jq,
  accache,
}: {
  compilers,
  roots,
  cacheDir,
  stateDir,
  readRoots ? ["."],
  # These names are removed from the compiler process, not merely ignored by
  # its key. Callers that intentionally use env!("out") must override this
  # list; retaining the value correctly partitions actions by output path.
  removeEnvironment ? [
    "out"
    "outputs"
    "src"
    "buildInputs"
    "nativeBuildInputs"
    "NIX_ATTRS_JSON_FILE"
    "NIX_ATTRS_SH_FILE"
    "NIX_BUILD_TOP"
    "buildCommand"
    "buildPhase"
    "configurePhase"
    "installPhase"
    "builder"
    "args"
    "name"
    "pname"
    "version"
    "phases"
    "RUSTC_WRAPPER"
    # Supported cached actions produce objects/libraries, not final linked
    # executables. The stdenv adds an output-specific install rpath here;
    # removing it from compiler execution permits reuse across derivations.
    # Final linking bypasses accache with the original environment intact.
    "NIX_LDFLAGS"
    "CARGO_MAKEFLAGS"
    "MAKEFLAGS"
    "MFLAGS"
    "SHLVL"
    "_"
    "OLDPWD"
  ],
}: let
  manifest = mkDerivation {
    pname = "accache-nix-manifest";
    version = "1";
    src = null;
    buildDeps = [jq];
    outputChecks.out = {};
    exportReferencesGraph.compilers = lib.unique roots;
    dontStrip = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "build";
        script = ''
          # NAR identities come from the daemon's realized closure, including
          # compiler wrappers, loaders, sysroots, and transitive shared libraries.
          # Source snapshots and .drv identities deliberately are not roots.
          jq -cS \
            --argjson compilers ${lib.escapeShellArg (builtins.toJSON compilers)} \
            --argjson remove ${lib.escapeShellArg (builtins.toJSON removeEnvironment)} \
            --argjson reads ${lib.escapeShellArg (builtins.toJSON readRoots)} \
            '{schema: 1, compilers: $compilers, remove_environment: $remove, read_roots: $reads,
              closure: [.compilers[] | {path, narHash}] | sort_by(.path)}' \
            "$NIX_ATTRS_JSON_FILE" > "$out/manifest.json"
        '';
      }
    ];
  };
in {
  ACCACHE_DIR = cacheDir;
  ACCACHE_STATE_DIR = stateDir;
  ACCACHE_MANIFEST = "${manifest}/manifest.json";
  RUSTC_WRAPPER = "${accache}/bin/accache";
  CMAKE_C_COMPILER_LAUNCHER = "${accache}/bin/accache";
  CMAKE_CXX_COMPILER_LAUNCHER = "${accache}/bin/accache";
}
