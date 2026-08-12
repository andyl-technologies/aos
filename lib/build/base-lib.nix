##! lib/build/base-lib.nix — assemble the in-image on-host eval-only base-lib
##!
##! Produces a self-contained derivation that the on-host
##! evaluator imports by store path to recompute the config manifest for a
##! verified `host.nix` WITHOUT touching the from-source build graph. The
##! derivation bundles:
##!
##!   - the AOS `lib`, `modules`, `systems`, and `pkgs` *source* trees (the
##!     module engine + every module definition; `pkgs` source is needed only
##!     for the handful of path literals modules reference — no package is
##!     built on-host),
##!   - `frozen-pkgs.json` — every package's already-built store path, captured
##!     here at stage-1 (image build) via `freeze-pkgs.nix`,
##!   - `frozen-artifacts.json` plus `artifact-roots/` symlinks — the stage-1
##!     store paths of image-fixed config artifacts, retained through ordinary
##!     Nix output references (`aos.config._artifactSources`),
##!   - `image-manifest.json` — the immutable image's rendered artifact
##!     baseline, with the base library output linked through Nix's output
##!     placeholder,
##!   - `system-modules.nix` — the variant's module list, and
##!   - `default.nix` (from `base-lib-entry.nix`) exporting `evalHostConfig`.
##!
##! `mkBaseLib` evaluates the real package set at image-build time to capture
##! `_artifactSources`, the option schema, and the image artifact baseline. The
##! candidate manifest is recomputed on-host under a frozen `pkgs`; the eval-only
##! core (the engine laziness fixes + the F2-A job-script inversion) is what
##! makes that recomputation build-graph-free and byte-identical to this
##! stage-1 manifest.
{
  lib,
  pkgs,
  system,
}: {
  ## The auto-discovered base module list (`import ./modules`).
  baseModules,
  ## The image variant's own module list (e.g. `[ ./systems/server.nix ]`).
  systemModules,
  ## The ABI resolved from the image's complete module list, including inline
  ## image settings that cannot be copied into the source-backed library.
  moduleAbi,
  ## A short name for the variant, used only in the derivation name.
  systemName ? "system",
}: let
  freeze = import ./freeze-pkgs.nix {inherit lib;};

  # Evaluate the schema first so the ABI hash is available to the complete
  # image-baseline evaluation below without introducing a recursive value.
  schemaEval = lib.evalModules {
    modules =
      baseModules
      ++ systemModules
      ++ [{aos.system.moduleAbi = lib.mkForce moduleAbi;}];
    inherit pkgs lib;
  };

  # A base library is bound to the complete option schema it exposes, not to
  # the incidental store path that contains it. `_optionDecls` is an
  # options-only projection: reading it never forces a `config` value or a
  # derivation.  Attribute names are already returned in sorted order by the
  # module engine; sort explicitly here so this remains a set identity if the
  # engine's representation changes.
  optionSchema = builtins.sort (a: b: builtins.head a < builtins.head b) (
    builtins.map (decl: [decl.pathStr decl.typeSig]) schemaEval._optionDecls
  );
  abiHash = "sha256:${builtins.hashString "sha256" (builtins.toJSON {
    abi = moduleAbi;
    schema = optionSchema;
  })}";

  # Capture the artifact baseline produced by the immutable image modules.
  # Nix replaces the output placeholder with this base library's final store
  # path while realizing the derivation, so the embedded manifest has the
  # exact same self-reference as later on-host evaluations.
  baseLibOut = builtins.placeholder "out";
  placeholderBaseLibDigest = builtins.hashString "sha256" baseLibOut;
  realEval = lib.evalModules {
    modules =
      baseModules
      ++ systemModules
      ++ [
        {
          aos.system.moduleAbi = lib.mkForce moduleAbi;
          aos.config.evalAtBoot = {
            baseLib = baseLibOut;
            baseLibAbiHash = abiHash;
          };
        }
      ];
    inherit pkgs lib;
  };

  # Root ownership shipped by the image is local system state, just like
  # package-owned roots derived from the exact installed profile. Every root
  # declared by the bundled base/system modules is already present and must
  # never trigger a structural package fetch. Contributable paths retain the
  # module engine's curated markers; interface ABI follows the image module ABI
  # until a root-specific image ABI is introduced.
  bundledRootNames = builtins.sort builtins.lessThan (lib.unique (
    builtins.map (declaration: builtins.head declaration.path) realEval._optionDecls
  ));
  bundledRoots =
    builtins.map (root: {
      inherit root;
      interface_abi = moduleAbi;
      contributable = builtins.sort builtins.lessThan (
        builtins.map
        (declaration: lib.concatStringsSep "." (builtins.tail declaration.path))
        (builtins.filter
          (declaration:
            declaration.contributable
            && builtins.head declaration.path == root
            && builtins.length declaration.path > 1)
          realEval._optionDecls)
      );
    })
    bundledRootNames;

  # logical-name -> stage-1 store path, for every registered (non-frozen)
  # artifact source. `"${drv}"` forces the artifact to its built path; context
  # is discarded so the JSON is a plain string map. The output also carries
  # one symlink per source below, preserving the same paths as real Nix output
  # references so every frozen artifact is present when the base lib is copied.
  frozenArtifactSourcesRaw =
    lib.filterAttrs (_: v: v != null)
    realEval.config.aos.config._artifactSources;
  invalidArtifactNames =
    builtins.filter
    (name: builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" name == null)
    (builtins.attrNames frozenArtifactSourcesRaw);
  frozenArtifactSources =
    if invalidArtifactNames == []
    then frozenArtifactSourcesRaw
    else
      throw
      "base-lib: config artifact names must be single safe path components; invalid: ${lib.concatStringsSep ", " invalidArtifactNames}";
  frozenArtifacts =
    builtins.mapAttrs (_: drv: builtins.unsafeDiscardStringContext "${drv}")
    frozenArtifactSources;

  frozenPkgsFile = builtins.toFile "frozen-pkgs.json" (freeze.freezeToJSON pkgs);
  frozenArtifactsFile = builtins.toFile "frozen-artifacts.json" (builtins.toJSON frozenArtifacts);
  rawImageManifest = realEval.config.system.build.configManifest;
  # Output placeholders acquire their real store-path context only when Nix
  # realizes this derivation. Add the self-reference explicitly so the
  # baseline's dependency inventory agrees with an on-host reevaluation.
  imageManifest = builtins.toJSON (rawImageManifest
    // {
      storePaths = lib.unique (rawImageManifest.storePaths ++ [baseLibOut]);
      ownership =
        rawImageManifest.ownership
        // {
          storePaths =
            rawImageManifest.ownership.storePaths
            // {"${baseLibOut}" = "@base";};
        };
    });

  # The variant's module list, materialized as a Nix expression the bundled
  # entrypoint imports. Paths are rewritten to the bundled `./systems` copy so
  # they resolve inside the base-lib store path under `restrict-eval`.
  systemModulesNix = let
    rel = m: let
      s = builtins.toString m;
      # Keep only the `systems/...` tail so the path resolves under `$out`.
      parts = lib.splitString "/systems/" s;
    in
      if builtins.length parts > 1
      then "./systems/" + builtins.elemAt parts 1
      else throw "base-lib: system module ${s} is not under a systems/ directory";
  in
    "[\n"
    + lib.concatMapStringsSep "\n" (m: "  ${rel m}") systemModules
    + "\n  ./module-abi.nix"
    + "\n]\n";

  systemModulesFile = builtins.toFile "system-modules.nix" systemModulesNix;
  moduleAbiFile = builtins.toFile "module-abi.nix" ''
    {aos.system.moduleAbi = ${toString moduleAbi};}
  '';
in
  pkgs.runCommand "aos-base-lib-${systemName}" {
    passthru = {inherit frozenArtifacts optionSchema moduleAbi abiHash;};
    inherit imageManifest placeholderBaseLibDigest;
    passAsFile = ["imageManifest"];
  } ''
    mkdir -p "$out"

    # Bundle the source trees the on-host eval imports. `--no-preserve=mode` so
    # the copied files are writable enough for the store (the originals are
    # read-only store paths). Modules reference `../../pkgs/...` and
    # `../../lib/...` path literals, so all four trees must be present even
    # though no package is built.
    cp -rL --no-preserve=mode ${../../lib} "$out/lib"
    cp -rL --no-preserve=mode ${../../modules} "$out/modules"
    cp -rL --no-preserve=mode ${../../systems} "$out/systems"
    cp -rL --no-preserve=mode ${../../pkgs} "$out/pkgs"

    ${pkgs.sed}/bin/sed \
      -e "s|@system@|${system}|g" \
      -e "s|@abiHash@|${abiHash}|g" \
      ${./base-lib-entry.nix} > "$out/default.nix"
    cp ${frozenPkgsFile} "$out/frozen-pkgs.json"
    cp ${frozenArtifactsFile} "$out/frozen-artifacts.json"
    mkdir -p "$out/artifact-roots"
    ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: artifact: ''
        ln -s ${artifact} "$out/artifact-roots/${name}"
      '')
      frozenArtifactSources)}
    actual_base_lib_digest=$(printf '%s' "$out" | ${pkgs.coreutils}/bin/sha256sum | ${pkgs.coreutils}/bin/cut -d ' ' -f 1)
    ${pkgs.sed}/bin/sed \
      -e "s|sha256:$placeholderBaseLibDigest|sha256:$actual_base_lib_digest|g" \
      "$imageManifestPath" > "$out/image-manifest.json"
    cp ${systemModulesFile} "$out/system-modules.nix"
    cp ${moduleAbiFile} "$out/module-abi.nix"

    echo ${lib.escapeShellArg systemName} > "$out/system-name"
    echo ${lib.escapeShellArg abiHash} > "$out/abi-hash"
    echo ${toString moduleAbi} > "$out/module-abi"
    cp ${builtins.toFile "option-schema.json" (builtins.toJSON optionSchema)} "$out/option-schema.json"
    cp ${builtins.toFile "system-roots.json" (builtins.toJSON bundledRoots)} "$out/system-roots.json"
  ''
