##! pkgs/build-support/_config-module-renderer.nix — configuration-module
##! output renderer.
##!
##! Converts a package-authored `configModule` attrset into a separate store
##! path — the package's second `config` output. The
##! rendered path carries `module.nix` at its root (plus any relative-imported
##! private `.nix`) and a `config-meta.json` describing the module's declared
##! interface. Like the expose renderer, the payload derivation never receives
##! the rendered path as a build input; consumers reach it through
##! `pkg.configModule` / `pkg.passthru.configModule`.
##!
##! The rendered store path is pure data: it must close over no derivations
##! (the publish-time `validate_config_output_meta` lint enforces this in
##! `crates/aos-package/src/types.rs`). The module references binaries by
##! string path; those are pinned by the config-eval manifest's `store_paths`,
##! never by a reference edge out of this output.
##!
##! ## `configModule` schema
##!
##! ```nix
##! configModule = {
##!   # Required: the directory containing `module.nix` at its root.
##!   src = ./config-module;
##!   # Inclusive base-lib ABI band this module is compatible with.
##!   moduleAbiCompat = { min = 1; max = 1; };
##!   # OPTIONAL author hints. The authoritative `declares` / `ownsRoots` /
##!   # `contributes` / `providesCapabilities` are DERIVED at publish time by an
##!   # options-only eval of the module in isolation (see the TODO below); these
##!   # fields are recorded only as a cross-check / pre-eval seed.
##!   declares = [ "firewall.allowedTCPPorts" ];
##!   ownsRoots = [ { root = "firewall"; interfaceAbi = 1; contributable = [ "allowedTCPPorts" ]; } ];
##!   contributes = [ ];
##!   providesCapabilities = [ ];
##! };
##! ```
{
  lib,
  pkgs,
}: let
  throwIfNot = lib.throwIfNot;

  knownKeys = [
    "src"
    "moduleAbiCompat"
    "declares"
    "ownsRoots"
    "contributes"
    "providesCapabilities"
  ];

  # Render one package's config module into its `config` output store path.
  #
  # Returns a derivation whose output is the NAR the registry records as
  # `ConfigOutputMeta.store_path`. The publish side (apr) reads `nar_hash`,
  # `nar_size`, and `references` off the realised path and the
  # `config-meta.json` describing the declared interface.
  render = {
    packageName,
    configModule,
  }: let
    extraKeys = builtins.filter (k: !(builtins.elem k knownKeys)) (builtins.attrNames configModule);

    src =
      configModule.src
      or (throw "configModule for package '${packageName}' must set 'src' (the directory containing module.nix)");

    abiCompat =
      configModule.moduleAbiCompat or {
        min = 1;
        max = 1;
      };
    abiMin = abiCompat.min or 1;
    abiMax = abiCompat.max or 1;

    # NOTE (populate path): `declares` / `ownsRoots` / `contributes` /
    # `providesCapabilities` are recorded here from author hints, but the
    # AUTHORITATIVE values are derived at publish time by an options-only eval
    # of `module.nix` in isolation (the package module's declared provides
    # derived, not declared"). That step needs the evaluator and is wired in a
    # later changeset; until then apr records these hints verbatim and the
    # options-only-eval cross-check is a TODO.
    metaJson = builtins.toJSON {
      schema = "aos.config-module-meta/v1";
      module_abi_compat = {
        min = abiMin;
        max = abiMax;
      };
      declares = configModule.declares or [];
      owns_roots = builtins.map (r: {
        root = r.root;
        interface_abi = r.interfaceAbi or abiMin;
        contributable = r.contributable or [];
      }) (configModule.ownsRoots or []);
      contributes = builtins.map (c: {
        root = c.root;
        paths = c.paths or [];
      }) (configModule.contributes or []);
      provides_capabilities = configModule.providesCapabilities or [];
    };
  in
    throwIfNot
    (extraKeys == [])
    "mkDerivation configModule for package '${packageName}' contains unknown keys: ${builtins.concatStringsSep ", " extraKeys}"
    (throwIfNot
      (abiMin <= abiMax)
      "configModule for package '${packageName}' has an inverted moduleAbiCompat band: min ${toString abiMin} > max ${toString abiMax}"
      (pkgs.runCommand "config-module-${packageName}" {
          inherit metaJson;
          passAsFile = ["metaJson"];
          # Pure-data output: must not pull a derivation into its closure.
          preferLocalBuild = true;
          allowSubstitutes = false;
        } ''
          set -eu
          mkdir -p "$out"
          if [ ! -e "${src}/module.nix" ]; then
            echo "config module for '${packageName}' has no module.nix at ${src}" >&2
            exit 1
          fi
          cp -a "${src}/." "$out/"
          cp "$metaJsonPath" "$out/config-meta.json"
        ''));
in {
  inherit render;
}
