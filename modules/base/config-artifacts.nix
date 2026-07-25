##! modules/base/config-artifacts.nix — image-fixed configuration artifacts
##!
##! Layer 2 of the eval-only core (see docs/rfcs/0011-on-host-config-eval/
##! eval-only-core.md). Some config modules build a *derivation* at eval time
##! for a `/etc` artifact or a unit input — e.g. `dbus-conf` merges the
##! `share/dbus-1` trees of several packages into a system bus config. These
##! artifacts are **image-fixed**: they depend on *image* config (which packages
##! are enabled), not on the operator `host.nix`, so they are identical across
##! every config generation of a given image. They cannot be Layer-1 frozen
##! (they are builder *calls*, not top-level packages) and cannot be rendered as
##! pure text (they merge file trees).
##!
##! A module registers such an artifact as a derivation under
##! `aos.config._artifactSources.<key>` and references it through
##! `config.aos.config.artifacts.<key>` (never the source directly):
##!
##! ```nix
##!   aos.config._artifactSources.dbus-system-conf =
##!     pkgs.dbus-conf { packages = cfg.packages; ... };
##!   # reference:
##!   "--config-file=${config.aos.config.artifacts.dbus-system-conf}/system.conf"
##! ```
##!
##! `artifacts.<key>` resolves to:
##!   - the **frozen store path** (a string-coercible record) when the on-host
##!     evaluator injects `aos.config.frozenArtifacts.<key>` — stage-2, no build;
##!   - the live **derivation source** otherwise — stage-1 / every existing
##!     system (`frozenArtifacts = {}`), so the resolved value is the exact same
##!     derivation as before and the build is byte-identical.
##!
##! At base-lib build time the producer forces `_artifactSources.<key>.outPath`
##! once and ships the resulting `frozenArtifacts` map to stage-2.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.config;

  # A true passthrough type: its merge returns the last definition's value
  # WITHOUT forcing it (unlike `types.anything`, whose merge inspects the value
  # to pick a strategy). This keeps an unfrozen `_artifactSources` entry a thunk,
  # so a stage-2 frozen `pkgs` lacking the builder function never evaluates it.
  raw = {
    name = "raw";
    description = "raw value (unevaluated)";
    check = _: true;
    merge = _loc: defs: (builtins.elemAt defs (builtins.length defs - 1)).value;
  };
in {
  options.aos.config = {
    _artifactSources = lib.mkOption {
      # `raw` (unevaluated) so an unfrozen source never forces its derivation
      # at stage-2: `artifacts.<key>` prefers the frozen path with a lazy `or`,
      # leaving the source thunk untouched (so a frozen `pkgs` that lacks the
      # builder function does not error).
      type = lib.types.attrsOf raw;
      default = {};
      internal = true;
      description = ''
        Image-fixed config-artifact derivations registered by modules. Built at
        stage-1; their store paths are captured into {option}`frozenArtifacts`
        for the on-host eval-only evaluator. Reference via {option}`artifacts`.
      '';
    };

    frozenArtifacts = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = {};
      internal = true;
      description = ''
        Stage-1-computed store paths for {option}`_artifactSources`, injected by
        the on-host evaluator (base-lib) so stage-2 references each artifact as a
        string without re-building it. Empty on every normal build, where
        {option}`artifacts` resolves to the live derivation source.
      '';
    };

    artifacts = lib.mkOption {
      type = lib.types.attrsOf raw;
      internal = true;
      readOnly = true;
      description = ''
        Resolved image-fixed config artifacts: the frozen store path (string-
        coercible) when available, else the live derivation. Modules reference
        `config.aos.config.artifacts.<key>` instead of the source directly.
      '';
    };
  };

  config.aos.config.artifacts =
    builtins.mapAttrs (
      name: source:
        if cfg.frozenArtifacts ? ${name}
        then let
          p = cfg.frozenArtifacts.${name};
        in {
          type = "derivation";
          inherit name;
          outPath = p;
          __toString = _: p;
        }
        else source
    )
    cfg._artifactSources;
}
