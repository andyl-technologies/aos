##! lib/ci/groups.nix — Segment the check set into a few functional CI jobs.
##!
##! AOS has hundreds of checks today and will have thousands. Fanning out
##! one CI job per check is wrong on two counts: it blows GitHub's matrix
##! limits, and most checks share large build closures, so per-check jobs
##! rebuild the same toolchain/packages over and over.
##!
##! Instead we segment checks into a small, fixed set of jobs by *function*
##! (lint, rust, eval, tla, build, integration, vm, fleet). Each job builds
##! its whole group with a single `nix build` of one aggregate derivation,
##! so a shared dependency is built once per job. Adding a check never adds
##! a job — it just joins an existing group by name.
##!
##! The grouping is keyed off the flat check names from `flake.nix`'s
##! `checksFor` (same naming the rest of CI relies on).
{
  lib,
  pkgs,
}: let
  inherit (lib) hasPrefix;

  # Fixed, ordered set of CI groups. Each job in the workflow corresponds
  # to exactly one of these.
  groupNames = [
    "lint"
    "rust"
    "eval"
    "tla"
    "build"
    "integration"
    "vm"
    "fleet"
  ];

  # Pure-eval library checks (no heavy builds) that belong with `eval`.
  evalExtras = [
    "module-args"
    "module-enforcement"
    "ignition-format"
    "fleet-spec" # the spec *validator* — pure eval, despite the name
    "systemd-lib"
    "systemd-generate"
    "trivial-builders"
  ];

  # Map a check name to its functional group. Prefix-based so new checks
  # join automatically. Order matters: exact/eval cases before the broad
  # `fleet-`/`build-` prefixes.
  groupOf = name:
    if name == "format" || name == "lint"
    then "lint"
    else if hasPrefix "cargo-" name
    then "rust"
    else if name == "eval" || builtins.elem name evalExtras
    then "eval"
    else if hasPrefix "tla-" name
    then "tla"
    else if name == "aos" || hasPrefix "build-" name
    then "build"
    else if hasPrefix "integration-" name
    then "integration"
    else if hasPrefix "server-" name || hasPrefix "edge-" name
    then "vm"
    else if hasPrefix "fleet-" name
    then "fleet"
    # Unknown checks build on the heavy runner rather than being treated
    # as cheap — fold them into `build`.
    else "build";

  # Build the per-group aggregate derivations from a flat check set.
  # Each aggregate depends on every member, so building it builds the
  # whole group (shared closures realised once).
  mkCiGroups = checks: let
    names = builtins.attrNames checks;
    membersOf = g: builtins.filter (n: groupOf n == g) names;

    mkAggregate = g: let
      members = membersOf g;
    in
      pkgs.mkDerivation {
        pname = "aos-ci-${g}";
        version = "0";
        src = null;
        buildDeps = map (n: checks.${n}) members;
        # Record membership so `nix eval .#ciGroups.<sys>.<g>.passthru.members`
        # is introspectable ("what did this job cover").
        passthru.members = members;
        phases = [
          {
            name = "check";
            script = ''
              mkdir -p $out
              echo "ci group '${g}': ${toString (builtins.length members)} checks" > $out/result
            '';
          }
        ];
        meta.description = "AOS CI group: ${g}";
      };
  in
    builtins.listToAttrs (
      map (g: {
        name = g;
        value = mkAggregate g;
      })
      groupNames
    );
in {
  inherit mkCiGroups groupOf groupNames;
}
