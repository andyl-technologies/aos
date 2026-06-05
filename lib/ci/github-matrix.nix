##! lib/ci/github-matrix.nix — Turn the `checks` set into a GitHub Actions matrix.
##!
##! `flake.nix` is the single source of truth for what CI runs: every
##! `checks.<system>.<name>` becomes one matrix entry, and therefore one
##! independently-reported GitHub status. Adding a check in Nix adds a CI
##! job automatically — no workflow edits.
##!
##! This is a hand-rolled, pure-Nix equivalent of
##! `nix-github-actions.lib.mkGithubMatrix`. We cannot use that flake
##! (it pulls nixpkgs); AOS depends on nothing but itself.
##!
##! The generator only forces `builtins.attrNames checks` — it never
##! evaluates a check derivation — so `nix eval .#githubActions.matrix`
##! stays as cheap as enumerating the check set.
##!
##! Each entry is classified into a *tier*, which selects the runner and
##! whether KVM is required:
##!
##!   tier 0  fast, no build      style/lint/eval         andyl-nixos-latest
##!   tier 1  compiles / builds   cargo build, packages   andyl-nixos-latest-32
##!   tier 2  virtualized (KVM)   VM & fleet integration  andyl-nixos-latest-32
{lib}: let
  # Self-hosted runner labels (see nix-host: config/host/role/builder).
  runners = {
    fast = "andyl-nixos-latest"; # 8 GB shape, plentiful
    heavy = "andyl-nixos-latest-32"; # 32 GB shape, KVM-capable
  };

  tier0 = {
    tier = 0;
    runner = runners.fast;
    needsKvm = false;
  };
  tier1 = {
    tier = 1;
    runner = runners.heavy;
    needsKvm = false;
  };
  tier2 = {
    tier = 2;
    runner = runners.heavy;
    needsKvm = true;
  };

  # Exact-name classification, checked before the prefix rules below.
  # Anything pure-eval or non-compiling lives here as tier 0; the cargo
  # build/test/doc gates and the `aos` package build are tier 1.
  explicit = {
    format = tier0;
    lint = tier0;
    eval = tier0;
    cargo-fmt = tier0;
    cargo-clippy = tier0;
    module-args = tier0;
    module-enforcement = tier0;
    ignition-format = tier0;
    fleet-spec = tier0; # the spec *validator* — pure eval, despite the name
    systemd-lib = tier0;
    systemd-generate = tier0;
    trivial-builders = tier0;
    cargo-test = tier1;
    cargo-doc = tier1;
    aos = tier1;
  };

  # Prefix rules for the dynamically-discovered check families.
  prefixRules = [
    {
      prefix = "tla-";
      tier = tier0;
    }
    {
      prefix = "build-";
      tier = tier1;
    }
    {
      prefix = "integration-";
      tier = tier2;
    }
    {
      prefix = "fleet-";
      tier = tier2;
    }
    {
      prefix = "server-";
      tier = tier2;
    }
    {
      prefix = "edge-";
      tier = tier2;
    }
    {
      prefix = "vm-";
      tier = tier2;
    }
  ];

  # Classify a check by name → { tier; runner; needsKvm; }.
  #
  # Explicit names win; then the first matching prefix; otherwise the
  # fail-safe default of tier 1 (build it on the big runner rather than
  # silently treat an unknown check as cheap).
  classify = name:
    if explicit ? ${name}
    then explicit.${name}
    else let
      match = lib.findFirst (r: lib.hasPrefix r.prefix name) null prefixRules;
    in
      if match != null
      then match.tier
      else tier1;

  # Build the `{ include = [...]; }` matrix for one system's check set.
  #
  # `name`  is the bare check name (the GitHub status label).
  # `attr`  is the build target passed to `nix build .#<attr>`.
  #
  # `exclude` lists checks that have a dedicated, always-runs job in the
  # workflow (the fast lane) and so should not also appear as a matrix
  # entry — this avoids a duplicate GitHub status for the same check.
  # They remain real checks (`nix flake check` still runs them); they are
  # merely omitted from the fan-out view.
  mkGithubMatrix = {
    checks,
    system,
    exclude ? [],
  }: let
    entry = name: let
      c = classify name;
    in {
      inherit name system;
      inherit (c) tier needsKvm runner;
      attr = "checks.${system}.${name}";
    };
    names = builtins.filter (n: !(builtins.elem n exclude)) (builtins.attrNames checks);
  in {
    include = map entry names;
  };
in {
  inherit mkGithubMatrix classify runners;
}
