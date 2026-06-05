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
  # Split a list into at most `n` contiguous, near-equal, non-empty chunks.
  chunkInto = n: list: let
    len = builtins.length list;
    size =
      if len == 0
      then 1
      else (len + n - 1) / n; # ceil(len / n) with integer division
  in
    builtins.filter (c: c != []) (
      builtins.genList (
        i: let
          start = i * size;
        in
          builtins.filter (x: x != null) (
            builtins.genList (
              j: let
                idx = start + j;
              in
                if idx < len
                then builtins.elemAt list idx
                else null
            )
            size
          )
      )
      n
    );

  # The build target for a check name.
  target = system: name: ".#checks.${system}.${name}";

  # GitHub Actions caps a workflow's matrix at 256 jobs. AOS has ~260
  # checks, the bulk being homogeneous per-package `integration-*` smoke
  # tests. We keep one job (and one status) per "real" suite (server-,
  # edge-, fleet-, tla-, build-, cargo-, eval, …) and bucket the
  # `integration-*` family into `integrationShards` jobs, each building
  # several checks with one `nix build`. This stays comfortably under the
  # cap with room to grow.
  #
  # Every entry carries `attrs` (a space-joined list of `.#` targets, one
  # or more) so the workflow's build step is uniform: `nix build $attrs`.
  mkGithubMatrix = {
    checks,
    system,
    exclude ? [],
    integrationShards ? 25,
  }: let
    names = builtins.filter (n: !(builtins.elem n exclude)) (builtins.attrNames checks);

    isIntegration = n: lib.hasPrefix "integration-" n;
    integrationNames = builtins.filter isIntegration names;
    soloNames = builtins.filter (n: !(isIntegration n)) names;

    # One job (one status) per non-integration check.
    soloEntry = name: let
      c = classify name;
    in {
      inherit name system;
      inherit (c) tier needsKvm runner;
      attrs = target system name;
    };

    # `integration-*` bucketed into shards; all are tier 2 / KVM.
    c2 = classify "integration-";
    shardChunks = chunkInto integrationShards integrationNames;
    nShards = builtins.length shardChunks;
    shardEntry = i: chunk: {
      name = "integration ${toString (i + 1)}/${toString nShards}";
      inherit system;
      inherit (c2) tier needsKvm runner;
      attrs = builtins.concatStringsSep " " (map (target system) chunk);
    };
  in {
    include =
      (map soloEntry soloNames)
      ++ (builtins.genList (i: shardEntry i (builtins.elemAt shardChunks i)) nShards);
  };
in {
  inherit mkGithubMatrix classify runners chunkInto;
}
