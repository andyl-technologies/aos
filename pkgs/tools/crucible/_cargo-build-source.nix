##! Compile-time source for the Crucible workspace test builds.
##!
##! The gate source in `_source.nix` also carries documentation, Nix wiring,
##! and fixtures that tests read only at run time. Compiling from that tree
##! would rebuild every test binary after any gate or document edit. This
##! tree keeps the Cargo workspace and exactly the files that Crucible crates
##! embed with `include_str!` or `include_bytes!`. A missing entry fails the
##! compile instead of silently changing what a test embeds.
{lib}: let
  repoRoot = ../../..;
  repoRootString = toString repoRoot;

  # Files and directories outside crates/ that Crucible crates embed. Each
  # entry is relative to the repository root.
  embeddedPaths = [
    "default.nix"
    "docs/rfcs/0014-signal-driven-fault-model/04-fault-taxonomy.md"
    "docs/rfcs/0014-signal-driven-fault-model/08-executable-effect-contracts.md"
    "docs/rfcs/0020-crucible-campaigns"
    "docs/users/crucible"
    "pkgs/emulation/qemu-patches/_atomic-patch.nix"
    "pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch"
    "tests/crucible/_e2e-determinism-native-runner.sh"
    "tests/crucible/_phase9-campaign-release-acceptance.sh"
    "tests/crucible/campaign-gate-matrix-inventory.toml"
    "tests/crucible/campaign-release-acceptance-contract.toml"
    "tests/crucible/default.nix"
    "tests/crucible/fixtures/debugger-live-aarch64.scenario.toml"
    "tests/crucible/fixtures/debugger-live-x86_64.scenario.toml"
    "tests/crucible/fixtures/e2e-determinism.scenario.toml"
    "tests/crucible/fixtures/envoy-network/init.sh"
    "tests/crucible/fixtures/envoy-network/traffic.py"
    "tests/crucible/fixtures/happy-path.scenario.toml"
    "tests/crucible/fixtures/live-qemu-fuzz.family.toml"
    "tests/crucible/fixtures/live-qemu-search.scenario.toml"
    "tests/crucible/fixtures/nginx-curl-http-200.scenario.toml"
    "tests/crucible/phase7-qemu-hot-fork-equivalence-vm.nix"
    "tests/crucible/phase9-campaign-release-acceptance-contract.nix"
    "tests/crucible/phase9-campaign-release-acceptance.nix"
  ];
  embeddedRoots = map (path: "${repoRootString}/${path}") embeddedPaths;

  # A directory is kept when it contains or is an embedded path.
  isAncestorOfEmbedded = pathString:
    builtins.any (root: lib.hasPrefix "${pathString}/" root) embeddedRoots;
  isWithinEmbedded = pathString:
    builtins.any (root: pathString == root || lib.hasPrefix "${root}/" pathString) embeddedRoots;
in
  builtins.path {
    path = repoRoot;
    name = "crucible-cargo-build-src";
    filter = path: _type: let
      pathString = toString path;
      base = baseNameOf path;
      crates = "${repoRootString}/crates";
    in
      base
      != ".git"
      && base != ".crucible"
      && base != "target"
      && base != "__pycache__"
      && !lib.hasSuffix ".pyc" base
      && (
        pathString
        == crates
        || lib.hasPrefix "${crates}/" pathString
        || isAncestorOfEmbedded pathString
        || isWithinEmbedded pathString
      );
  }
