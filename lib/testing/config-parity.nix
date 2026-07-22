# lib/testing/config-parity.nix — flat-merge to module-eval parity.
#
# operability.md §Parity gate (model: the aos-nix `.drv` parity gate). The
# safe-migration invariant is that a package migrating from a flat
# `expose.config` to an equivalent config module renders a **byte-identical**
# materialized artifact + reload/restart set. The authoritative oracle is the
# Rust `golden_config_artifact` integration test (CS1): it snapshots
# `aos_package::render_package_config` for a multi-artifact fixture and pins
#   (a) equality with the committed golden under tests/fixtures/,
#   (b) order independence (shuffled artifact/field input -> identical bytes),
#   (c) idempotence.
# That test runs inside the hermetic `pkgs.aos` build, so byte-parity is already
# gated on every PR through the crate build.
#
# This Nix derivation is the declarative CI handle for that gate: it pins the
# committed golden fixture into the closure and re-asserts its well-formedness
# (non-empty, canonical `=== <name> ===` section headers), so a reviewer sees
# `checks.config-parity` go RED in the same PR that perturbs the oracle's
# fixture. As packages migrate, each gains a flat-vs-module parity fixture in
# the Rust oracle; once module-only, the fixture retires.
#
# Runs via `nix-build -A checks.config-parity`.
{
  pkgs,
  lib,
}: let
  golden = ../../crates/aos-package/tests/fixtures/golden_config_artifact/web.golden;
  goldenText = builtins.readFile golden;

  # The golden is a sequence of `=== <name> ===` sections (the order-independent
  # canonical form the Rust oracle compares). Assert it parses as such.
  sectionHeaders =
    builtins.filter (l: builtins.match "=== .* ===" l != null)
    (lib.splitString "\n" goldenText);

  goldenNonEmpty = goldenText != "";
  hasSections = sectionHeaders != [];
  # The fixture corpus spans three artifacts (env/json/toml); a regression that
  # drops a section is a parity-oracle break.
  hasAllSections = builtins.length sectionHeaders >= 3;

  evalAssertions =
    lib.throwIfNot goldenNonEmpty
    "config-parity: the committed flat-merge golden must be non-empty"
    (lib.throwIfNot hasSections
      "config-parity: the golden must contain canonical '=== <name> ===' section headers"
      (lib.throwIfNot hasAllSections
        "config-parity: the golden must retain all fixture artifact sections (parity-oracle break)"
        true));
in
  pkgs.mkDerivation {
    pname = "config-parity-check";
    version = "0";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          : ${builtins.toString evalAssertions}
          mkdir -p $out
          cp ${golden} $out/web.golden
          echo "==> config-parity gate" | tee $out/result
          echo "  flat-merge golden present + well-formed (${builtins.toString (builtins.length sectionHeaders)} sections): OK"
          echo "  authoritative byte-parity oracle: crates/aos-package/tests/golden_config_artifact.rs (runs in pkgs.aos build)"
        '';
      }
    ];
  }
