##! Runs the canonical gate chain with the migrated GPL suite components.
{
  system ? builtins.currentSystem,
  abiDriver ? "cargo",
}: let
  root = ../../..;
  aos = import root {inherit system;};
  inherit (aos) lib;
  gpl = aos.checks.build.bazel.qemu-gpl;
  pkgs =
    aos.pkgs
    // {
      crucible = gpl.suite;
      crucible-controller = gpl.suite.passthru.controller;
      crucible-qemu-plugin = gpl.installed.plugin;
      crucible-debug-gateway = gpl.installed.gateway;
    }
    // lib.optionalAttrs (abiDriver == "bazel") {
      crucibleBazelAbiOwners = aos.checks.build.bazel.abi-owners.all;
    };
  testing = import ../../../lib/testing {inherit pkgs lib;};
  checks = import ../../../tests/crucible {
    inherit pkgs lib testing;
    inherit (aos) mkSystem;
  };
in
  assert builtins.elem abiDriver ["cargo" "bazel"];
  assert checks.phase2.gates.abiConformance.rawGate.passthru.abiDriver == abiDriver; rec {
    # Request the named wrappers so their green-before-advance dependencies run.
    # The license driver still uses Cargo; ABI execution follows abiDriver.
    license-boundary = checks.phase1.gates.licenseBoundary;
    abi-conformance = checks.phase2.gates.abiConformance;
    abi-package-audit = checks.phase7.cruciblePackageAbiConformance;

    selections = pkgs.writeTextFile {
      name = "aos-bazel-gpl-normative-gate-selections.json";
      text = builtins.toJSON {
        schema_version = 1;
        abi_driver = abiDriver;
        suite = toString gpl.suite;
        controller = toString pkgs.crucible-controller;
        plugin = toString gpl.installed.plugin;
        gateway = toString gpl.installed.gateway;
        license_boundary = toString license-boundary;
        abi_conformance = toString abi-conformance;
      };
    };

    all = pkgs.runCommand "aos-bazel-gpl-normative-gates" {} ''
      mkdir -p "$out"
      ln -s ${license-boundary} "$out/license-boundary"
      ln -s ${abi-conformance} "$out/abi-conformance"
      cp ${selections} "$out/selections.json"
    '';
  }
