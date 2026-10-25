##! Runs the canonical gate chain with the migrated GPL suite components.
{system ? builtins.currentSystem}: let
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
    };
  testing = import ../../../lib/testing {inherit pkgs lib;};
  checks = import ../../../tests/crucible {
    inherit pkgs lib testing;
    inherit (aos) mkSystem;
  };
in rec {
  # Request the named wrappers so their green-before-advance dependencies run.
  # The canonical drivers still use Cargo during this comparison stage.
  license-boundary = checks.phase1.gates.licenseBoundary;
  abi-conformance = checks.phase2.gates.abiConformance;

  selections = pkgs.writeTextFile {
    name = "aos-bazel-gpl-normative-gate-selections.json";
    text = builtins.toJSON {
      schema_version = 1;
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
