# lib/testing/darling-check.nix — Evaluation guards for Darling fleet helpers.
{
  pkgs,
  lib,
}: let
  inherit (import ./darling.nix {inherit pkgs lib;}) mkDarlingFleetSpec mkDarlingFleetSuite;

  artifact = pkgs.runCommand "darling-harness-check-artifact" {} ''
    mkdir -p "$out/bin"
    touch "$out/bin/probe"
  '';
  stubSystem = {
    extendModules = _: stubSystem;
  };
  probeCase = {
    name = "probe";
    inherit artifact;
    program = "bin/probe";
    args = ["one" "two"];
    expectedStdout = "probe\n";
    expectedStderr = "";
  };
  mkSuite = cases:
    mkDarlingFleetSuite {
      name = "darling-harness-check";
      system = stubSystem;
      inherit cases;
      payloadSizeMiB = 384;
    };
  force = value: builtins.deepSeq value true;
  acceptsValidSuite = let
    suite = mkSuite [
      probeCase
      (probeCase
        // {
          name = "second-probe";
          args = [];
        })
    ];
    disk = builtins.head suite.machines.darwin.extraDisks;
  in
    force suite
    && suite.name == "darling-harness-check"
    && disk.readOnly
    && disk.sizeMiB == 384
    && lib.hasInfix "aos.darling-vm-suite-result/v1" suite.testScript
    && lib.hasInfix "--uid=65534" suite.testScript;
  acceptsSingleFacade = let
    spec = mkDarlingFleetSpec {
      name = "darling-single-check";
      system = stubSystem;
      inherit artifact;
      program = "bin/probe";
      expectedStdout = "probe\n";
    };
  in
    force spec
    && spec.name == "darling-single-check"
    && lib.hasInfix "aos.darling-vm-result/v1" spec.testScript;
  rejects = cases: !(builtins.tryEval (force (mkSuite cases))).success;
  rejectsEmptySuite = rejects [];
  rejectsDuplicateNames = rejects [probeCase probeCase];
  rejectsUnsafeProgram = rejects [
    (probeCase
      // {
        program = "../bin/probe";
      })
  ];
  rejectsNonStringArgument = rejects [
    (probeCase
      // {
        args = [1];
      })
  ];
  allOk =
    lib.throwIfNot acceptsValidSuite
    "darling-harness: valid suite did not evaluate"
    (lib.throwIfNot acceptsSingleFacade
      "darling-harness: single-program facade did not evaluate"
      (lib.throwIfNot rejectsEmptySuite
        "darling-harness: empty suite should be rejected"
        (lib.throwIfNot rejectsDuplicateNames
          "darling-harness: duplicate case names should be rejected"
          (lib.throwIfNot rejectsUnsafeProgram
            "darling-harness: unsafe program path should be rejected"
            (lib.throwIfNot rejectsNonStringArgument
              "darling-harness: non-string argument should be rejected"
              true)))));
in
  pkgs.mkDerivation {
    pname = "darling-harness-check";
    version = "0";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          : ${builtins.toString allOk}
          mkdir -p "$out"
          printf 'PASS\n' > "$out/result"
        '';
      }
    ];
    meta.description = "Evaluation guards for batched Darling fleet tests";
  }
