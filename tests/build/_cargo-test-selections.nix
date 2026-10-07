# Pure check-builder contract: role selections must not unify Cargo graphs.
let
  phases = import ../../stdenv/phases.nix;
  checks = arguments:
    builtins.filter (phase: phase.name == "check")
    (phases.cargoPhases ({cargoDeps = "unused";} // arguments));
  script = arguments: (builtins.head (checks arguments)).script;
  matches = expression: value: builtins.match expression value != null;
  scalar = script {cargoTestFlags = "-p first";};
  singleton = script {cargoTestFlagSets = ["-p first"];};
  selections = {
    cargoTestFlagSets = ["-p first --features controller" "-p second --features policy"];
  };
  cargo = script selections;
  nextest = script (selections // {cargoNextest = "selected-nextest";});
  invalid = value: !(builtins.tryEval (script {cargoTestFlagSets = value;})).success;
in
  assert scalar == singleton;
  assert matches ".*AOS_CROSS_COMPILING.*" cargo;
  assert matches ".*cargo test.*-p first --features controller.*cargo test.*-p second --features policy.*" cargo;
  assert matches ".*cargo nextest run.*-p first --features controller.*cargo nextest run.*-p second --features policy.*" nextest;
  assert matches ".*--cargo-profile release.*" nextest;
  assert checks {
    doCheck = false;
    cargoTestFlagSets = [""];
  }
  == [];
  assert invalid [""];
  assert invalid [" \t\n"];
  assert invalid [1];
  assert invalid "not-a-list"; true
