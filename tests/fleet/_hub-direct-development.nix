# Explicit reduced workload over the ordinary fleet's immutable runtime inputs.
# Admission and prequalification remain required; this is never qualification.
{
  lib,
  pkgs,
  mkSystem,
  runtimeSource,
  runtimeSourceIdentity,
}: let
  # Preserve a realized source's store context. A literal Nix path would copy it
  # under a second name and rebuild source-pinned helpers for identical bytes.
  runtime = builtins.storePath (toString runtimeSource);
  fixture = import (runtime + "/tests/fleet/_native-hub-production.nix") {
    inherit lib pkgs mkSystem;
  };
  publication = import (runtime + "/tests/fleet/_container-publication-project.nix") {
    inherit lib pkgs;
    packages.hub-helper = fixture.helperV1;
  };
  original = import ./hub-hybrid.nix {
    inherit lib pkgs mkSystem runtimeSourceIdentity;
    runtimeSource = runtime;
    separateDatabase = true;
    externalDirect = true;
  };
  anchor = "FLEET_CUTOFF_MONOTONIC = time.monotonic() + 14400";
  development =
    ''
      DEVELOPMENT_PUBLICATION_INVENTORY = ${builtins.toJSON (toString publication.inventoryFile)}
      DEVELOPMENT_PUBLICATION_PROJECT = ${builtins.toJSON "${publication.project}/default.nix"}
    ''
    + builtins.readFile ./_hub-direct-development.py;
in
  assert lib.hasInfix anchor original.testScript;
    original
    // {
      name = "hub-direct-development";
      timeout = 1800;
      testScript =
        builtins.replaceStrings [anchor] [
          (development + "\nFLEET_CUTOFF_MONOTONIC = time.monotonic() + 1800")
        ]
        original.testScript;
    }
