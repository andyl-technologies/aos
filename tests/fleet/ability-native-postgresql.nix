##! Native PostgreSQL provisioning, isolation, lifecycle, and teardown acceptance.
{
  lib,
  mkSystem,
  pkgs,
  qualificationImage ? false,
}: let
  fixture = import ./_postgresql-runtime-reference.nix {
    inherit lib mkSystem pkgs;
    guestTools = qualificationImage;
  };
in
  {
    name = "ability-native-postgresql";
    timeout = 14400;
    bootTimeout = 600;

    machines.runtime = {
      system = fixture.runtimeSystem;
      extraClosures = fixture.extraClosures;
      varSizeMiB = 12288;
      memoryMiB = 4096;
    };

    testScript =
      fixture.testPrelude
      + builtins.readFile ./ability-native-postgresql-helpers.py
      + builtins.readFile ./ability-native-postgresql-lifecycle.py
      + builtins.readFile ./ability-native-postgresql-network.py
      + builtins.readFile ./ability-native-postgresql-quarantine.py
      + builtins.readFile ./ability-native-postgresql-security.py
      + builtins.readFile ./ability-native-postgresql-trust.py
      + builtins.readFile ./ability-native-postgresql-isolation.py
      + builtins.readFile ./ability-native-postgresql-recovery.py
      + builtins.readFile ./ability-native-postgresql-faults.py
      + builtins.readFile ./ability-native-postgresql-capacity.py
      + builtins.readFile ./ability-native-postgresql-adoption.py;
  }
  // lib.optionalAttrs qualificationImage {
    qualification = {
      candidateRuntimeCompanions = fixture.qualificationCandidateRuntimeCompanions;
      extraClosures = fixture.qualificationExtraClosures;
      setupBody = fixture.qualificationSetupBody;
    };
  }
