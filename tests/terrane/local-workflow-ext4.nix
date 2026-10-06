# Exercises T1 deployment through the packaged local CLI and registered SDK
# checkout on actual guest ext4. This workflow is not the TEST-6 backend suite.
{
  pkgs,
  lib,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  workflow =
    lib.replaceStrings ["@TERRANE@"] ["${pkgs.terrane}/bin/terrane"]
    (builtins.readFile ./local-workflow-ext4/workflow.sh);
in
  testing.mkVMTest {
    name = "terrane-local-workflow-ext4";
    memory = 1024;
    rootfsDeps = [
      pkgs.terrane
      pkgs.coreutils
      pkgs.util-linux
    ];
    testScript = workflow;
  }
