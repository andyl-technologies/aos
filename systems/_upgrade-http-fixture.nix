{
  lib,
  pkgs,
  generation,
}: let
  isGen2 = generation == 2;
in {
  assertions = [
    {
      assertion = generation == 1 || generation == 2;
      message = "upgrade HTTP fixture generation must be 1 or 2";
    }
  ];

  # These packages exist only to exercise image-generation reconciliation.
  aos.image.allowTestArtifacts = true;
  aos.image.testArtifactRoots = [
    pkgs.test-http-server
    pkgs.upgrade-transition-fixture
  ];

  aos.abilities.environment = {
    authority = "test";
    key = "upgrade-http-fixture";
    stage = "host";
  };

  environment.systemPackages = [
    pkgs.test-http-server
    pkgs.upgrade-transition-fixture
  ];

  test-http-server = {
    enable = true;
    port = 8000;
  };
  upgrade-transition-fixture = {
    enable = true;
    generation =
      if isGen2
      then "updated"
      else "initial";
  };
}
