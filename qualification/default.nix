##! Shared release contract, evaluated without builds or deployment credentials.
{packageNames}: let
  contract = import ./contracts/server-v1.nix;
in
  contract
  // {
    schema_version = "aos.release.qualification-contract/v1";
    targets = import ./targets.nix;
    package_rules = import ./packages.nix {inherit packageNames;};
    requirements = import ./requirements.nix;
  }
