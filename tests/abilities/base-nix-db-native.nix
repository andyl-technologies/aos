##! Checks base Nix database ownership through native provider requests.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "base-nix-db";
    module = ../../modules/base/nix-db.nix;
    packages = [pkgs.systemd pkgs.aos-nix-store-provider];
  };
  config = evaluated.config;
  requests = config.aos.abilities.requests;
in
  assert builtins.attrNames requests
  == [
    "system:aos-nix-db-dependencies"
    "system:aos-nix-db-environment"
    "system:aos-nix-db-lifecycle"
    "system:filesystem-readiness"
    "system:nix-store-database"
  ];
  assert requests."system:nix-store-database".parameters
  == {
    scope = "local";
    registration = {
      path = "/aos-registration";
      required = false;
    };
    prerequisites = [];
  };
  assert requests."system:aos-nix-db-dependencies".parameters.requires
  == [
    {
      _type = "aos-request-output-reference";
      request = "system:filesystem-readiness";
      output = "readiness-resource";
    }
    {
      _type = "aos-request-output-reference";
      request = "system:nix-store-database";
      output = "readiness-resource";
    }
  ];
  assert config.systemd.services == {}; true
