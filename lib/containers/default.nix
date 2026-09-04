##! lib/containers/default.nix — Separate scratch-container evaluator
##!
##! Container definitions use the ordinary AOS module engine but a distinct,
##! closed option schema. Evaluating a container never imports the boot, kernel,
##! initrd, systemd-service, or disk-image module trees.
{
  lib,
  pkgs,
}: let
  schema = import ./schema.nix;

  forceAssertions = name: evaluated: let
    failures = builtins.filter (assertion: !assertion.assertion) evaluated.config.assertions;
    checked =
      if failures == []
      then evaluated.config
      else
        throw ''
          Container '${name}' failed evaluation:
          ${lib.concatStringsSep "\n" (map (failure: "  - ${failure.message}") failures)}
        '';
  in
    builtins.seq checked checked;
in {
  evalContainer = {
    name,
    modules,
  }: let
    evaluated = lib.evalModules {
      modules = [schema] ++ modules;
      inherit lib pkgs;
      specialArgs = {inherit name;};
    };
  in
    forceAssertions name evaluated;
}
