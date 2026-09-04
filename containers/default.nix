##! containers/default.nix — Registered AOS scratch containers
##!
##! Registration is explicit rather than filesystem-discovered. The first
##! release intentionally exposes exactly one mutable base image, `aos`.
{
  lib,
  pkgs,
  goldenRoots,
  evidenceOverrides ? [],
  aosSystem,
}: let
  evaluator = import ../lib/containers {inherit lib pkgs;};
  definitions = {
    aos = import ./aos.nix {
      inherit lib pkgs goldenRoots evidenceOverrides aosSystem;
    };
  };
  registeredNames = builtins.attrNames definitions;
in
  assert registeredNames == ["aos"];
    lib.mapAttrs
    (name: definition:
      evaluator.evalContainer {
        inherit name;
        modules = [definition];
      })
    definitions
