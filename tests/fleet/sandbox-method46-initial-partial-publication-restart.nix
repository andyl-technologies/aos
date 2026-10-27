# Recovers real short checkpoint writes by both installed initializers.
{
  lib,
  pkgs,
  systems,
  ...
} @ args:
import ./sandbox-method46-initial-provision.nix (args // {initialCut = "partial-publication";})
