# Qualifies both installed initializers across a real after-response power cut.
{
  lib,
  pkgs,
  systems,
  ...
} @ args:
import ./sandbox-method46-initial-provision.nix (args // {initialCut = "after-response";})
