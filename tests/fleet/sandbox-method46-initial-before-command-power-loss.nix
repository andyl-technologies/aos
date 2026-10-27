# Qualifies both installed initializers across a real before-command power cut.
{
  lib,
  pkgs,
  systems,
  ...
} @ args:
import ./sandbox-method46-initial-provision.nix (args // {initialCut = "before-command";})
