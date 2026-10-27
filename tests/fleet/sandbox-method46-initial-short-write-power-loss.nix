# Cuts QEMU and swtpm after each installed producer's actual short write.
{
  lib,
  pkgs,
  systems,
  ...
} @ args:
import ./sandbox-method46-initial-provision.nix (args // {initialCut = "short-write";})
