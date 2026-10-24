# A real expired mount namespace must require repair without blocking startup.
{
  lib,
  mkSystem,
  pkgs,
  ...
} @ args:
import ./sandbox-storage-rpc.nix (args // {seedInPrivateMountNamespace = true;})
