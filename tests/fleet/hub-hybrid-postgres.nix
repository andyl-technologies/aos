##! Qualifies the hybrid Hub with PostgreSQL on an independent fleet VM.
{
  lib,
  mkSystem,
  pkgs,
}:
import ./hub-hybrid.nix {
  inherit lib mkSystem pkgs;
  separateDatabase = true;
}
