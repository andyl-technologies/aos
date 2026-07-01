##! lib/formats/default.nix — Structured-config format helpers
##!
##! Analog of nixpkgs' `pkgs.formats`. Each entry is a factory that
##! receives `{ lib, pkgs, ... }` at call time and returns an attrset
##! with:
##!
##!     type      :: lib.types value  — option/submodule type for the format
##!     generate  :: name -> value -> derivation  — serialises a value
##!
##! Unlike nixpkgs, the AOS `lib` is `pkgs`-less at construction time
##! (see `lib/default.nix`), so every factory takes both `lib` and
##! `pkgs` at call time rather than being pre-bound. Call sites write:
##!
##!     fmt = lib.formats.json { inherit lib pkgs; };
##!     fmt.generate "example.json" { foo = 1; }
##!
##! Additional format-specific options may live on individual
##! factories (passed as extra arguments alongside `lib`/`pkgs`).
##!
##! This file is an aggregator only — the factories themselves live
##! in sibling files (`json.nix`, `yaml.nix`, `toml.nix`, ...).
##! Keeping the factories lazy — not pre-applied — avoids threading
##! `pkgs` through `lib/default.nix`, which is deliberately
##! `pkgs`-less.
{
  json = import ./json.nix;
  yaml = import ./yaml.nix;
  toml = import ./toml.nix;
}
