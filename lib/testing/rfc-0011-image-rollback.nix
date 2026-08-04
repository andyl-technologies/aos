# RFC-0011 durable image rollback contract.
{
  pkgs,
  lib,
}: let
  sysroot = builtins.readFile ../../crates/aos-package/src/sysroot.rs;
  boot = builtins.readFile ../../modules/base/boot.nix;
in
  assert lib.hasInfix "bootctl" sysroot && lib.hasInfix "set-default" sysroot;
  assert lib.hasInfix "bootCountingTries" boot;
    pkgs.runCommand "rfc-0011-image-rollback" {} ''
      mkdir -p $out
      echo PASS > $out/result
    ''
