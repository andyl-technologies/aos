# RFC-0011 retained-input and prior-base-lib GC-root contract.
{
  pkgs,
  lib,
}: let
  store = builtins.readFile ../../crates/aos-package/src/store.rs;
  activation = builtins.readFile ../../crates/aos-package/src/config_eval/activation.rs;
in
  assert lib.hasInfix "reconcile_baselib_gc_roots" store;
  assert lib.hasInfix "create_config_gc_roots" activation;
  assert lib.hasInfix "instance_facts/store_path" activation;
    pkgs.runCommand "rfc-0011-cfgsrc-gc" {} ''
      mkdir -p $out
      echo PASS > $out/result
    ''
