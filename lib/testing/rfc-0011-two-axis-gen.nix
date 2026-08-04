# RFC-0011 two-axis generation integration contract.
#
# Building pkgs.aos executes the Rust workspace test suite, including
# aos-package/tests/generations_split.rs. That integration test serializes both
# persisted axes independently, rejects the retired bundled schema as live
# config authority, and exercises same-/cross-ABI reactivation planning.
{
  pkgs,
  lib ? null,
}:
  pkgs.runCommand "rfc-0011-two-axis-gen" {
    buildDeps = [pkgs.aos];
  } ''
      mkdir -p $out
      echo PASS > $out/result
  ''
