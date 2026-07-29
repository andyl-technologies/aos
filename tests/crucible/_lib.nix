# tests/crucible/_lib.nix — shared predicates for the Crucible gate checks.
#
# Nearly every `phase*.nix` check asserts that a set of needles is present in
# (or absent from) a source file it reads with `builtins.readFile`. Before this
# module each check carried its own copy of the three helpers below — `hasInfix`
# was duplicated into 423 files, `failuresFor` into 384 and `forbiddenFor` into
# 210 — so a fix to any of them had to be applied hundreds of times.
#
# `hasInfix` now lives in `lib/strings.nix` (`lib.hasInfix`) because it is a
# general string predicate with no test-harness specificity; it is re-exported
# here so a check needs only one import.
#
# Usage from a check:
#
#   {pkgs, lib, ...}: let
#     inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;
#     ...
#     failures =
#       failuresFor "crates/crucible/src/lib.rs" source [
#         {
#           label = "DAG store put";
#           needle = "fn put(&self, bytes: &[u8])";
#         }
#       ];
#   in
#     if failures != [] then throw "..." else <derivation>
{lib}: rec {
  ## Whether `needle` occurs anywhere in `haystack`.
  ##
  ## Re-exported from `lib.hasInfix` so checks import one module.
  inherit (lib) hasInfix;

  ## Requirements whose needle is MISSING from `content`, as failure strings.
  ##
  ## `fileLabel` names the file in the message; `requirements` is a list of
  ## `{label, needle}` attrsets. Returns `[]` when every needle is present.
  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  ## Requirements whose needle is PRESENT in `content`, as failure strings.
  ##
  ## The inverse of [`failuresFor`], for asserting that a retired or forbidden
  ## construct has not been reintroduced. Returns `[]` when every needle is
  ## absent.
  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;
}
