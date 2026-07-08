# Eval-only WIDE aggregate benchmark (RFC-0007 L2-P3b).
#
# `bench.wide` is a single derivation whose `packages` attribute lists every
# IFD-free package in the set, so instantiating it forces every package's
# .drv in ONE evaluation. Because a .drv path pins the content hash of its
# entire input-derivation closure, byte-comparing the root `bench-wide` .drv
# against C++ Nix transitively byte-checks every package .drv it references.
#
# The derivation is never built; `builder` deliberately points at a path that
# only exists to give the derivation a well-formed builder string.
{
  pkgs,
  lib,
}: let
  # Packages whose instantiation is IFD-poisoned: evaluating their drvPath
  # imports a *built* store output (probed with `nix-instantiate --option
  # max-jobs 0`, which turns any eval-time build into a hard failure):
  #   - bazel* vendor their dependency tree with a bazel-bootstrap build
  #     whose FOD output is imported back during evaluation;
  #   - envoy vendors its bazel dependency tree the same way;
  #   - gcc-libs imports headers out of a built gcc stage output;
  #   - linux imports the generated kernel config from a built derivation.
  excluded = [
    "bazel"
    "bazel-7"
    "bazel-8"
    "bazel-9"
    "bazel-bootstrap"
    "envoy"
    "gcc-libs"
    "linux"
  ];
  # Packages whose *evaluation* performs a large builtins.fetchGit (edk2
  # clones its whole submodule tree; firecracker fetches micro_http): the
  # fetch dominates wall clock and would drown eval timing, so the eval-only
  # benchmark variant excludes them. `wide` keeps them for parity coverage.
  evalTimeFetchers = [
    "edk2"
    "firecracker"
  ];
  isDerivation = value: builtins.isAttrs value && (value.type or "") == "derivation";
  namesExcluding = extraExcluded:
    builtins.filter (
      name: let
        attempt = builtins.tryEval (pkgs.${name});
      in
        !(builtins.elem name (excluded ++ extraExcluded))
        && attempt.success
        && isDerivation attempt.value
    ) (builtins.attrNames pkgs);
  mkWide = name: names:
    builtins.derivation {
      inherit name;
      system = pkgs.bash.system;
      builder = "${pkgs.bash}/bin/bash";
      args = ["-c" ":"];
      packages = map (pkgName: pkgs.${pkgName}) names;
    };
in {
  wide = mkWide "bench-wide" (namesExcluding []);
  # Timing-oriented variant: identical shape, minus eval-time git fetchers.
  wide-eval = mkWide "bench-wide-eval" (namesExcluding evalTimeFetchers);
}
