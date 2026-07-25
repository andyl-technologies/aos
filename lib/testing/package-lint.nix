# lib/testing/package-lint.nix — Evaluation-only package definition lint checks
#
# Exposes one cheap derivation per package derivation for `aos lint`. The checks
# run at Nix evaluation time: if a package definition is malformed, the lint
# derivation cannot instantiate. The builder only records a PASS marker.
{
  pkgs,
  lib,
}: let
  metadataExemptions = [
    "binutils"
    "bootstrapTools"
    "cc"
    "gcc"
    "gccUnwrapped"
    "getent"
    "glibc"
  ];

  packageNames = builtins.filter (name: lib.isDerivation pkgs.${name}) (builtins.attrNames pkgs);

  lintPackage = name: let
    pkg = pkgs.${name};
    hasPname = pkg ? pname && builtins.isString pkg.pname && pkg.pname != "";
    hasVersion = pkg ? version && builtins.isString pkg.version && pkg.version != "";
    metadataOk =
      builtins.elem name metadataExemptions
      || (hasPname && hasVersion);
    forced =
      lib.throwIfNot (pkg ? name && builtins.isString pkg.name && pkg.name != "")
      "package lint: pkgs.${name} has no derivation name"
      (lib.throwIfNot metadataOk
        "package lint: pkgs.${name} must define non-empty pname and version"
        true);
  in
    builtins.derivation {
      name = "aos-package-lint-${name}-0";
      system = lib.system;
      builder = "${pkgs.bash}/bin/bash";
      args = [
        "-c"
        ''
          : ${builtins.toString forced}
          echo "package lint: ${name}"
          echo "PASS" > "$out"
        ''
      ];
    };
in
  builtins.listToAttrs (
    builtins.map (name: {
      inherit name;
      value = lintPackage name;
    })
    packageNames
  )
