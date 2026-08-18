# lib/testing/package-lint.nix — Evaluation-only package definition lint checks
#
# Exposes one cheap derivation per package derivation for `aos lint`. The checks
# run at Nix evaluation time: if a package definition is malformed, the lint
# derivation cannot instantiate. The builder only records a PASS marker.
{
  pkgs,
  lib,
}: let
  # Bootstrap aliases predate pname/version passthrough but still carry the
  # distribution metadata consumed by registry publication.
  identityExemptions = [
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
    hasDescription = pkg.meta ? description && builtins.isString pkg.meta.description && pkg.meta.description != "";
    hasLicense =
      pkg.meta ? license
      && (
        (builtins.isString pkg.meta.license && pkg.meta.license != "")
        || (
          builtins.isList pkg.meta.license
          && pkg.meta.license != []
          && builtins.all (license: builtins.isString license && license != "") pkg.meta.license
        )
      );
    hasMaintainers =
      pkg.meta
      ? maintainers
      && builtins.isList pkg.meta.maintainers
      && pkg.meta.maintainers != []
      && builtins.all (maintainer: builtins.isString maintainer && maintainer != "") pkg.meta.maintainers;
    forced =
      lib.throwIfNot (pkg ? name && builtins.isString pkg.name && pkg.name != "")
      "package lint: pkgs.${name} has no derivation name"
      (lib.throwIfNot (builtins.elem name identityExemptions || (hasPname && hasVersion))
        "package lint: pkgs.${name} must define non-empty pname and version"
        (lib.throwIfNot hasDescription
          "package lint: pkgs.${name} must define a non-empty meta.description"
          (lib.throwIfNot hasLicense
            "package lint: pkgs.${name} must define a non-empty meta.license string or list"
            (lib.throwIfNot hasMaintainers
              "package lint: pkgs.${name} must define non-empty string meta.maintainers"
              true))));
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
