##! Reads Bazel-owned release identities without evaluating a build driver.
{
  lib,
  metadataFile ? ../../../tools/bazel/metadata/crucible-release-packages.json,
}: let
  root = ../../..;
  metadata = builtins.fromJSON (builtins.readFile metadataFile);
  packages = import ./_packages.nix;
  names = builtins.attrNames metadata.packages;
  declarationPaths = builtins.attrNames metadata.declaration_sha256;
  validPath = path: let
    parts = lib.splitString "/" path;
  in
    builtins.isString path
    && builtins.match "[A-Za-z0-9_./-]+" path != null
    && builtins.all (part: part != "" && part != "." && part != "..") parts;
  packageBuildFiles = map (name: "${metadata.packages.${name}.directory}/BUILD.bazel") names;
  requiredDeclarations =
    packageBuildFiles
    ++ [
      "crates/BUILD.bazel"
      "pkgs/tools/crucible/_packages.nix"
      "tools/bazel/rules/rust_package.bzl"
      "tools/bazel/rules/source_package.bzl"
      "tools/bazel/metadata/export_release_packages.py"
    ];
  validDeclarations =
    builtins.sort builtins.lessThan requiredDeclarations
    == declarationPaths
    && builtins.all validPath declarationPaths;
  staleDeclarations =
    builtins.filter
    (path: builtins.hashFile "sha256" (root + "/${path}") != metadata.declaration_sha256.${path})
    declarationPaths;
in
  assert metadata.schema_version == 1;
  assert names == builtins.sort builtins.lessThan packages;
  assert builtins.all (name: lib.hasPrefix "crates/" metadata.packages.${name}.directory) names;
  assert validDeclarations;
    if staleDeclarations != []
    then throw "stale Bazel Crucible release metadata; regenerate tools/bazel/metadata/crucible-release-packages.json: ${builtins.concatStringsSep ", " staleDeclarations}"
    else metadata.packages
