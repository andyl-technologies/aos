##! Exact package and dependency identities survive native envelope lowering.
{
  pkgs,
  lib,
}: let
  artifacts = import ../../lib/packages/artifacts.nix {};
  modules = import ../../lib/build/package-modules.nix {};
  packageFor = name: path: runtimeDeps: {
    pname = name;
    version = "1";
    outPath = path;
    system = "x86_64-linux";
    outputName = "out";
    module = "${path}-module";
    inherit runtimeDeps;
  };
  firstHelper = packageFor "helper" "/nix/store/00000000000000000000000000000001-helper" [];
  secondHelper = packageFor "helper" "/nix/store/00000000000000000000000000000002-helper" [];
  firstOwner = packageFor "first-owner" "/nix/store/00000000000000000000000000000003-first-owner" [firstHelper];
  secondOwner = packageFor "second-owner" "/nix/store/00000000000000000000000000000004-second-owner" [secondHelper];
  first = artifacts.envelope firstOwner;
  second = artifacts.envelope secondOwner;
  rejected = value: !(builtins.tryEval (builtins.deepSeq value true)).success;
  firstRecord = modules.recordFor firstOwner;
in
  assert first.runtimeDependencies.helper.path == builtins.toString firstHelper;
  assert second.runtimeDependencies.helper.path == builtins.toString secondHelper;
  assert first.runtimeDependencies.helper != second.runtimeDependencies.helper;
  assert first.module.source == builtins.toString firstOwner.module;
  assert firstRecord.artifacts.dependencies.helper == first.runtimeDependencies.helper;
  assert artifacts.valid first.package;
  assert rejected (artifacts.keyed [firstHelper secondHelper]);
  assert rejected (artifacts.unique [first.package (first.package // {version = "2";})]);
  assert rejected (modules.canonicalize [firstRecord (firstRecord // {version = "2";})]);
  assert rejected (modules.select [firstOwner] [(firstRecord // {artifacts = firstRecord.artifacts // {package = second.package;};})]); true
