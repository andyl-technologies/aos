##! Package artifact resolution remains scoped to authenticated provenance.
{
  pkgs,
  lib,
}: let
  packageOrigins = pkgs.ociTools.checkedPackageOrigin;
  localHelper = {
    _type = "aos-package-output-selector";
    package = "helper";
    output = "out";
  };
  packageFor = {
    name,
    path,
    runtimeDeps ? [],
    selectors ? [],
  }: {
    pname = name;
    version = "1";
    outPath = path;
    outputName = "out";
    abilities = {};
    module = "${path}-module";
    inherit runtimeDeps;
    contract = {
      document = "${path}-contract";
      value = {
        artifacts = selectors;
        package = {
          inherit name;
          version = "1";
        };
        package_module = {
          artifact = "module";
          path = "module.nix";
        };
      };
      inherit selectors;
    };
  };
  firstArtifact = "/nix/store/first-origin-helper";
  secondArtifact = "/nix/store/second-origin-helper";
  selector = builtins.removeAttrs localHelper ["_type"];
  firstHelper = packageFor {
    name = "helper";
    path = firstArtifact;
  };
  secondHelper = packageFor {
    name = "helper";
    path = secondArtifact;
  };
  ownerFor = name: path: helper:
    packageFor {
      inherit name path;
      runtimeDeps = [helper];
      selectors = [selector];
    };
  firstOwner = ownerFor "first-package" "/nix/store/first-package-payload" firstHelper;
  firstProjection = lib.abilities.authenticatedPackageProjectionFor firstOwner;
  secondProjection = lib.abilities.authenticatedPackageProjectionFor (
    ownerFor "second-package" "/nix/store/second-package-payload" secondHelper
  );
  first = packageOrigins.resolve firstProjection localHelper;
  second = packageOrigins.resolve secondProjection localHelper;
  rejects = projection:
    !(builtins.tryEval (builtins.deepSeq (
        lib.abilities.checkedAuthenticatedPackageProjection projection
      )
      true)).success;
  rejectsConstructor = package:
    !(builtins.tryEval (builtins.deepSeq (
        lib.abilities.authenticatedPackageProjectionFor package
      )
      true)).success;
  withOriginIdentity = projection: identity:
    projection
    // {
      origin = projection.origin // {package = projection.origin.package // identity;};
    };
in
  assert builtins.toString first == firstArtifact;
  assert builtins.toString second == secondArtifact;
  assert builtins.toString first != builtins.toString second;
  assert rejects (withOriginIdentity firstProjection {name = "other-package";});
  assert rejects (withOriginIdentity firstProjection {version = "2";});
  assert rejects (withOriginIdentity firstProjection {document = "/nix/store/other-contract";});
  assert rejects (firstProjection // {payload = firstProjection.payload // {pname = "other-package";};});
  assert rejects (firstProjection // {payload = firstProjection.payload // {version = "2";};});
  assert rejects (firstProjection // {contract = firstProjection.contract // {selectors = [];};});
  assert rejectsConstructor (firstOwner // {pname = "other-package";}); true
