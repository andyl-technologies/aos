##! Package artifact resolution remains scoped to authenticated provenance.
{lib}: let
  common = import ../../pkgs/containers/_aos-oci-backend/oci/common.nix {
    inherit lib;
  };
  packageOrigins = import ../../pkgs/containers/_aos-oci-backend/oci/checked-package-origin.nix {
    inherit common;
  };
  localHelper = {
    _type = "aos-package-output-selector";
    package = "helper";
    output = "out";
  };
  projectionFor = name: artifact: {
    _type = "aos-checked-package-projection";
    payload = {outPath = "/nix/store/${name}-payload";};
    contract = {};
    origin = {
      _type = "aos-authenticated-package-origin";
      package = {
        inherit name;
        version = "1";
        document = "/nix/store/${name}-contract";
      };
      packageArtifactFor = selector:
        if selector == localHelper
        then artifact
        else throw "authenticated origin received an unretained selector";
    };
  };
  firstArtifact = "/nix/store/first-origin-helper";
  secondArtifact = "/nix/store/second-origin-helper";
  first = packageOrigins.resolve (projectionFor "first-package" firstArtifact) localHelper;
  second = packageOrigins.resolve (projectionFor "second-package" secondArtifact) localHelper;
in
  assert first == firstArtifact;
  assert second == secondArtifact;
  assert first != second;
    true
