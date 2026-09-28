##! syft — Artifact package cataloger and SBOM generator
{
  mkGoPackage,
  fetchurl,
  fetchGoModules,
}: let
  version = "1.52.0";
  src = fetchurl {
    urls = ["https://github.com/anchore/syft/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-i5maG4vQixJRIXbN7F0GPbnP4gnGXMXenE6yq3vcezw=";
  };
  goModules = fetchGoModules {
    inherit src;
    name = "syft-go-modules-${version}";
    hash = "sha256-g0N1BowtAUhuxpo2q+3zUzNSFPzRk85Qai591HwBSTA=";
  };
in
  mkGoPackage {
    pname = "syft";
    inherit version src goModules;
    goPackage = "./cmd/syft";
    goOutput = "build/syft";
    cgoEnabled = false;
    ldflags = "-s -w -X main.version=${version} -X main.gitDescription=v${version}";
    postConfigure = ''
      export GOTOOLCHAIN=local
      export GOFLAGS="$GOFLAGS -p=$NIX_BUILD_CORES"
    '';

    # Container integration tests require an external daemon and network.
    doCheck = false;

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-syft";
        tool = self;
        command = "syft version && syft scan --help >/dev/null";
      };
    };

    meta = {
      description = "Package cataloger and SBOM generator for images and filesystems";
      homepage = "https://github.com/anchore/syft";
      license = "Apache-2.0";
      mainProgram = "syft";
    };
  }
