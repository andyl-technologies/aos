##! grype — Vulnerability scanner for images, filesystems, and SBOMs
{
  mkGoPackage,
  fetchurl,
  fetchGoModules,
}: let
  version = "0.119.0";
  src = fetchurl {
    urls = ["https://github.com/anchore/grype/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-vpyQSTjZcC5DLjwk6iKIkTZ4rzOWhAWYDSBh1hWSSLI=";
  };
  goModules = fetchGoModules {
    inherit src;
    name = "grype-go-modules-${version}";
    hash = "sha256-R+6H4ZgEtEsHOihMUwSZ9b/5RLzVvZsK7EewQ3QwuXs=";
  };
  databaseArchive = import ./_grype-database.nix {inherit fetchurl;};
in
  mkGoPackage {
    pname = "grype";
    inherit version src goModules;
    goPackage = "./cmd/grype";
    goOutput = "build/grype";
    cgoEnabled = false;
    ldflags = "-s -w -X main.version=${version} -X main.gitDescription=v${version}";
    postConfigure = ''
      export GOTOOLCHAIN=local
      export GOFLAGS="$GOFLAGS -p=$NIX_BUILD_CORES"
    '';

    # Upstream integration tests download databases and build container images.
    # Scanner qualification supplies a real, authenticated database explicitly.
    doCheck = false;
    passthru = {inherit databaseArchive;};

    checks = {
      testing,
      self,
      pkgs,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-grype";
        tool = self;
        command = "grype version && grype db import --help >/dev/null";
      };
      scan = import ./_grype-scan-check.nix {
        inherit pkgs databaseArchive;
        grype = self;
      };
    };

    meta = {
      description = "Vulnerability scanner for container images, filesystems, and SBOMs";
      homepage = "https://github.com/anchore/grype";
      license = "Apache-2.0";
      mainProgram = "grype";
    };
  }
