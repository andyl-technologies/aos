##! gopls — Official Go language server
{
  mkGoPackage,
  fetchGoModules,
  fetchurl,
}: let
  version = "0.22.0";
  src = fetchurl {
    urls = ["https://github.com/golang/tools/archive/refs/tags/gopls/v${version}.tar.gz"];
    hash = "sha256-JJ3AxLnz6FP2p/tvNSjbL0h5PnxUMj87Mqo49kMvCIo=";
  };
  goModules = fetchGoModules {
    inherit src;
    sourceRoot = "tools-gopls-v${version}/gopls";
    hash = "sha256-XhcQW1G05gmD9UWmHEJ8bLNnsJ8cARw3Wm6F2z9H3L0=";
  };
in
  mkGoPackage {
    pname = "gopls";
    inherit version src goModules;
    postPatch = ''cd gopls'';
    goPackage = ".";
    goOutput = "gopls";
    ldflags = "-s -w -X main.version=v${version}";
    doCheck = false;
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-gopls";
        tool = self;
        command = "gopls version";
      };
    };
    meta = {
      description = "Official language server for Go";
      homepage = "https://go.dev/gopls/";
      license = "BSD-3-Clause";
      mainProgram = "gopls";
    };
  }
