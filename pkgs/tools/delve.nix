##! delve — Debugger for the Go programming language
{
  mkGoPackage,
  fetchGoModules,
  fetchurl,
}: let
  version = "1.26.3";
  src = fetchurl {
    urls = ["https://github.com/go-delve/delve/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-xavQIDPXYBpBu2dIWJwL5CCA3E+Rx+SPyMu39VjMh0g=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-qIUppugEqvc/VftMQL/Jz9HdGhxEkrGFHH8s2gxju8U=";
  };
in
  mkGoPackage {
    pname = "delve";
    inherit version src goModules;
    goPackage = "./cmd/dlv";
    goOutput = "dlv";
    cgoEnabled = true;
    doCheck = false;
    hardeningDisable = ["fortify"];
    postInstall = ''ln -s dlv "$out/bin/dlv-dap"'';
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-delve";
        tool = self;
        command = "dlv version";
      };
    };
    meta = {
      description = "Debugger for the Go programming language";
      homepage = "https://github.com/go-delve/delve";
      license = "MIT";
      mainProgram = "dlv";
    };
  }
