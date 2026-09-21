##! gopls — Official Go language server
{
  mkGoPackage,
  fetchGoModules,
  fetchurl,
  buildPackages,
  bash,
  go,
  stdenv,
}: let
  version = "0.23.0";
  src = fetchurl {
    urls = ["https://github.com/golang/tools/archive/refs/tags/gopls/v${version}.tar.gz"];
    hash = "sha256-G6QYdbkY23PGpAmtj1Urhfct/upD/7VBt5gyL/a0FSs=";
  };
  goModules = fetchGoModules {
    inherit src;
    sourceRoot = "tools-gopls-v${version}/gopls";
    hash = "sha256-jQtTmUSar1QgMxgrnfslfTFX37ypK36p27mzJdDHWHM=";
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
    runtimeDeps = [bash go];
    # Retain the target Go toolchain, while cross builds still reject native Go.
    disallowedReferences =
      if stdenv.isCross
      then [buildPackages.go]
      else [];
    postInstall = ''
      # Workspace loading runs Go commands even when no compilation is requested.
      mkdir -p "$out/libexec"
      mv "$out/bin/gopls" "$out/libexec/gopls"
      cat > "$out/bin/gopls" <<EOF
      #!${bash}/bin/bash
      export PATH="${go}/bin\''${PATH:+:}\$PATH"
      exec "$out/libexec/gopls" "\$@"
      EOF
      chmod +x "$out/bin/gopls"
    '';

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
