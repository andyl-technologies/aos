##! sccache — Shared compilation cache
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
  pkg-config,
  openssl,
}: let
  version = "0.15.0";
  src = fetchurl {
    urls = ["https://github.com/mozilla/sccache/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-bmm4jy+ImC3GOJ9opmJLNVArWidgpqige9sQolDtmN8=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-Kkmq+fd0GTuEdE/QeTu/Qw8hyHdZ/zZGkjhZz5+mMyY=";
  };
in
  mkCargoPackage {
    pname = "sccache";
    inherit version src cargoDeps;
    buildDeps = [pkg-config];
    runtimeDeps = [openssl];
    doCheck = false;
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-sccache";
        tool = self;
        command = "sccache --version";
      };
    };
    meta = {
      description = "Compiler cache with local and remote storage support";
      homepage = "https://github.com/mozilla/sccache";
      license = "Apache-2.0";
      mainProgram = "sccache";
    };
  }
