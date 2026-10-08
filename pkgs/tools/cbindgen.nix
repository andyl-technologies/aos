##! C and C++ public-header generator for Rust libraries
{
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
  buildPackages,
  rust,
}: let
  version = "0.29.4";
  src = fetchurl {
    name = "cbindgen-${version}.tar.gz";
    urls = ["https://static.crates.io/crates/cbindgen/cbindgen-${version}.crate"];
    hash = "sha256-LstTSEycFnumdAJrZW2KJ9dleljmBmqpAr+xpKoAriA=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-8kmbAdECssqt984x6C/whXmN+DI+XGkwNhyhvtA1aNs=";
  };
in
  mkCargoPackage {
    pname = "cbindgen";
    inherit version src cargoDeps;
    buildDeps = [buildPackages.cython];
    runtimeDeps = [rust];
    doCheck = true;

    meta = {
      description = "Generates C and C++ public headers from Rust libraries";
      homepage = "https://github.com/mozilla/cbindgen";
      license = "MPL-2.0";
      mainProgram = "cbindgen";
    };
  }
