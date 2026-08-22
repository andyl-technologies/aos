##! cargo-hakari — workspace-hack generator and validator.
{
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
}: let
  version = "0.9.38";
  src = fetchurl {
    urls = [
      "https://github.com/guppy-rs/guppy/archive/refs/tags/cargo-hakari-${version}.tar.gz"
    ];
    hash = "sha256-vPLzO/vBEplbocL/PhxbEyIEuegr3KTxHL2XOkVWrGQ=";
  };
in
  mkCargoPackage {
    pname = "cargo-hakari";
    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      hash = "sha256-+dnMXEeDrHptMrSGocLnLXsR1/eB16IYSGFBRTzsl4Y=";
    };
    cargoFlags = "-p cargo-hakari --bin cargo-hakari";
    doCheck = false;

    meta = {
      description = "Manage workspace-hack crates for faster Cargo builds";
      homepage = "https://docs.rs/cargo-hakari";
      license = "MIT OR Apache-2.0";
      mainProgram = "cargo-hakari";
    };
  }
