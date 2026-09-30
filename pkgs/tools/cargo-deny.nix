##! cargo-deny — lint a Cargo dependency graph for advisories, licenses, bans, and sources.
{
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
}: let
  version = "0.20.2";
  src = fetchurl {
    urls = ["https://github.com/EmbarkStudios/cargo-deny/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-MfwdM/ro1bQmTbjtXGwHDCfNL4acxtKYOsA1SMWoHI4=";
  };
in
  mkCargoPackage {
    pname = "cargo-deny";
    inherit version src;

    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "cargo-deny-${version}-vendor";
      hash = "sha256-Zb6vQCnhhhL9Ducn9eh5P8Gfopl0lQPTXWW8Q0Y5xBQ=";
    };
    cargoFlags = "--bin cargo-deny";

    # The advisory and source tests fetch the RustSec database and Git
    # repositories, which the build sandbox forbids.
    doCheck = false;

    postInstall = ''
      "$out/bin/cargo-deny" --version

      mkdir -p "$out/share/licenses/cargo-deny"
      cp LICENSE-APACHE LICENSE-MIT "$out/share/licenses/cargo-deny/"
    '';

    meta = {
      description = "Cargo plugin for linting dependency advisories, licenses, bans, and sources";
      homepage = "https://embarkstudios.github.io/cargo-deny/";
      license = "MIT OR Apache-2.0";
      mainProgram = "cargo-deny";
    };
  }
