##! cargo-fuzz — drive libFuzzer targets from Cargo.
{
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
}: let
  version = "0.13.2";
  src = fetchurl {
    urls = ["https://github.com/rust-fuzz/cargo-fuzz/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-iOF5gF5P5MmQNyCgBO9pA7DyiyeiLnRmDNcvWGEva0Y=";
  };
in
  mkCargoPackage {
    pname = "cargo-fuzz";
    inherit version src;

    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "cargo-fuzz-${version}-vendor";
      hash = "sha256-7P3bii0Y0hf3z9RCPIH6uClFIw/CTtUSzbTbaZNQkYQ=";
    };
    cargoFlags = "--bin cargo-fuzz";

    # The integration tests create and build fuzz projects, which downloads
    # crates and requires a nightly compiler for sanitizer flags.
    doCheck = false;

    postInstall = ''
      "$out/bin/cargo-fuzz" --version

      mkdir -p "$out/share/licenses/cargo-fuzz"
      cp LICENSE-APACHE LICENSE-MIT "$out/share/licenses/cargo-fuzz/"
    '';

    meta = {
      description = "Command-line helper for fuzzing Rust code with libFuzzer";
      homepage = "https://github.com/rust-fuzz/cargo-fuzz";
      license = "MIT OR Apache-2.0";
      mainProgram = "cargo-fuzz";
    };
  }
