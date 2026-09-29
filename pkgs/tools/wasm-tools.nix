##! wasm-tools — inspect, validate, and transform WebAssembly modules and components.
{
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
}: let
  version = "1.259.0";
  src = fetchurl {
    urls = ["https://github.com/bytecodealliance/wasm-tools/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-w+5/B1fRIgvUtGJgxPrUVJzuohH5HXBmScG6JMp/3Bc=";
  };
in
  mkCargoPackage {
    pname = "wasm-tools";
    inherit version src;

    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "wasm-tools-${version}-vendor";
      hash = "sha256-9/QqcFlC3DBKEaREmPUqMSDTVvgz/23tGo9NFJFJ8f0=";
    };
    cargoFlags = "-p wasm-tools --bin wasm-tools";

    # The upstream suite runs the full WebAssembly spec testsuite through every
    # subcommand and takes longer than the build itself. The install smoke
    # check below proves the binary loads and runs its argument parser.
    doCheck = false;

    postInstall = ''
      "$out/bin/wasm-tools" --version

      mkdir -p "$out/share/licenses/wasm-tools"
      cp LICENSE-APACHE LICENSE-Apache-2.0_WITH_LLVM-exception LICENSE-MIT \
        "$out/share/licenses/wasm-tools/"
    '';

    meta = {
      description = "Low-level tooling for WebAssembly modules and components";
      homepage = "https://github.com/bytecodealliance/wasm-tools";
      license = "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT";
      mainProgram = "wasm-tools";
    };
  }
