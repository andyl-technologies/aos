##! Wasmtime — standalone WebAssembly and component-model runtime CLI.
{
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
}: let
  version = "49.0.1";

  # The release source archive carries the Git submodules that the GitHub
  # tag archive omits; several workspace members build from them.
  src = fetchurl {
    urls = ["https://github.com/bytecodealliance/wasmtime/releases/download/v${version}/wasmtime-v${version}-src.tar.gz"];
    hash = "sha256-FH7vKERjCCqFQTjilN9c1IrvRu49m2ta243kghJzd8M=";
  };
in
  mkCargoPackage {
    pname = "wasmtime";
    inherit version src;

    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "wasmtime-${version}-vendor";
      hash = "sha256-Iq8apl1MNynlKjFUakJ4J5zStoJPfex+qImh1ky2HWE=";
    };
    cargoFlags = "-p wasmtime-cli --bin wasmtime";

    # The upstream suite compiles guest programs for WASI targets that the AOS
    # Rust toolchain does not ship. The install smoke check below proves the
    # runtime loads and runs its argument parser.
    doCheck = false;

    postInstall = ''
      "$out/bin/wasmtime" --version

      mkdir -p "$out/share/licenses/wasmtime"
      cp LICENSE "$out/share/licenses/wasmtime/"
    '';

    meta = {
      description = "Fast and secure runtime for WebAssembly modules and components";
      homepage = "https://wasmtime.dev";
      license = "Apache-2.0 WITH LLVM-exception";
      mainProgram = "wasmtime";
    };
  }
