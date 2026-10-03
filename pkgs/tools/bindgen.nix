##! Rust FFI binding generator using the source-built Clang library
{
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
  llvm,
  bash,
}: let
  version = "0.72.1";
  src = fetchurl {
    name = "bindgen-cli-${version}.tar.gz";
    urls = ["https://static.crates.io/crates/bindgen-cli/bindgen-cli-${version}.crate"];
    hash = "sha256-ikCMD8sgv3vUzq9L+ZDiI+NUOgS4TSOU8+3u4poOh+I=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-uwxqYpH+x3ZQJdBZCrw3TpK5vrcW3ruvmGLZXlDJtBM=";
  };
in
  mkCargoPackage {
    pname = "bindgen";
    inherit version src cargoDeps;

    runtimeDeps = [llvm bash];
    doCheck = true;

    postInstall = ''
      # Runtime discovery must resolve the same source-built libclang used
      # by the package, including in hermetic downstream build sandboxes.
      mkdir -p "$out/libexec"
      mv "$out/bin/bindgen" "$out/libexec/bindgen"
      cat > "$out/bin/bindgen" <<'WRAPPER'
      #!${bash}/bin/bash
      export LIBCLANG_PATH=${llvm}/lib
      exec ${builtins.placeholder "out"}/libexec/bindgen "$@"
      WRAPPER
      chmod 0755 "$out/bin/bindgen"
    '';

    meta = {
      description = "Generates Rust bindings from C and C++ headers";
      homepage = "https://rust-lang.github.io/rust-bindgen/";
      license = "BSD-3-Clause";
      mainProgram = "bindgen";
    };
  }
