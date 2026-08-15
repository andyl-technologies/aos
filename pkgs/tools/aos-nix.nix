##! aos-nix — native evaluator parity-check driver
{
  mkCargoPackage,
  fetchCargoVendor,
  cmake,
  libssh2,
  openssl,
  perl,
  pkg-config,
  zlib,
  zstd,
}: let
  version = "0.1.0";
  src = builtins.path {
    path = ../../crates;
    name = "aos-crates-src";
    filter = path: type: let
      base = baseNameOf path;
    in
      base != "target" && base != ".git";
  };
in
  mkCargoPackage {
    pname = "aos-nix";
    inherit version src;
    cargoFlags = "-p aos-nix --bin aos-nix-eval --features candidate_c_value";
    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "aos-nix-vendor-${version}";
      hash = "sha256-RvgGglI1TqzOmlqgt3qG+GBHEGd3ZHT9M4CueO0Q/W4=";
    };
    buildDeps = [perl pkg-config openssl cmake libssh2];
    runtimeDeps = [openssl libssh2 zlib zstd];
    preBuild = ''
      export OPENSSL_DIR="${openssl}"
      export OPENSSL_LIB_DIR="${openssl}/lib"
      export OPENSSL_INCLUDE_DIR="${openssl}/include"
      export OPENSSL_NO_VENDOR=1
      export OPENSSL_STATIC=0
    '';
    doCheck = true;
    # The parity derivation below exercises the public driver end to end. Keep
    # the package-level check focused on the persistent import cache primitive
    # so feature-gated fallback-policy tests do not become package build gates.
    cargoTestFlags = "-p aos-nix --features candidate_c_value native::tests::warm_import";
  }
