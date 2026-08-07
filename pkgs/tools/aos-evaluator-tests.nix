##! aos-evaluator-tests — hermetic native configuration-evaluator component gate
{
  lib,
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
  src = import ./aos/_workspace-source.nix {
    inherit lib;
    evaluatorFixtures = true;
  };
  componentPackages = [
    "aos-nix"
    "aos-nix-compat"
    "aos-nix-dialect"
    "aos-nix-syntax"
    "ratchet-cache"
    "ratchet-core"
    "ratchet-dialect"
    "ratchet-jit"
    "ratchet-oracle"
    "ratchet-runtime-ffi"
    "ratchet-value"
  ];
  componentFlags = builtins.concatStringsSep " " (
    map (package: "-p ${package}") componentPackages
  );
in
  mkCargoPackage {
    pname = "aos-evaluator-tests";
    inherit version src;

    # Build and test every evaluator component together so Cargo's feature
    # unification gives all ratchet crates the same Candidate-C value ABI used
    # by the production on-host evaluator. C++ Nix differential parity is a
    # separate hermetic gate (`checks.config-parity-p2`); keeping the optional
    # developer oracle unset here prevents component tests from reaching for a
    # mutable host Nix store.
    cargoFlags = "${componentFlags} --features aos-nix/candidate_c_value";
    cargoTestFlags = "${componentFlags} --features aos-nix/candidate_c_value";
    cargoDeps = fetchCargoVendor {
      inherit src;
      # Share the CLI package's lockfile-vendor FOD exactly; the vendor output
      # records its declared name, so changing only the name also changes the
      # fixed-output hash.
      name = "aos-vendor-${version}";
      sourceRoot = "source/crates";
      hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
    };

    buildDeps = [perl pkg-config openssl cmake libssh2];
    runtimeDeps = [openssl libssh2 zlib zstd];
    preBuild = ''
      export OPENSSL_DIR="${openssl}"
      export OPENSSL_LIB_DIR="${openssl}/lib"
      export OPENSSL_INCLUDE_DIR="${openssl}/include"
      export OPENSSL_NO_VENDOR=1
      export OPENSSL_STATIC=0
      cd crates
    '';

    doCheck = true;
    buildType = "debug";
    checkType = "debug";
    installBins = false;
    postInstall = ''
      mkdir -p "$out"
      echo PASS > "$out/result"
    '';

    meta = {
      description = "Hermetic full component test gate for the AOS native Nix evaluator";
      license = "Apache-2.0";
    };
  }
