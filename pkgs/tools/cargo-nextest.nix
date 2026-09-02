##! cargo-nextest — process-per-test Rust test runner.
{
  stdenv,
  buildPackages,
  mkDerivation,
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
  patch,
  pkg-config,
  openssl,
}: let
  version = "0.9.143";
  src = fetchurl {
    urls = [
      "https://github.com/nextest-rs/nextest/archive/refs/tags/cargo-nextest-${version}.tar.gz"
    ];
    hash = "sha256-StXb6eJm/XMDw5QTxWEMTKA/PBtw+NWcgSZqRFLlk2E=";
  };
  unpatchedCargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-TMIaRjGV+qooWVMKL0dWfcC1EJcNlHnllHIIB5AgkqA=";
  };
  cargoDeps = mkDerivation {
    pname = "cargo-nextest-cargo-deps";
    inherit version;
    src = unpatchedCargoDeps;
    buildDeps = [patch];
    phases = [
      {
        name = "install";
        script = ''
          cp -R "$src"/. "$out"/
          chmod -R u+w "$out"
          patch -d "$out/usdt-impl" -p1 < ${./cargo-nextest-usdt-cross-arch.patch}
          sed -i \
            's|4d58f89e90a902be940ee23dd2e572ea88e6a4e4cf71fe61e53f6e70a239c3e6|aae4b570192f395d4edc90973d831774af8d9e68dda40e5e1f40983cbf8691c7|' \
            "$out/usdt-impl/.cargo-checksum.json"
          sed -i \
            's|3c64ecebf7996061243ce3809f99c2c60105abe25684ddc979440e603d4573c6|c01790a56d0c2918186e3050c9a1e463d049a8e2abbcda0cc68433b1e034db4e|' \
            "$out/usdt-impl/.cargo-checksum.json"
          sed -i \
            's|d223014ffc59d798cc5e53605942204056beb0ef2e75484b45942aae742fc233|577b977d8431056c0e0839ccd74328eb0a1dec6b6202317cd078e912df2e9d82|' \
            "$out/usdt-impl/.cargo-checksum.json"
        '';
      }
    ];
  };
in
  mkCargoPackage {
    pname = "cargo-nextest";
    inherit version src;

    inherit cargoDeps;
    cargoFlags = "-p cargo-nextest --bin cargo-nextest";
    cargoEnv =
      {USDT_TARGET = stdenv.hostPlatform.config;}
      // (
        if stdenv.hostPlatform.system == "aarch64-darwin"
        then {
          CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER = "${buildPackages.darwinCctoolsLinker}/bin/aarch64-apple-darwin-ld";
        }
        else {}
      );
    doCheck = false;
    buildDeps =
      [pkg-config openssl]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [buildPackages.darwinDtraceCompiler]
        else []
      );
    runtimeDeps = [openssl];
    OPENSSL_DIR = "${openssl}";
    OPENSSL_NO_VENDOR = "1";

    meta = {
      description = "Next-generation test runner for Rust projects";
      homepage = "https://nexte.st";
      license = "MIT OR Apache-2.0";
      mainProgram = "cargo-nextest";
    };
  }
