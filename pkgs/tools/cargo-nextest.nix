##! cargo-nextest — process-per-test Rust test runner.
{
  mkCargoPackage,
  fetchurl,
  fetchCargoDeps,
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
in
  mkCargoPackage {
    pname = "cargo-nextest";
    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      hash = "sha256-TMIaRjGV+qooWVMKL0dWfcC1EJcNlHnllHIIB5AgkqA=";
    };
    cargoFlags = "-p cargo-nextest --bin cargo-nextest";
    doCheck = false;
    buildDeps = [pkg-config openssl];
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
