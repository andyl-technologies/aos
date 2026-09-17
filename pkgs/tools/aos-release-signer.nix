##! aos-release-signer — file-backed release signing adapter
##!
##! Builds the `aos-release-signer` binary from the shared `crates/` cargo
##! workspace. `aos release` commands invoke a deployment-configured signer
##! executable with the `sign-exchange-v1` operation; this adapter serves that
##! protocol from operator-owned key files for registries without an HSM, such
##! as `andyl/testing`.
##!
##! The binary depends only on pure-Rust cryptography, so the derivation needs
##! no native libraries. Authenticode and kernel-module transforms shell out to
##! `sbsign` and `openssl` at paths named in the operator configuration; the
##! package deliberately does not bake either tool in, because the finalizer
##! independently pins its own verification copies from the image assembly.
{
  lib,
  mkCargoPackage,
  fetchCargoVendor,
}: let
  version = "0.1.0";
  repoRoot = ../..;
  repoRootString = toString repoRoot;
  src = builtins.path {
    path = repoRoot;
    name = "aos-release-signer-workspace-src";
    filter = path: _type: let
      pathString = toString path;
      base = baseNameOf path;
    in
      base
      != "target"
      && base != ".git"
      && (
        pathString
        == repoRootString
        || lib.hasPrefix "${repoRootString}/crates" pathString
      );
  };
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-yf/Gu30exf9weCOK6RRrjusN+bXZ6rj1r+tZbEJMy4g=";
  };
in
  mkCargoPackage {
    pname = "aos-release-signer";
    inherit version src cargoDeps;

    cargoFlags = "-p aos-release-signer";
    cargoRoot = "crates";

    buildDeps = [];
    runtimeDeps = [];

    # The workspace test suite, including this crate's unit tests, runs in the
    # `aos` package's check phase; this derivation only installs the binary.
    doCheck = false;

    meta = {
      description = "aos-release-signer — file-backed release signing adapter";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
    };
  }
