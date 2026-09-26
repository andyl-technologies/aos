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
  mkAosCargoPackage,
  aosWorkspaceVendor,
}: let
  version = "0.1.0";
in
  mkAosCargoPackage {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      role = "public-package";
    };
    pname = "aos-release-signer";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-release-signer";
      entryPoint = "bin/aos-release-signer";
    };
    inherit version;
    cargoDeps = aosWorkspaceVendor;

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
