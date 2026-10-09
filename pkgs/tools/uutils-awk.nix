##! uutils awk — experimental Rust AWK interpreter.
{
  mkCargoPackage,
  fetchCargoVendor,
  fetchurl,
  llvm,
  glibc,
  linux-headers,
  stdenv,
  buildPackages,
}: let
  version = "0.1.0";
  revision = "5e3a13c917fb470893c6fed71dc9413e30e3b146";
  buildLlvm =
    if stdenv.isCross
    then buildPackages.llvm
    else llvm;
  src = fetchurl {
    urls = ["https://github.com/uutils/awk/archive/${revision}.tar.gz"];
    hash = "sha256-1knKBhGbindexCiS/LSelH1eb0ex60SMUUYmB/lD2Yo=";
  };
  # The lockfile contains a Git dependency; lockfile-driven vendoring keeps it offline.
  cargoDeps = fetchCargoVendor {
    inherit src;
    hash = "sha256-Zt3kc2GMuCZwXb4cWYtwAmMMshRyeabAImePFngjczs=";
  };
in
  mkCargoPackage {
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
      target = [];
      role = "public-package";
    };
    pname = "uutils-awk";
    inherit version src cargoDeps;

    cargoFlags = "--bin awk";
    buildDeps = [buildLlvm];
    doCheck = false;

    # Upstream's release-only linear-register assertion currently fails to
    # compile; debug assertions select its runtime assertion instead.
    CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS = "true";
    LIBCLANG_PATH = "${buildLlvm}/lib";
    preBuild = ''
      gcc_include=$("$CC" -print-file-name=include)
      export BINDGEN_EXTRA_CLANG_ARGS="-isystem $gcc_include -isystem ${glibc.dev}/include -isystem ${linux-headers}/include"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uutils-awk";
        tool = self;
        command = "printf 'one two\\n' | ${self}/bin/awk '{print $2}'";
        expectedOutput = "two";
      };
    };

    meta = {
      description = "Experimental Rust AWK interpreter";
      homepage = "https://github.com/uutils/awk";
      license = "MIT OR Apache-2.0";
      mainProgram = "awk";
    };
  }
