##! LLVM native compiler with ARM32 compatibility code generation for ARM64 fixtures
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
  python3,
  zlib,
  zstd,
  libxml2,
  libedit,
  bootstrapTools,
  stdenv,
  buildPackages,
}: let
  compiler = import ../toolchain/llvm/llvm-22.nix {
    inherit lib mkDerivation fetchurl gnumake cmake ninja python3 zlib zstd libxml2 libedit bootstrapTools stdenv buildPackages;
    # arm64's ordinary COMPAT vDSO contains ARM32 code. Keeping that kernel
    # feature requires the ARM backend in addition to the normal AOS targets.
    additionalTargets = ["ARM"];
  };
in
  compiler.overrideAttrs (_: {
    pname = "llvm-gem5";
    meta.description = "Source-built LLVM with the normal AOS code generators plus ARM32 for arm64 compatibility vDSO compilation";
  })
