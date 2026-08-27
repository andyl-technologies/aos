##! OpenJDK 19 — bootstrap chain intermediate (built with openjdk-18)
{
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  gnumake,
  autoconf,
  bash,
  which,
  zip,
  unzip,
  gawk,
  coreutils,
  zlib,
  alsa-lib,
  binutils,
  cups,
  file,
  fontconfig,
  freetype,
  xorg-stubs,
  bootstrapTools,
  openjdk-18,
}: let
  mkOpenJDKBootstrap = import ./_openjdk-bootstrap.nix {
    inherit
      fetchurl
      mkDerivation
      stdenv
      buildPackages
      gnumake
      autoconf
      bash
      which
      zip
      unzip
      gawk
      coreutils
      zlib
      alsa-lib
      binutils
      cups
      file
      fontconfig
      freetype
      xorg-stubs
      bootstrapTools
      ;
  };
in
  mkOpenJDKBootstrap {
    major = 19;
    version = "19.0.2";
    build = "7";
    srcHash = "sha256-WQPv1SfdCOnCNciCLj1WmcPRioYYw+UzMH6NZJH/u/A=";
    prevJdk = openjdk-18;
  }
