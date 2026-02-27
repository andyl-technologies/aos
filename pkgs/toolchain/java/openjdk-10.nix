##! OpenJDK 10 — bootstrap chain intermediate (built with openjdk-9)
{
  mkDerivation,
  fetchurl,
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
  openjdk-9,
}: let
  mkOpenJDKBootstrap = import ./_openjdk-bootstrap.nix {
    inherit
      fetchurl
      mkDerivation
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
      ;
  };
in
  mkOpenJDKBootstrap {
    major = 10;
    version = "10.0.2";
    build = "13";
    srcHash = "sha256-Oc4SONWyBm/+HBoJ2HwXB2Ywn+GCkPJ6SrfRWETTTcE=";
    prevJdk = openjdk-9;
  }
