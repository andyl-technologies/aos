##! OpenJDK 23 — bootstrap chain intermediate (built with openjdk-22)
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
  openjdk-22,
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
    major = 23;
    version = "23.0.2";
    build = "7";
    srcHash = "sha256-pQchkZBngfybbXDjNa6NI/AIc5zlg3KwGYAltLovvsY=";
    prevJdk = openjdk-22;
  }
