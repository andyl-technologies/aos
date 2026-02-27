##! OpenJDK 15 — bootstrap chain intermediate (built with openjdk-14)
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
  openjdk-14,
}:
let
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
  major = 15;
  version = "15.0.10";
  build = "5";
  srcHash = "sha256-eq6rSmhHHmMNker1VA0GfI/9XwIwMb4IK4iXY8H5Tzo=";
  prevJdk = openjdk-14;
}
