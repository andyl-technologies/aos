##! OpenJDK 14 — bootstrap chain intermediate (built with openjdk-13)
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
  openjdk-13,
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
  major = 14;
  version = "14.0.2";
  build = "12";
  srcHash = "sha256-WC49gFq3RYIzIlD5X5hFYIyPPTJzqpKvb2g8RdGk+Og=";
  prevJdk = openjdk-13;
}
