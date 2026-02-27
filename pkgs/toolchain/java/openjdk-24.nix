##! OpenJDK 24 — bootstrap chain intermediate (built with openjdk-23)
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
  openjdk-23,
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
  major = 24;
  version = "24.0.1";
  build = "9";
  srcHash = "sha256-H7POv+7tyD+URC4l2PMh4o2jTAn8D+IbS3ALzbLtDuQ=";
  prevJdk = openjdk-23;
}
