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
  bootstrapTools,
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
      bootstrapTools
      ;
  };
in
  mkOpenJDKBootstrap {
    major = 10;
    version = "10.0.2";
    build = "13";
    srcHash = "sha256-Oc4SONWyBm/+HBoJ2HwXB2Ywn+GCkPJ6SrfRWETTTcE=";
    prevJdk = openjdk-9;
    # JDK-8299435 records the matching javac failure: jrtfs iterates a mutable
    # ImageReader child list. Resolving entries during that traversal can
    # extend the same list, even in a single-job build.
    extraPatches = [./openjdk-patches/snapshot-jrt-directory-children-jdk10.patch];
  }
