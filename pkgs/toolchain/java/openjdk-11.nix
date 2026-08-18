##! OpenJDK 11 — bootstrap chain intermediate (built with openjdk-10)
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
  openjdk-10,
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
    major = 11;
    version = "11.0.25";
    build = "9";
    srcHash = "sha256-pmnvno57buWNPlFZ31f9Eqp0KBn7voYvKLncdJ9H8E4=";
    prevJdk = openjdk-10;
    # JDK 10's module reader is not safe under highly parallel javac batches.
    # Keep native compilation parallel while bounding the number of concurrent
    # boot-compiler invocations used to construct JDK 11.
    buildJobs = 16;
    # JDK 10's javac server has a ConcurrentModificationException bug in
    # jrtfs when multiple threads access the module system simultaneously.
    # Disable the javac server to avoid the race condition.
    extraConfigureFlags = ["--enable-javac-server=no"];
  }
