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
    # JDK 10's module reader is not safe while the JDK 11 make graph runs
    # concurrent boot-compiler batches.  It still throws
    # ConcurrentModificationException with 16 jobs and the javac server
    # disabled, so serialize this bootstrap boundary completely.
    buildJobs = 1;
    # JDK 10's javac server has a ConcurrentModificationException bug in
    # jrtfs when multiple threads access the module system simultaneously.
    # Disable the javac server to avoid the race condition.
    extraConfigureFlags = ["--enable-javac-server=no"];
  }
