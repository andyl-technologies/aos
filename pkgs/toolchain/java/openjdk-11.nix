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
    # The JDK 10 jrtfs snapshot patch prevents re-entrant child-list mutation,
    # but does not make the old module reader safe for arbitrary concurrent
    # callers. Keep this bootstrap boundary serialized.
    buildJobs = 1;
    # Avoid sharing the JDK 10 module reader across compiler requests. Cap the
    # boot JVM at AVX2 as well: its HotSpot defaults to AVX-512 on newer CPUs
    # and can crash in libjvm while compiling a large module batch.
    extraConfigureFlags = [
      "--enable-javac-server=no"
      "--with-boot-jdk-jvmargs=-XX:UseAVX=2"
    ];
  }
