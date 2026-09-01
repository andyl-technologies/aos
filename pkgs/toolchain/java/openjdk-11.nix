##! OpenJDK 11 — bootstrap chain intermediate (built with openjdk-10)
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
  krb5,
  openjdk-10,
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
      krb5
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
    # Avoid sharing the JDK 10 module reader across compiler requests. Its old
    # optimizing VM also crashes while compiling JDK 11's large Graal module
    # on current CPUs, so keep bootstrap execution interpreted, single-threaded,
    # and capped at AVX2. This affects only tools executed by the boot JDK.
    extraConfigureFlags = [
      "--enable-javac-server=no"
      ''--with-boot-jdk-jvmargs="-Xint -XX:+UseSerialGC -XX:ActiveProcessorCount=1 -XX:UseAVX=2"''
    ];
  }
