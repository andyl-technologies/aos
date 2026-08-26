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
    # JDK 10's module reader is not safe when multiple javac batches traverse
    # its JRT index concurrently. Keep this one bootstrap transition serial;
    # later JDK stages use their normal parallel builds again.
    buildJobs = 1;
    # JDK 10's javac server has a ConcurrentModificationException bug in
    # jrtfs when multiple threads access the module system simultaneously.
    # Its old optimizing VM also crashes while compiling JDK 11's large Graal
    # module on current CPUs. Keep the bootstrap tools interpreted and
    # single-processor; this affects only tools executed by the boot JDK.
    extraConfigureFlags = [
      "--enable-javac-server=no"
      ''--with-boot-jdk-jvmargs="-Xint -XX:+UseSerialGC -XX:ActiveProcessorCount=1"''
    ];
  }
