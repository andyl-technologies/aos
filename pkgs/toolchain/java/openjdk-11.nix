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
  openjdk-10,
}: let
  mkOpenJDKBootstrap = import ./_openjdk-bootstrap.nix {
    inherit fetchurl mkDerivation gnumake autoconf bash which zip unzip gawk
            coreutils zlib alsa-lib binutils cups file fontconfig freetype xorg-stubs;
  };
in
  mkOpenJDKBootstrap {
    major = 11;
    version = "11.0.25";
    build = "9";
    srcHash = "sha256-pmnvno57buWNPlFZ31f9Eqp0KBn7voYvKLncdJ9H8E4=";
    prevJdk = openjdk-10;
  }
