##! X font encoding library with the complete encoding database.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  xorgproto,
  zlib,
  encodings,
}:
import ./_libfontenc.nix {inherit mkDerivation fetchurl buildPackages stdenv xorgproto zlib encodings;}
