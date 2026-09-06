##! perl-encode-locale — Locale encoding detection for Perl
{
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "1.05";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-encode-locale";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/G/GA/GAAS/Encode-Locale-${version}.tar.gz"];
      hash = "sha256-F2+gJ3H1QqTvsdvCpMko6PQ5G/QHhHO9YEDY8RrbDsE=";
    };
    sourceRoot = "Encode-Locale-${version}";
    module = "Encode::Locale";
    description = "Determines the locale encoding for Perl programs";
    homepage = "https://metacpan.org/dist/Encode-Locale";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
