##! perl-http-date — HTTP date conversion for Perl
{
  mkDerivation,
  fetchurl,
  perl,
  perl-timedate,
}: let
  version = "6.06";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-http-date";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/O/OA/OALDERS/HTTP-Date-${version}.tar.gz"];
      hash = "sha256-e2hRkcasw+dz0fwCyV7h+frpT3d4MXX154wYHMktK1I=";
    };
    sourceRoot = "HTTP-Date-${version}";
    module = "HTTP::Date";
    dependencies = [perl-timedate];
    description = "Converts dates used by HTTP into Perl values";
    homepage = "https://metacpan.org/dist/HTTP-Date";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
