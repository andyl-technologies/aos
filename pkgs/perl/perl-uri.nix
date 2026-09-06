##! perl-uri — Uniform resource identifier support for Perl
{
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "5.21";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-uri";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/O/OA/OALDERS/URI-${version}.tar.gz"];
      hash = "sha256-liZYYM1hveFuhBXc+/EIBW3hYsqgrDf4HraVydLgq3c=";
    };
    sourceRoot = "URI-${version}";
    module = "URI";
    description = "Implements uniform resource identifiers in Perl";
    homepage = "https://metacpan.org/dist/URI";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
