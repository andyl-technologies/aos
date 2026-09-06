##! perl-timedate — Date and time parsing modules for Perl
{
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "2.33";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-timedate";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/A/AT/ATOOMIC/TimeDate-${version}.tar.gz"];
      hash = "sha256-wLacSwOd5vUBsNnxPsWMhrBAwffpsn7ySWUcFD1gXrI=";
    };
    sourceRoot = "TimeDate-${version}";
    module = "Date::Parse";
    description = "Date and time parsing modules for Perl";
    homepage = "https://metacpan.org/dist/TimeDate";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
