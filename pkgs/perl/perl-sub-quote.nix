##! perl-sub-quote — Efficient string-generated Perl subroutines
{
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "2.006008";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-sub-quote";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/H/HA/HAARG/Sub-Quote-${version}.tar.gz"];
      hash = "sha256-lL69UAr1V2LoPqLyvFlNh6+CgHI3DHEQxgwjioANFbI=";
    };
    sourceRoot = "Sub-Quote-${version}";
    module = "Sub::Quote";
    description = "Generates Perl subroutines efficiently from strings";
    homepage = "https://metacpan.org/dist/Sub-Quote";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
