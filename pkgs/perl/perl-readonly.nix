##! perl-readonly — Read-only Perl values
{
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "2.05";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-readonly";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/S/SA/SANKO/Readonly-${version}.tar.gz"];
      hash = "sha256-SyNUJJGvAQ1EpcfIYSRHOKzHSrq65riDjTVN+xlGK14=";
    };
    sourceRoot = "Readonly-${version}";
    module = "Readonly";
    description = "Creates read-only Perl scalars, arrays, and hashes";
    homepage = "https://metacpan.org/dist/Readonly";
    license = "Artistic-2.0";
  }
