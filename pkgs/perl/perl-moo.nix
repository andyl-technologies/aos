##! perl-moo — Minimal object system for Perl
{
  mkDerivation,
  fetchurl,
  perl,
  perl-class-method-modifiers,
  perl-module-runtime,
  perl-role-tiny,
  perl-sub-quote,
}: let
  version = "2.005005";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-moo";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/H/HA/HAARG/Moo-${version}.tar.gz"];
      hash = "sha256-+1opUmSfrtBzc/Igt4AEqcaro4dzkTN0DBdw6bH0sQg=";
    };
    sourceRoot = "Moo-${version}";
    module = "Moo";
    dependencies = [
      perl-class-method-modifiers
      perl-module-runtime
      perl-role-tiny
      perl-sub-quote
    ];
    description = "Provides a minimal object system for Perl";
    homepage = "https://metacpan.org/dist/Moo";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
