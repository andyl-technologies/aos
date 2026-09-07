##! perl-class-method-modifiers — Moose-style method modifiers for Perl
{
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "2.15";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-class-method-modifiers";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/E/ET/ETHER/Class-Method-Modifiers-${version}.tar.gz"];
      hash = "sha256-Zc2Fv+R10GbpGG96jMY2BwmFswsOuxzehoHPBiwuFfw=";
    };
    sourceRoot = "Class-Method-Modifiers-${version}";
    module = "Class::Method::Modifiers";
    description = "Provides Moose-style method modifiers";
    homepage = "https://metacpan.org/dist/Class-Method-Modifiers";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
