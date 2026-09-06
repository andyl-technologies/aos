##! perl-role-tiny — Minimal role composition for Perl
{
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "2.002004";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-role-tiny";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/H/HA/HAARG/Role-Tiny-${version}.tar.gz"];
      hash = "sha256-173unhOKT4OqUtCpgWJWRL2of/FmQt+oRdy0TZokK0U=";
    };
    sourceRoot = "Role-Tiny-${version}";
    module = "Role::Tiny";
    description = "Provides lightweight role composition for Perl";
    homepage = "https://metacpan.org/dist/Role-Tiny";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
