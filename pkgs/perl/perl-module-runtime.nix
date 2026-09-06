##! perl-module-runtime — Runtime module handling for Perl
{
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "0.016";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-module-runtime";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/Z/ZE/ZEFRAM/Module-Runtime-${version}.tar.gz"];
      hash = "sha256-aDAuxkaDNUfUEL4o4JZ223UAb0qlihHzvbRP/pnw8CQ=";
    };
    sourceRoot = "Module-Runtime-${version}";
    module = "Module::Runtime";
    description = "Handles Perl modules at runtime";
    homepage = "https://metacpan.org/dist/Module-Runtime";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
