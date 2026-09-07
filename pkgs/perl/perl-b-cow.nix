##! perl-b-cow — Copy-on-write inspection helpers for Perl
{
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
}: let
  version = "0.007";
in
  mkDerivation {
    pname = "perl-b-cow";
    inherit version;

    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/A/AT/ATOOMIC/B-COW-${version}.tar.gz"];
      hash = "sha256-EpDa8ifosJiJoxzxguKRBvHPnxpOm/d1L53pLtEVi0Q=";
    };

    buildDeps = [gnumake perl];
    runtimeDeps = [perl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd B-COW-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ${perl}/bin/perl Makefile.PL INSTALL_BASE="$out" CC="$CC" LD="$CC"
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''make test'';
      }
      {
        name = "install";
        script = ''
          make install
          cp -a "$out"/lib/perl5/*-thread-multi/. "$out/lib/perl5/"
          rm -f "$out"/lib/perl5/*/*/perllocal.pod "$out"/lib/perl5/*/*/.packlist
          PERL5LIB="$out/lib/perl5" ${perl}/bin/perl -MB::COW -e 1
        '';
      }
    ];

    meta = {
      description = "Copy-on-write inspection helpers for Perl internals";
      homepage = "https://metacpan.org/dist/B-COW";
      license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
    };
  }
