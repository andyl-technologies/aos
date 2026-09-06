##! perl-clone — Recursive Perl data cloning
{
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
  perl-b-cow,
}: let
  version = "0.46";
in
  mkDerivation {
    pname = "perl-clone";
    inherit version;

    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/G/GA/GARU/Clone-${version}.tar.gz"];
      hash = "sha256-qt7tXkyL1rvfaMDdAGbLUT4Wq55bQ4LcSgqv1ViQaXs=";
    };

    buildDeps = [gnumake perl perl-b-cow];
    runtimeDeps = [perl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd Clone-${version}
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
        script = ''PERL5LIB=${perl-b-cow}/lib/perl5 make test'';
      }
      {
        name = "install";
        script = ''
          make install
          cp -a "$out"/lib/perl5/*-thread-multi/. "$out/lib/perl5/"
          rm -f "$out"/lib/perl5/*/*/perllocal.pod "$out"/lib/perl5/*/*/.packlist
          PERL5LIB="$out/lib/perl5" ${perl}/bin/perl -MClone -e 1
        '';
      }
    ];

    meta = {
      description = "Recursively copies Perl data structures";
      homepage = "https://metacpan.org/dist/Clone";
      license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
    };
  }
