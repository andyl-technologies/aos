##! perl-io-tty — Pseudo-terminal support for Perl
{
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
}: let
  version = "1.20";
in
  mkDerivation {
    pname = "perl-io-tty";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/T/TO/TODDR/IO-Tty-${version}.tar.gz"];
      hash = "sha256-sVMJ/IViOJMonLmyuI36ntHmkVa3XymThVOkW+bXMK8=";
    };
    buildDeps = [gnumake perl];
    runtimeDeps = [perl];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd IO-Tty-${version}
        '';
      }
      {
        name = "configure";
        script = ''${perl}/bin/perl Makefile.PL INSTALL_BASE="$out" CC="$CC" LD="$CC"'';
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
          PERL5LIB="$out/lib/perl5" ${perl}/bin/perl -MIO::Tty -e 1
        '';
      }
    ];
    meta = {
      description = "Low-level pseudo-terminal allocation and terminal constants for Perl";
      homepage = "https://metacpan.org/dist/IO-Tty";
      license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
    };
  }
