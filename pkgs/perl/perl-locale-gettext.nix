##! Perl bindings for gettext message catalogs.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  perl,
  gettext,
}: let
  version = "1.07";
in
  mkDerivation {
    pname = "perl-locale-gettext";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/P/PV/PVANDRY/Locale-gettext-${version}.tar.gz"];
      hash = "05cwqjxxary11di03gg3fm6j9lbvg1dr2wpr311c1rwp8salg7ch";
    };

    buildDeps = [buildPackages.gnumake buildPackages.perl];
    runtimeDeps = [perl gettext];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd Locale-gettext-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          perl Makefile.PL INSTALL_BASE="$out" CC="$CC" LD="$CC"
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL"
        '';
      }
      {
        name = "check";
        script = ''
          make test SHELL="$CONFIG_SHELL"
        '';
      }
      {
        name = "install";
        script = ''
          make install SHELL="$CONFIG_SHELL"
          cp -a "$out"/lib/perl5/*-thread-multi/. "$out/lib/perl5/"
          mkdir -p "$out/share/licenses/perl-locale-gettext"
          cp README "$out/share/licenses/perl-locale-gettext/"
        '';
      }
    ];

    meta = {
      description = "Perl interface to gettext message translation";
      homepage = "https://metacpan.org/dist/Locale-gettext";
      license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
    };
  }
