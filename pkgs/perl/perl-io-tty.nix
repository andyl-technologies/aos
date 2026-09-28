##! perl-io-tty — Pseudo-terminal support for Perl
{
  mkDerivation,
  fetchurl,
  buildPackages,
  gnumake,
  lib,
  perl,
  stdenv,
}: let
  version = "1.20";
  xsCross = import ../build-support/_perl-xs-cross-config.nix {
    inherit buildPackages lib perl stdenv;
  };
  runtimeClosureManifest = builtins.toString perl;
in
  mkDerivation {
    pname = "perl-io-tty";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/T/TO/TODDR/IO-Tty-${version}.tar.gz"];
      hash = "sha256-sVMJ/IViOJMonLmyuI36ntHmkVa3XymThVOkW+bXMK8=";
    };
    buildDeps = [gnumake xsCross.buildPerl];
    runtimeDeps = [perl];
    propagatedDeps = [];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd IO-Tty-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            ${xsCross.setup}
            ${xsCross.buildPerl}/bin/perl Makefile.PL INSTALL_BASE="$out" \
              CC="$CC" LD="$CC" CCFLAGS="" LDFLAGS=""
          '';
        }
        {
          name = "build";
          script = ''make -j"$NIX_BUILD_CORES"'';
        }
      ]
      ++ lib.optionals (!stdenv.isCross) [
        {
          name = "check";
          script = ''make test'';
        }
      ]
      ++ [
        {
          name = "install";
          script = ''
            make install
            cp -a "$out"/lib/perl5/*-thread-multi*/. "$out/lib/perl5/"
            rm -f "$out"/lib/perl5/*/*/perllocal.pod "$out"/lib/perl5/*/*/.packlist

            # The XS module does not retain the interpreter used to load it.
            mkdir -p "$out/nix-support"
            echo '${runtimeClosureManifest}' > "$out/nix-support/runtime-closure"

            ${lib.optionalString (!stdenv.isCross) ''
              PERL5LIB="$out/lib/perl5" ${xsCross.buildPerl}/bin/perl -MIO::Tty -e 1
            ''}
          '';
        }
      ];
    meta = {
      description = "Low-level pseudo-terminal allocation and terminal constants for Perl";
      homepage = "https://metacpan.org/dist/IO-Tty";
      license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
    };
  }
