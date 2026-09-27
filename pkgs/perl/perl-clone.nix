##! perl-clone — Recursive Perl data cloning
{
  mkDerivation,
  fetchurl,
  buildPackages,
  gnumake,
  lib,
  perl,
  perl-b-cow,
  stdenv,
}: let
  version = "0.46";
  xsCross = import ../build-support/_perl-xs-cross-config.nix {
    inherit buildPackages lib perl stdenv;
  };
  runtimeClosureManifest = builtins.toString perl;
in
  mkDerivation {
    pname = "perl-clone";
    inherit version;

    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/G/GA/GARU/Clone-${version}.tar.gz"];
      hash = "sha256-qt7tXkyL1rvfaMDdAGbLUT4Wq55bQ4LcSgqv1ViQaXs=";
    };

    buildDeps = [gnumake xsCross.buildPerl] ++ lib.optionals (!stdenv.isCross) [perl-b-cow];
    runtimeDeps = [perl];
    propagatedDeps = [];

    phases =
      [
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
            ${xsCross.setup}
            ${xsCross.buildPerl}/bin/perl Makefile.PL INSTALL_BASE="$out" CC="$CC" LD="$CC"
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
          script = ''PERL5LIB=${perl-b-cow}/lib/perl5 make test'';
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
              PERL5LIB="$out/lib/perl5" ${xsCross.buildPerl}/bin/perl -MClone -e 1
            ''}
          '';
        }
      ];

    meta = {
      description = "Recursively copies Perl data structures";
      homepage = "https://metacpan.org/dist/Clone";
      license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
    };
  }
