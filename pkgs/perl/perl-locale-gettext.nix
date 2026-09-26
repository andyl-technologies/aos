##! Perl bindings for gettext message catalogs.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  lib,
  stdenv,
  perl,
  gettext,
}: let
  version = "1.07";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "perl-locale-gettext";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A catalog domain with no installed translations and a plural count of two.";
        operation = "Bind the domain and resolve singular and plural messages.";
        expected = "The binding returns the untranslated messages when no catalog exists.";
        artifacts = [];
        files."probe.pl" = ''
          use strict;
          use warnings;
          use Locale::gettext;

          my $domain = "aos-qualification-absent";
          my $path = Locale::gettext::bindtextdomain($domain, ".");
          die "domain binding failed" unless $path eq ".";

          Locale::gettext::textdomain($domain);
          die "singular fallback failed"
            unless Locale::gettext::gettext("hello") eq "hello";
          die "plural fallback failed"
            unless Locale::gettext::ngettext("one", "many", 2) eq "many";
        '';
        steps = [
          {
            argv = ["@perl@" "probe.pl"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A domain name without the required message identifier.";
        operation = "Call dgettext with a missing message argument.";
        expected = "The binding reports its required arguments.";
        artifacts = [];
        files."probe.pl" = ''
          use strict;
          use warnings;
          use Locale::gettext;

          eval { Locale::gettext::dgettext("aos-qualification-absent") };
          die "missing message identifier accepted"
            unless $@ =~ /^Usage: Locale::gettext::dgettext/;
        '';
        steps = [
          {
            argv = ["@perl@" "probe.pl"];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/P/PV/PVANDRY/Locale-gettext-${version}.tar.gz"];
      hash = "05cwqjxxary11di03gg3fm6j9lbvg1dr2wpr311c1rwp8salg7ch";
    };

    buildDeps = [buildPackages.gnumake buildPackages.perl];
    runtimeDeps = [perl gettext];

    # The XS tests load the compiled module, so they run only on native builds.
    phases =
      [
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
      ]
      ++ lib.optionals (!stdenv.isCross) [
        {
          name = "check";
          script = ''
            make test SHELL="$CONFIG_SHELL"
          '';
        }
      ]
      ++ [
        {
          name = "install";
          script = ''
            make install SHELL="$CONFIG_SHELL"
            cp -a "$out"/lib/perl5/*-thread-multi/. "$out/lib/perl5/"
            # MakeMaker stamps this install log with wall-clock time.
            rm -f "$out"/lib/perl5/perllocal.pod "$out"/lib/perl5/*-thread-multi/perllocal.pod
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
