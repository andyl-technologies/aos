##! perl-io-html — HTML input with automatic encoding detection for Perl
{
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "1.004";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-io-html";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/C/CJ/CJM/IO-HTML-${version}.tar.gz"];
      hash = "sha256-yHst9ZRju/LDlZZ3PftcA73g9+EFGvM5+WP1jBy9i/U=";
    };
    sourceRoot = "IO-HTML-${version}";
    module = "IO::HTML";
    description = "Opens HTML input with automatic character set detection";
    homepage = "https://metacpan.org/dist/IO-HTML";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
