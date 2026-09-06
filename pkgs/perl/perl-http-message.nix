##! perl-http-message — HTTP message objects for Perl
{
  mkDerivation,
  fetchurl,
  perl,
  perl-clone,
  perl-encode-locale,
  perl-http-date,
  perl-io-html,
  perl-lwp-mediatypes,
  perl-uri,
}: let
  version = "6.45";
  dependencies = [
    perl-clone
    perl-encode-locale
    perl-http-date
    perl-io-html
    perl-lwp-mediatypes
    perl-uri
  ];
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-http-message";
    inherit version dependencies;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/O/OA/OALDERS/HTTP-Message-${version}.tar.gz"];
      hash = "sha256-AcuEBmEqP3OIQtHpcxOuTYdIcNG41tZjMfFgAJQ9TL4=";
    };
    sourceRoot = "HTTP-Message-${version}";
    module = "HTTP::Message";
    description = "Provides HTTP request and response message objects";
    homepage = "https://metacpan.org/dist/HTTP-Message";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
