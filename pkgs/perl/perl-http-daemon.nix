##! perl-http-daemon — Simple HTTP server class for Perl
{
  mkDerivation,
  fetchurl,
  perl,
  perl-clone,
  perl-encode-locale,
  perl-http-date,
  perl-io-html,
  perl-lwp-mediatypes,
  perl-http-message,
  perl-uri,
}: let
  version = "6.17";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-http-daemon";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/O/OA/OALDERS/HTTP-Daemon-${version}.tar.gz"];
      hash = "sha256-FigVgMQOIxCNAoQ0aYtdfVNje/kEyd+CJIHiU8vskgw=";
    };
    sourceRoot = "HTTP-Daemon-${version}";
    module = "HTTP::Daemon";
    dependencies = [
      perl-clone
      perl-encode-locale
      perl-http-date
      perl-io-html
      perl-lwp-mediatypes
      perl-http-message
      perl-uri
    ];
    description = "Provides a simple HTTP server class for Perl";
    homepage = "https://metacpan.org/dist/HTTP-Daemon";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
