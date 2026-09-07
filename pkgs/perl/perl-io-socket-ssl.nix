##! perl-io-socket-ssl — TLS sockets for Perl
{
  mkDerivation,
  fetchurl,
  perl,
  perl-mozilla-ca,
  perl-net-ssleay,
  ca-certificates,
}: let
  version = "2.083";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-io-socket-ssl";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/S/SU/SULLR/IO-Socket-SSL-${version}.tar.gz"];
      hash = "sha256-kE7yh2VECpfYqaDfWX+MPX88sKBT0bCCwQvtA7yAIGk=";
    };
    sourceRoot = "IO-Socket-SSL-${version}";
    module = "IO::Socket::SSL";
    dependencies = [perl-mozilla-ca perl-net-ssleay];
    postInstall = ''
      sed -i \
        's|$openssldir/cert.pem|${ca-certificates}/etc/ssl/certs/ca-certificates.crt|' \
        "$out/lib/perl5/IO/Socket/SSL.pm"
    '';
    description = "Provides TLS sockets for Perl";
    homepage = "https://metacpan.org/dist/IO-Socket-SSL";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
