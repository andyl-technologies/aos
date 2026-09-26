##! perl-io-socket-ssl — TLS sockets for Perl
{
  lib,
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
    pname = "perl-io-socket-ssl";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "IO::Socket::SSL returns an existing CA file or directory.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use IO::Socket::SSL;\nmy %ca = IO::Socket::SSL::default_ca();\nmy $path = $ca{SSL_ca_file} // $ca{SSL_ca_path};\ndie \"default CA unavailable\" unless defined($path) && -e $path;\n";
        };
        "input" = "The package's configured default certificate authority source.";
        "operation" = "Resolve the default CA configuration without opening a socket.";
        "steps" = [
          {
            "argv" = [
              "@perl@"
              "probe.pl"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The utility rejects the malformed certificate.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use IO::Socket::SSL::Utils qw(PEM_string2cert);\neval { PEM_string2cert(\"not a certificate\") };\ndie \"malformed certificate accepted\" unless $@ =~ /cannot parse/;\n";
        };
        "input" = "Text that is not a PEM X.509 certificate.";
        "operation" = "Parse it with IO::Socket::SSL's certificate utility.";
        "steps" = [
          {
            "argv" = [
              "@perl@"
              "probe.pl"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

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
