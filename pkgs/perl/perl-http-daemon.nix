##! perl-http-daemon — Simple HTTP server class for Perl
{
  lib,
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
    pname = "perl-http-daemon";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The daemon binds loopback and reports a nonzero local port in an HTTP URL.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use HTTP::Daemon;\nmy $daemon = HTTP::Daemon->new(LocalAddr => \"127.0.0.1\", LocalPort => 0, ReuseAddr => 1);\ndie \"listener creation failed\" unless $daemon && $daemon->sockport > 0;\ndie \"wrong listener URL\" unless $daemon->url =~ m{\\Ahttp://127\\.0\\.0\\.1:\\d+/\\z};\n$daemon->close;\n";
        };
        "input" = "A loopback HTTP listener requesting an ephemeral port.";
        "operation" = "Create the listener with HTTP::Daemon and inspect its advertised URL.";
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
        "expected" = "HTTP::Daemon declines the conflicting bind request.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use HTTP::Daemon;\nmy $first = HTTP::Daemon->new(LocalAddr => \"127.0.0.1\", LocalPort => 0);\ndie \"first listener creation failed\" unless $first;\nmy $second = HTTP::Daemon->new(LocalAddr => \"127.0.0.1\", LocalPort => $first->sockport);\ndie \"occupied endpoint accepted\" if defined $second;\n$first->close;\n";
        };
        "input" = "A loopback endpoint already occupied by another HTTP listener.";
        "operation" = "Attempt to bind a second daemon to the occupied endpoint.";
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
