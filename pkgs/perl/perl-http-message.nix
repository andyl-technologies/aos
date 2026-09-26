##! perl-http-message — HTTP message objects for Perl
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
    pname = "perl-http-message";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The serialized message contains the request line, header, and exact body.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use HTTP::Request;\nmy $request = HTTP::Request->new(\"POST\", \"http://example.test/qualified\");\n$request->header(\"Content-Type\" => \"text/plain\");\n$request->content(\"payload\");\nmy $wire = $request->as_string(\"\\r\\n\");\ndie \"request line missing\" unless $wire =~ /\\APOST http:\\/\\/example\\.test\\/qualified\\r\\n/;\ndie \"body missing\" unless $wire =~ /\\r\\n\\r\\npayload\\z/;\n";
        };
        "input" = "A POST request with one content-type header and a fixed body.";
        "operation" = "Construct and serialize the request through HTTP::Request.";
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
        "expected" = "HTTP::Message rejects the non-reference content value.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use HTTP::Message;\nmy $message = HTTP::Message->new;\neval { $message->content_ref(\"not-a-reference\") };\ndie \"invalid content reference accepted\" unless $@ =~ /non-ref/;\n";
        };
        "input" = "A scalar supplied to the reference-only content_ref setter.";
        "operation" = "Replace message content through content_ref with the invalid value.";
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
