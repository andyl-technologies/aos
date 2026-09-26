##! perl-http-date — HTTP date conversion for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
  perl-timedate,
}: let
  version = "6.06";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-http-date";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "HTTP::Date returns 784111777.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use HTTP::Date qw(str2time time2str);\nmy $epoch = str2time(\"Sun, 06 Nov 1994 08:49:37 GMT\");\ndie \"wrong epoch\" unless $epoch == 784111777;\ndie \"round trip failed\" unless time2str($epoch) eq \"Sun, 06 Nov 1994 08:49:37 GMT\";\n";
        };
        "input" = "The IMF-fixdate Sun, 06 Nov 1994 08:49:37 GMT.";
        "operation" = "Parse the HTTP date into Unix epoch seconds.";
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
        "expected" = "HTTP::Date returns no timestamp.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use HTTP::Date qw(str2time);\ndie \"invalid date accepted\" if defined str2time(\"qualification-invalid-date\");\n";
        };
        "input" = "A date string without a valid HTTP date grammar.";
        "operation" = "Parse the malformed date with HTTP::Date.";
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
      urls = ["https://cpan.metacpan.org/authors/id/O/OA/OALDERS/HTTP-Date-${version}.tar.gz"];
      hash = "sha256-e2hRkcasw+dz0fwCyV7h+frpT3d4MXX154wYHMktK1I=";
    };
    sourceRoot = "HTTP-Date-${version}";
    module = "HTTP::Date";
    dependencies = [perl-timedate];
    description = "Converts dates used by HTTP into Perl values";
    homepage = "https://metacpan.org/dist/HTTP-Date";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
