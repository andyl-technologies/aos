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
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-http-date operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-http-date operation passed\n";
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
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-http-date operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-http-date operation passed\n";
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
