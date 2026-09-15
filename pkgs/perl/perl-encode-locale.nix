##! perl-encode-locale — Locale encoding detection for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "1.05";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-encode-locale";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Encode::Locale preserves the decoded qualification argument.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Encode::Locale qw(decode_argv);\nEncode::Locale::reinit(\"UTF-8\", \"UTF-8\");\nlocal @ARGV = (\"qualification\");\ndecode_argv();\ndie \"argument changed\" unless $ARGV[0] eq \"qualification\";\n";
        };
        "input" = "One UTF-8 command-line argument decoded in void context.";
        "operation" = "Configure UTF-8 as the locale encoding and decode @ARGV in place.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-encode-locale operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-encode-locale operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Encode::Locale rejects the unsupported calling context.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Encode::Locale qw(decode_argv);\neval { my $value = decode_argv(); };\ndie \"scalar context accepted\" unless $@;\n";
        };
        "input" = "A scalar-context request for the void-only decode_argv operation.";
        "operation" = "Call decode_argv where a return value is requested.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-encode-locale operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-encode-locale operation passed\n";
            };
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/G/GA/GAAS/Encode-Locale-${version}.tar.gz"];
      hash = "sha256-F2+gJ3H1QqTvsdvCpMko6PQ5G/QHhHO9YEDY8RrbDsE=";
    };
    sourceRoot = "Encode-Locale-${version}";
    module = "Encode::Locale";
    description = "Determines the locale encoding for Perl programs";
    homepage = "https://metacpan.org/dist/Encode-Locale";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
