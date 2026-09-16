##! perl-io-html — HTML input with automatic encoding detection for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "1.004";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-io-html";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The module normalizes the declaration to utf-8-strict.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use IO::HTML qw(find_charset_in);\nmy $encoding = find_charset_in(q{<meta charset=\"UTF-8\"><p>qualified</p>});\ndie \"charset not detected\" unless defined($encoding) && $encoding =~ /utf-8/i;\n";
        };
        "input" = "An HTML meta charset declaration for UTF-8.";
        "operation" = "Detect the declared encoding with IO::HTML.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-io-html operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-io-html operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "IO::HTML declines the unknown charset.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use IO::HTML qw(find_charset_in);\nmy $encoding = find_charset_in(q{<meta charset=\"qualification-invalid\">});\ndie \"invalid charset accepted\" if defined $encoding;\n";
        };
        "input" = "An HTML meta declaration naming a nonexistent character encoding.";
        "operation" = "Attempt to resolve the unsupported encoding.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-io-html operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-io-html operation passed\n";
            };
          }
        ];
      };
    };

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
