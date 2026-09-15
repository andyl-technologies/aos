##! perl-time-duration — English expressions of time durations
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "1.21";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-time-duration";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The module reports one hour, one minute, and one second.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Time::Duration qw(duration_exact);\nmy $rendered = duration_exact(3661);\ndie \"wrong duration\" unless $rendered eq \"1 hour, 1 minute, and 1 second\";\n";
        };
        "input" = "An exact duration of 3661 seconds.";
        "operation" = "Render the duration through Time::Duration.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-time-duration operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-time-duration operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Time::Duration rejects the nonnumeric duration.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Time::Duration qw(duration_exact);\nlocal $SIG{__WARN__} = sub { die @_ };\neval { duration_exact(\"qualification-invalid\") };\ndie \"nonnumeric duration accepted\" unless $@;\n";
        };
        "input" = "A duration value containing no numeric representation.";
        "operation" = "Render the malformed value while treating numeric warnings as rejection.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-time-duration operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-time-duration operation passed\n";
            };
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/N/NE/NEILB/Time-Duration-${version}.tar.gz"];
      hash = "sha256-/jQOuodl+SY2lGdOXf8UgzRD4Zhl5f9Ce715t7X4qbg=";
    };
    sourceRoot = "Time-Duration-${version}";
    module = "Time::Duration";
    description = "Formats time durations as rounded or exact English text";
    homepage = "https://metacpan.org/dist/Time-Duration";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
