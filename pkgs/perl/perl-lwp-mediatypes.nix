##! perl-lwp-mediatypes — MIME type inference for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "6.04";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-lwp-mediatypes";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "LWP::MediaTypes identifies application/x-tar with gzip encoding.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use LWP::MediaTypes qw(guess_media_type);\nmy ($type, $encoding) = guess_media_type(\"qualification.tar.gz\");\ndie \"wrong media inference\" unless $type eq \"application/x-tar\" && $encoding eq \"gzip\";\n";
        };
        "input" = "The archive name qualification.tar.gz.";
        "operation" = "Infer its media type and content encoding.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-lwp-mediatypes operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-lwp-mediatypes operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "LWP::MediaTypes returns no suffix.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use LWP::MediaTypes qw(media_suffix);\nmy $suffix = media_suffix(\"application/qualification-invalid\");\ndie \"unknown media type accepted\" if defined $suffix;\n";
        };
        "input" = "An unregistered application/qualification-invalid media type.";
        "operation" = "Request a preferred filename suffix for the unknown media type.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-lwp-mediatypes operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-lwp-mediatypes operation passed\n";
            };
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/O/OA/OALDERS/LWP-MediaTypes-${version}.tar.gz"];
      hash = "sha256-jxvKEtqxahwqfAOknF5YzOQab+yVGfCq37qNrZl5Gdk=";
    };
    sourceRoot = "LWP-MediaTypes-${version}";
    module = "LWP::MediaTypes";
    description = "Infers MIME types from file names and URLs";
    homepage = "https://metacpan.org/dist/LWP-MediaTypes";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
