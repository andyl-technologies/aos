##! perl-module-runtime — Runtime module handling for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "0.016";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-module-runtime";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Module::Runtime returns Qualification/Example.pm.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Module::Runtime qw(module_notional_filename);\ndie \"wrong filename\" unless module_notional_filename(\"Qualification::Example\") eq \"Qualification/Example.pm\";\n";
        };
        "input" = "The valid module name Qualification::Example.";
        "operation" = "Convert the name to its notional module filename.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-module-runtime operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-module-runtime operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Module::Runtime rejects the invalid module name.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Module::Runtime qw(check_module_name);\neval { check_module_name(\"Qualification::../Invalid\") };\ndie \"invalid module name accepted\" unless $@ =~ /not a module name/;\n";
        };
        "input" = "A module name containing a path traversal segment.";
        "operation" = "Validate and convert the malformed module name.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-module-runtime operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-module-runtime operation passed\n";
            };
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/Z/ZE/ZEFRAM/Module-Runtime-${version}.tar.gz"];
      hash = "sha256-aDAuxkaDNUfUEL4o4JZ223UAb0qlihHzvbRP/pnw8CQ=";
    };
    sourceRoot = "Module-Runtime-${version}";
    module = "Module::Runtime";
    description = "Handles Perl modules at runtime";
    homepage = "https://metacpan.org/dist/Module-Runtime";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
