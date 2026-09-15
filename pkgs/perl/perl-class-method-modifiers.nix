##! perl-class-method-modifiers — Moose-style method modifiers for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "2.15";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-class-method-modifiers";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Class::Method::Modifiers preserves the return value and runs the modifier once.";
        "files" = {
          "probe.pl" = "use strict; use warnings;\n{ package Qualified::Class; sub value { \"qualified\" } }\n{ package Qualified::Class; use Class::Method::Modifiers; our $calls = 0; after value => sub { $calls++ }; }\ndie \"method result changed\" unless Qualified::Class->value eq \"qualified\";\ndie \"modifier did not run\" unless $Qualified::Class::calls == 1;\n";
        };
        "input" = "A class method with an after modifier that records one invocation.";
        "operation" = "Install the modifier and call the method.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-class-method-modifiers operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-class-method-modifiers operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Class::Method::Modifiers rejects the missing target.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Class::Method::Modifiers qw(install_modifier);\n{ package Qualified::Empty; }\neval { install_modifier(\"Qualified::Empty\", \"after\", \"qualification_missing\", sub {}) };\ndie \"missing method accepted\" unless $@;\n";
        };
        "input" = "A modifier targeting a method absent from the class.";
        "operation" = "Install an after modifier for the nonexistent method.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-class-method-modifiers operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-class-method-modifiers operation passed\n";
            };
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/E/ET/ETHER/Class-Method-Modifiers-${version}.tar.gz"];
      hash = "sha256-Zc2Fv+R10GbpGG96jMY2BwmFswsOuxzehoHPBiwuFfw=";
    };
    sourceRoot = "Class-Method-Modifiers-${version}";
    module = "Class::Method::Modifiers";
    description = "Provides Moose-style method modifiers";
    homepage = "https://metacpan.org/dist/Class-Method-Modifiers";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
