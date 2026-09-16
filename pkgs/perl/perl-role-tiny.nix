##! perl-role-tiny — Minimal role composition for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "2.002004";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-role-tiny";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Role::Tiny composes the method and it returns qualified.";
        "files" = {
          "probe.pl" = "use strict; use warnings;\n{ package Qualified::Role; use Role::Tiny; requires \"name\"; sub label { shift->name } }\n{ package Qualified::Class; sub name { \"qualified\" } }\nRole::Tiny->apply_role_to_package(\"Qualified::Class\", \"Qualified::Role\");\ndie \"role method unavailable\" unless Qualified::Class->label eq \"qualified\";\n";
        };
        "input" = "A role requiring name and providing a label method, plus a class implementing name.";
        "operation" = "Apply the role to the class and call the provided method.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-role-tiny operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-role-tiny operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Role::Tiny rejects composition and identifies the missing requirement.";
        "files" = {
          "probe.pl" = "use strict; use warnings;\n{ package Qualified::Role; use Role::Tiny; requires \"required_method\"; }\n{ package Qualified::Incomplete; }\neval { Role::Tiny->apply_role_to_package(\"Qualified::Incomplete\", \"Qualified::Role\") };\ndie \"unsatisfied role accepted\" unless $@ =~ /required_method/;\n";
        };
        "input" = "A class that lacks a method required by the role.";
        "operation" = "Apply the role to the incomplete class.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-role-tiny operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-role-tiny operation passed\n";
            };
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/H/HA/HAARG/Role-Tiny-${version}.tar.gz"];
      hash = "sha256-173unhOKT4OqUtCpgWJWRL2of/FmQt+oRdy0TZokK0U=";
    };
    sourceRoot = "Role-Tiny-${version}";
    module = "Role::Tiny";
    description = "Provides lightweight role composition for Perl";
    homepage = "https://metacpan.org/dist/Role-Tiny";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
