##! perl-moo — Minimal object system for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
  perl-class-method-modifiers,
  perl-module-runtime,
  perl-role-tiny,
  perl-sub-quote,
}: let
  version = "2.005005";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-moo";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Moo initializes the attribute and the method returns qualified.";
        "files" = {
          "probe.pl" = "BEGIN {\n    $SIG{__WARN__} = sub {\n        my ($warning) = @_;\n        die $warning unless $warning =~ /Possible attempt to escape whitespace in qw\\(\\) list .*Sub\\/Quote\\.pm line 64/;\n    };\n}\n\nuse strict; use warnings;\n{ package Qualified::Moo; use Moo; has name => (is => \"ro\", required => 1); sub label { shift->name } }\nmy $object = Qualified::Moo->new(name => \"qualified\");\ndie \"wrong object value\" unless $object->label eq \"qualified\";\n";
        };
        "input" = "A class with one required read-only name attribute.";
        "operation" = "Construct the object and call a method derived from the attribute.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-moo operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-moo operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Moo rejects construction and names the missing attribute.";
        "files" = {
          "probe.pl" = "BEGIN {\n    $SIG{__WARN__} = sub {\n        my ($warning) = @_;\n        die $warning unless $warning =~ /Possible attempt to escape whitespace in qw\\(\\) list .*Sub\\/Quote\\.pm line 64/;\n    };\n}\n\nuse strict; use warnings;\n{ package Qualified::Moo; use Moo; has name => (is => \"ro\", required => 1); }\neval { Qualified::Moo->new() };\ndie \"missing required attribute accepted\" unless $@ =~ /name/;\n";
        };
        "input" = "An object construction request missing its required name attribute.";
        "operation" = "Construct the Moo class without the required value.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-moo operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-moo operation passed\n";
            };
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/H/HA/HAARG/Moo-${version}.tar.gz"];
      hash = "sha256-+1opUmSfrtBzc/Igt4AEqcaro4dzkTN0DBdw6bH0sQg=";
    };
    sourceRoot = "Moo-${version}";
    module = "Moo";
    dependencies = [
      perl-class-method-modifiers
      perl-module-runtime
      perl-role-tiny
      perl-sub-quote
    ];
    description = "Provides a minimal object system for Perl";
    homepage = "https://metacpan.org/dist/Moo";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
