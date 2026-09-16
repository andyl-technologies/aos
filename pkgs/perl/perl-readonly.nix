##! perl-readonly — Read-only Perl values
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "2.05";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-readonly";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Readonly preserves the exact scalar value.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Readonly;\nReadonly my $value => \"qualified\";\ndie \"wrong readonly value\" unless $value eq \"qualified\";\n";
        };
        "input" = "A scalar initialized to the value qualified.";
        "operation" = "Declare it read-only and read the stored value.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-readonly operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-readonly operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Readonly rejects the assignment and preserves the original value.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Readonly;\nReadonly my $value => \"qualified\";\neval { $value = \"changed\"; };\ndie \"readonly assignment accepted\" unless $@ && $value eq \"qualified\";\n";
        };
        "input" = "An assignment that attempts to replace a read-only scalar.";
        "operation" = "Mutate the protected value.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-readonly operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-readonly operation passed\n";
            };
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/S/SA/SANKO/Readonly-${version}.tar.gz"];
      hash = "sha256-SyNUJJGvAQ1EpcfIYSRHOKzHSrq65riDjTVN+xlGK14=";
    };
    sourceRoot = "Readonly-${version}";
    module = "Readonly";
    description = "Creates read-only Perl scalars, arrays, and hashes";
    homepage = "https://metacpan.org/dist/Readonly";
    license = "Artistic-2.0";
  }
