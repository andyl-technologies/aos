##! perl-algorithm-diff — Intelligent differences between Perl sequences
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "1.1903";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-algorithm-diff";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The module returns alpha and gamma in order.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Algorithm::Diff qw(LCS);\nmy @common = LCS([qw(alpha beta gamma)], [qw(alpha delta gamma)]);\ndie \"wrong common sequence\" unless join(\",\", @common) eq \"alpha,gamma\";\n";
        };
        "input" = "The sequences alpha, beta, gamma and alpha, delta, gamma.";
        "operation" = "Compute their longest common subsequence through Algorithm::Diff.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-algorithm-diff operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-algorithm-diff operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Algorithm::Diff rejects the non-array sequence.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Algorithm::Diff ();\neval { Algorithm::Diff::diff(\"not-an-array\", []) };\ndie \"invalid sequence accepted\" unless $@;\n";
        };
        "input" = "A scalar supplied where Algorithm::Diff requires a sequence reference.";
        "operation" = "Attempt to compute a diff with the malformed operand.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import json, os, pathlib, subprocess\n\nclosure = json.loads(os.environ[\"AOS_QUALIFICATION_PACKAGE_CLOSURE\"])\ninterpreters = sorted({str(pathlib.Path(path) / \"bin/perl\") for path in closure if (pathlib.Path(path) / \"bin/perl\").is_file()})\nlibraries = sorted(str(pathlib.Path(path) / \"lib/perl5\") for path in closure if (pathlib.Path(path) / \"lib/perl5\").is_dir())\nassert interpreters and libraries\nenvironment = os.environ.copy()\nenvironment[\"PERL5LIB\"] = \":\".join(libraries)\nresult = subprocess.run([interpreters[0], \"probe.pl\"], env=environment, capture_output=True, text=True)\nassert result.returncode == 0, result.stderr\nassert result.stdout == \"\" and result.stderr == \"\"\nprint(\"perl-algorithm-diff operation passed\")\n"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "perl-algorithm-diff operation passed\n";
            };
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/T/TY/TYEMQ/Algorithm-Diff-${version}.tar.gz"];
      hash = "sha256-MOhKxLMdQLZik/exIhMxxaUFYaOdWA2FAE2cH/+ZF1E=";
    };
    sourceRoot = "Algorithm-Diff-${version}";
    module = "Algorithm::Diff";
    description = "Computes intelligent differences between Perl sequences";
    homepage = "https://metacpan.org/dist/Algorithm-Diff";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
