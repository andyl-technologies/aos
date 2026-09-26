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
              "@perl@"
              "probe.pl"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
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
              "@perl@"
              "probe.pl"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
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
