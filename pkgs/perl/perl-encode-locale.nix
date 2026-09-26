##! perl-encode-locale — Locale encoding detection for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "1.05";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-encode-locale";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Encode::Locale preserves the decoded qualification argument.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Encode::Locale qw(decode_argv);\nEncode::Locale::reinit(\"UTF-8\", \"UTF-8\");\nlocal @ARGV = (\"qualification\");\ndecode_argv();\ndie \"argument changed\" unless $ARGV[0] eq \"qualification\";\n";
        };
        "input" = "One UTF-8 command-line argument decoded in void context.";
        "operation" = "Configure UTF-8 as the locale encoding and decode @ARGV in place.";
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
        "expected" = "Encode::Locale rejects the unsupported calling context.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Encode::Locale qw(decode_argv);\neval { my $value = decode_argv(); };\ndie \"scalar context accepted\" unless $@;\n";
        };
        "input" = "A scalar-context request for the void-only decode_argv operation.";
        "operation" = "Call decode_argv where a return value is requested.";
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
      urls = ["https://cpan.metacpan.org/authors/id/G/GA/GAAS/Encode-Locale-${version}.tar.gz"];
      hash = "sha256-F2+gJ3H1QqTvsdvCpMko6PQ5G/QHhHO9YEDY8RrbDsE=";
    };
    sourceRoot = "Encode-Locale-${version}";
    module = "Encode::Locale";
    description = "Determines the locale encoding for Perl programs";
    homepage = "https://metacpan.org/dist/Encode-Locale";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
