##! perl-regexp-common — Common regular expression patterns for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "2017060201";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "perl-regexp-common";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The address matches and is captured intact.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Regexp::Common qw(net);\nmy $input = \"192.0.2.25\";\ndie \"IPv4 address did not match\" unless $input =~ /\\A($RE{net}{IPv4})\\z/ && $1 eq $input;\n";
        };
        "input" = "The dotted-quad IPv4 address 192.0.2.25.";
        "operation" = "Match it with Regexp::Common's IPv4 pattern.";
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
        "expected" = "Regexp::Common rejects the invalid address.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Regexp::Common qw(net);\nmy $input = \"999.0.2.25\";\ndie \"invalid IPv4 address accepted\" if $input =~ /\\A$RE{net}{IPv4}\\z/;\n";
        };
        "input" = "The out-of-range dotted quad 999.0.2.25.";
        "operation" = "Match it with the IPv4 pattern.";
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
      urls = ["https://cpan.metacpan.org/authors/id/A/AB/ABIGAIL/Regexp-Common-${version}.tar.gz"];
      hash = "sha256-7geFOu4G8xDgQLa/GgGZoY2BiW0yGbmzXJYw0OtpCJs=";
    };
    sourceRoot = "Regexp-Common-${version}";
    module = "Regexp::Common";
    description = "Provides commonly requested regular expression patterns";
    homepage = "https://metacpan.org/dist/Regexp-Common";
    license = "MIT";
  }
