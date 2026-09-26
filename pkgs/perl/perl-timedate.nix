##! perl-timedate — Date and time parsing modules for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "2.33";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "perl-timedate";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Date::Parse returns Unix epoch 784111777.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Date::Parse qw(str2time);\ndie \"wrong parsed timestamp\" unless str2time(\"1994-11-06 08:49:37 GMT\") == 784111777;\n";
        };
        "input" = "The UTC timestamp 1994-11-06 08:49:37 GMT.";
        "operation" = "Parse the timestamp through Date::Parse.";
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
        "expected" = "Date::Parse returns no timestamp.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Date::Parse qw(str2time);\ndie \"invalid timestamp accepted\" if defined str2time(\"qualification-invalid-date\");\n";
        };
        "input" = "A string with no recognizable date fields.";
        "operation" = "Parse the malformed timestamp through Date::Parse.";
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
      urls = ["https://cpan.metacpan.org/authors/id/A/AT/ATOOMIC/TimeDate-${version}.tar.gz"];
      hash = "sha256-wLacSwOd5vUBsNnxPsWMhrBAwffpsn7ySWUcFD1gXrI=";
    };
    sourceRoot = "TimeDate-${version}";
    module = "Date::Parse";
    description = "Date and time parsing modules for Perl";
    homepage = "https://metacpan.org/dist/TimeDate";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
