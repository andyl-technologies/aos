##! perl-time-duration — English expressions of time durations
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "1.21";
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
    pname = "perl-time-duration";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The module reports one hour, one minute, and one second.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Time::Duration qw(duration_exact);\nmy $rendered = duration_exact(3661);\ndie \"wrong duration\" unless $rendered eq \"1 hour, 1 minute, and 1 second\";\n";
        };
        "input" = "An exact duration of 3661 seconds.";
        "operation" = "Render the duration through Time::Duration.";
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
        "expected" = "Time::Duration rejects the nonnumeric duration.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use Time::Duration qw(duration_exact);\nlocal $SIG{__WARN__} = sub { die @_ };\neval { duration_exact(\"qualification-invalid\") };\ndie \"nonnumeric duration accepted\" unless $@;\n";
        };
        "input" = "A duration value containing no numeric representation.";
        "operation" = "Render the malformed value while treating numeric warnings as rejection.";
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
      urls = ["https://cpan.metacpan.org/authors/id/N/NE/NEILB/Time-Duration-${version}.tar.gz"];
      hash = "sha256-/jQOuodl+SY2lGdOXf8UgzRD4Zhl5f9Ce715t7X4qbg=";
    };
    sourceRoot = "Time-Duration-${version}";
    module = "Time::Duration";
    description = "Formats time durations as rounded or exact English text";
    homepage = "https://metacpan.org/dist/Time-Duration";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
