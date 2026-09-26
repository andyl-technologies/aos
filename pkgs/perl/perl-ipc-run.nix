##! perl-ipc-run — Subprocess and pipeline management for Perl
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
  perl-io-tty,
  perl-readonly,
}: let
  version = "20231003.0";
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
    pname = "perl-ipc-run";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "IPC::Run reports success and captures the exact line.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use IPC::Run qw(run);\nmy $output = \"\";\nmy $ok = run([$^X, \"-e\", q{print \"qualified\\n\"}], \">\", \\$output);\ndie \"child failed\" unless $ok && $output eq \"qualified\\n\";\n";
        };
        "input" = "A child Perl command that emits one fixed line.";
        "operation" = "Run the command and capture its standard output with IPC::Run.";
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
        "expected" = "IPC::Run rejects the missing executable.";
        "files" = {
          "probe.pl" = "use strict; use warnings; use IPC::Run qw(run);\neval { run([\"qualification-command-does-not-exist\"]) };\ndie \"missing executable accepted\" unless $@;\n";
        };
        "input" = "A child executable name absent from the imported closure.";
        "operation" = "Start the nonexistent command through IPC::Run.";
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
      urls = ["https://cpan.metacpan.org/authors/id/T/TO/TODDR/IPC-Run-${version}.tar.gz"];
      hash = "sha256-6yW731kT0pF5fvG/6ZjxUTC0VdPtAqrN5oVvCyXk/lc=";
    };
    sourceRoot = "IPC-Run-${version}";
    module = "IPC::Run";
    dependencies = [perl-io-tty perl-readonly];
    description = "Runs subprocesses and pipelines with redirection and pseudo-terminals";
    homepage = "https://metacpan.org/dist/IPC-Run";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
