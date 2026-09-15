##! GNU parallel — Parallel shell job runner
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
  procps-ng,
  coreutils,
  gawk,
}: let
  version = "20260822";
in
  mkDerivation {
    pname = "parallel";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Parallel preserves input order and prints both exact results.";
        "files" = {
          "emit.sh" = "printf 'answer=%s\\n' \"$1\"\n";
        };
        "input" = "The ordered values 1 and 2 supplied as standard input.";
        "operation" = "Run one formatting job per value through GNU Parallel.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/parallel"
              "--keep-order"
              "@bash@"
              "emit.sh"
              "{}"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdin" = "1\n2\n";
            "stdout" = {
              "exact" = "answer=1\nanswer=2\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Parallel rejects the missing file with status 255.";
        "files" = {};
        "input" = "A pipe-part input pathname that does not exist.";
        "operation" = "Open the missing input through GNU Parallel's pipe-part mode.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/parallel"
              "--pipepart"
              "-a"
              "missing-qualification-file"
              "@bash@"
              "emit.sh"
              "{}"
            ];
            "exit_code" = 255;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://ftpmirror.gnu.org/parallel/parallel-${version}.tar.bz2"];
      hash = "sha256-HTinJYeWAVqSpabu4pM0C5JOT/aOTo6EW4vbtfT32eg=";
    };

    buildDeps = [gnumake perl];
    runtimeDeps = [perl procps-ng coreutils gawk];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd parallel-${version}
        '';
      }
      {
        name = "configure";
        script = ''./configure $configureFlags --prefix="$out"'';
      }
      {
        name = "build";
        script = ''make SHELL="$CONFIG_SHELL" -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          for program in parallel sql niceload parcat parset parsort; do
            sed -i "1s|^#!.*|#!${perl}/bin/perl|" "src/$program"
          done
          make SHELL="$CONFIG_SHELL" install
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-parallel";
        tool = self;
        command = "parallel --version";
      };
    };

    meta = {
      description = "Executes shell jobs in parallel";
      homepage = "https://www.gnu.org/software/parallel/";
      license = "GPL-3.0-or-later";
      mainProgram = "parallel";
    };
  }
