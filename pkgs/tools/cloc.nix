##! cloc — Source code line counter
{
  lib,
  mkDerivation,
  fetchurl,
  perl,
  perl-algorithm-diff,
  perl-class-method-modifiers,
  perl-module-runtime,
  perl-moo,
  perl-parallel-forkmanager,
  perl-regexp-common,
  perl-role-tiny,
  perl-sub-quote,
}: let
  version = "2.10";
  modules = [
    perl-algorithm-diff
    perl-class-method-modifiers
    perl-module-runtime
    perl-moo
    perl-parallel-forkmanager
    perl-regexp-common
    perl-role-tiny
    perl-sub-quote
  ];
  modulePath = builtins.concatStringsSep " " (map (module: "${module}/lib/perl5") modules);
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "cloc";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Cloc reports one Python file with the exact blank, comment, and code counts.";
        "files" = {
          "sample.py" = "# qualification comment\n\nprint('qualified')\n";
        };
        "input" = "A Python file containing one comment, one blank line, and one code line.";
        "operation" = "Count the file and validate cloc's CSV language totals.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import csv, subprocess\nresult = subprocess.run([\"@out@/bin/cloc\", \"--quiet\", \"--csv\", \"sample.py\"], capture_output=True, text=True)\nassert result.returncode == 0\nrows = list(csv.DictReader(result.stdout.splitlines()))\npython = next(row for row in rows if row[\"language\"] == \"Python\")\nassert (python[\"files_count\"], python[\"blank\"], python[\"comment\"], python[\"code\"]) == (\"1\", \"1\", \"1\", \"1\")\nprint(\"cloc operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "cloc operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Cloc rejects the unknown option with a nonzero status.";
        "files" = {};
        "input" = "A command-line option that cloc does not define.";
        "operation" = "Run cloc with the unknown option.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/cloc\", \"--aos-invalid-option\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"cloc rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "cloc rejected invalid input\n";
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
      urls = ["https://github.com/AlDanial/cloc/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-qPrDX0z0Jyh2VYC6Ea/CVorSBVCaIiBGY/UmFpVIQ20=";
    };
    buildDeps = [];
    runtimeDeps = [perl] ++ modules;
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd cloc-${version}/Unix
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/man/man1"
          sed -i \
            -e "1s|^#!.*|#!${perl}/bin/perl|" \
            -e "2i use lib qw(${modulePath});" \
            cloc
          install -m 0755 cloc "$out/bin/cloc"
          ${perl}/bin/pod2man --section=1 --release='cloc ${version}' cloc.1.pod cloc.1
          install -m 0644 cloc.1 "$out/share/man/man1/cloc.1"

          "$out/bin/cloc" --version | grep -qx '${version}'
          printf 'fn main() {}\n' > example.rs
          "$out/bin/cloc" --quiet --csv example.rs | grep -q ',Rust,'
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-cloc";
        tool = self;
        command = "cloc --version | grep -qx '${version}'";
      };
    };
    meta = {
      description = "Counts blank lines, comment lines, and physical source lines";
      homepage = "https://github.com/AlDanial/cloc";
      license = "GPL-2.0-or-later";
      mainProgram = "cloc";
    };
  }
