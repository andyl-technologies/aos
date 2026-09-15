##! numad — Automatic NUMA placement daemon
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "0.5+20150602";
in
  mkDerivation {
    pname = "numad";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Numad documents its interval, logging, and process-placement options.";
        "files" = {};
        "input" = "The packaged NUMA placement daemon's option inventory.";
        "operation" = "Request usage without starting the daemon.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/numad\"] + [\"-h\"], capture_output=True, text=True)\nassert result.returncode == 1 and \"usage:\" in result.stderr.lower() and \"-i\" in result.stderr and \"-p\" in result.stderr, (result.returncode, result.stdout, result.stderr)\nprint(\"numad primary passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "numad primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Numad rejects the unsupported option.";
        "files" = {};
        "input" = "A numad invocation containing an unsupported long option.";
        "operation" = "Parse the invalid option without starting the daemon.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/numad\"] + [\"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"invalid option\" in result.stderr.lower(), (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"numad rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "numad rejected invalid input\n";
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
      urls = ["https://deb.debian.org/debian/pool/main/n/numad/numad_0.5+20150602.orig.tar.gz"];
      hash = "sha256-Nb/5CIjfn3kXUjz+KXhev5jCKq2Ug34tfu5w6Yfb88I=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd numad-${version}
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install prefix="$out"
          "$out/bin/numad" -V | grep -q '${version}'
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-numad";
        tool = self;
        command = "numad -V";
      };
    };

    meta = {
      description = "Monitors NUMA topology and places workloads for local memory access";
      homepage = "https://pagure.io/numad";
      license = "LGPL-2.1-only";
      mainProgram = "numad";
    };
  }
