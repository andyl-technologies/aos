##! hdparm — Get/set SATA/IDE device parameters
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "9.65";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "hdparm";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The command returns success and documents its invocation contract.";
        "files" = {};
        "input" = "The packaged hdparm command-line interface.";
        "operation" = "Request its offline help text.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/sbin/hdparm\", \"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"usage\" in (result.stdout + result.stderr).lower(), (result.returncode, result.stdout, result.stderr)\nprint(\"hdparm operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "hdparm operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The command rejects the unsupported option before performing external I/O.";
        "files" = {};
        "input" = "A hdparm invocation containing an unsupported option.";
        "operation" = "Parse the invalid option without accessing a device or service.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/sbin/hdparm\", \"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"hdparm rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "hdparm rejected invalid input\n";
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
      urls = [
        "https://sourceforge.net/projects/hdparm/files/hdparm/hdparm-${version}.tar.gz"
      ];
      hash = "sha256-0Ukp+RDQYJMucX6TgkJdR8LnFEI1pTcT1VqU995TWks=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd hdparm-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install prefix=$out sbindir=$out/sbin bindir=$out/bin mandir=$out/share/man
        '';
      }
    ];

    meta = {
      description = "Get/set SATA/IDE device parameters";
      homepage = "https://sourceforge.net/projects/hdparm/";
      license = "BSD";
    };
  }
