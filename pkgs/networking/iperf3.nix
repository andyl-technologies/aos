##! iperf3 — Network throughput measurement tool
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  openssl,
  lksctp-tools,
}: let
  version = "3.21";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "iperf3";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Iperf3 documents its client, server, port, and duration options.";
        "files" = {};
        "input" = "The packaged iperf3 option inventory.";
        "operation" = "Request help without opening a network connection.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/iperf3\"] + [\"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"--client\" in result.stdout and \"--server\" in result.stdout and \"--time\" in result.stdout, (result.returncode, result.stdout, result.stderr)\nprint(\"iperf3 primary passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "iperf3 primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Iperf3 rejects the unsupported option.";
        "files" = {};
        "input" = "An iperf3 invocation containing an unsupported option.";
        "operation" = "Parse the invalid option without opening a network connection.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/iperf3\"] + [\"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"unrecognized option\" in result.stderr.lower(), (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"iperf3 rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "iperf3 rejected invalid input\n";
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
      urls = ["https://downloads.es.net/pub/iperf/iperf-${version}.tar.gz"];
      hash = "sha256-ZW5EBevWIBId587KPq9DqI956huFfQQaagsTFIAazdg=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [openssl lksctp-tools];
    propagatedDeps = [];
    configureFlags = "--with-openssl=${openssl}";

    postInstall = ''ln -s iperf3 "$out/bin/iperf"'';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-iperf3";
        tool = self;
        command = "iperf3 --version";
      };
    };

    meta = {
      description = "Measures TCP, UDP, and SCTP network throughput";
      homepage = "https://software.es.net/iperf/";
      license = "BSD-3-Clause";
      mainProgram = "iperf3";
    };
  }
