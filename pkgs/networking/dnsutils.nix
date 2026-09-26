##! dnsutils — DNS client tools from the BIND build
{
  bind,
  lib,
  withProbeOnlyPackageContract,
}:
withProbeOnlyPackageContract {
  packageName = "dnsutils";
  version = bind.version;
  packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Dig identifies its BIND implementation and returns success.";
        "files" = {};
        "input" = "The packaged DNS query client.";
        "operation" = "Request dig's linked BIND version without performing a DNS query.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/dig\", \"-v\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"DiG\" in result.stdout and \"9.20\" in result.stdout\nprint(\"dnsutils operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "dnsutils operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Dig rejects the invalid port before attempting network I/O.";
        "files" = {};
        "input" = "A DNS server port outside the valid unsigned 16-bit range.";
        "operation" = "Parse the invalid port for an otherwise offline query request.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/dig\", \"-p\", \"not-a-port\", \"example.test\"], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"dnsutils rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "dnsutils rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
  };
}
(bind.dnsutils.overrideAttrs (_: {
  platformSupport = {
    build = [{abi = ["gnu"]; os = ["linux"];}];
    host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
    target = [];
    role = "public-package";
  };
}))
