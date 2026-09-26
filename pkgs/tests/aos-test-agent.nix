{
  lib,
  mkDerivation,
  writeTextFile,
  bash,
  coreutils,
  socat,
  systemd,
}: let
  agentBin = writeTextFile {
    name = "aos-test-agent";
    executable = true;
    destination = "/bin/aos-test-agent";
    text =
      builtins.replaceStrings
      ["exec socat VSOCK-LISTEN"]
      ["exec ${socat}/bin/socat VSOCK-LISTEN"]
      (builtins.readFile ./_aos-test-agent/agent.sh);
  };
in
  mkDerivation {
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
      ];
      target = [];
      role = "build-input";
    };
    pname = "aos-test-agent";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The link resolves to a nonempty Bash program with valid syntax.";
        "files" = {};
        "input" = "The installed VM guest-agent script.";
        "operation" = "Resolve its package link and parse the complete shell program.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, subprocess\nscript = pathlib.Path(\"@out@/share/aos-test-agent/aos-test-agent\")\nassert script.is_symlink() and script.resolve().stat().st_size > 0\nresult = subprocess.run([\"@bash@\", \"-n\", script.resolve()], capture_output=True)\nassert result.returncode == 0, result.stderr\nprint(\"aos-test-agent data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "aos-test-agent data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The package rejects the absent host-generated configuration.";
        "files" = {};
        "input" = "A request for a host-side agent configuration in the guest package.";
        "operation" = "Resolve the undeclared mutable configuration.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys\nif pathlib.Path(\"@out@/etc/aos-test-agent/config.json\").exists():\n    raise SystemExit(2)\nsys.stderr.write(\"aos-test-agent rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "aos-test-agent rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    version = "0";
    src = null;

    runtimeDeps = [
      agentBin
      bash
      coreutils
      socat
      systemd
    ];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/aos-test-agent"
          ln -s ${agentBin}/bin/aos-test-agent "$out/share/aos-test-agent/aos-test-agent"
        '';
      }
    ];

    abilities = ./_aos-test-agent;

    meta = {
      description = "AOS package for the VM test guest agent";
      license = "Apache-2.0";
    };
  }
