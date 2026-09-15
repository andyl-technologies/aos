##! aos-agent-rpc — Single-shot RPC client for the AOS VM test agent
{lib, mkDerivation}:
mkDerivation {
  pname = "aos-agent-rpc";
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "The client sends the exact command and prints the server's framed JSON response.";
      "files" = {};
      "input" = "A local Unix socket server and a fixed command frame.";
      "operation" = "Exchange a length-prefixed request and JSON response with the RPC client.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import json, pathlib, socket, subprocess, threading\npath = str(pathlib.Path(\"agent.sock\").resolve())\nserver = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\nserver.bind(path)\nserver.listen(1)\nobserved = []\ndef serve():\n    connection, _ = server.accept()\n    with connection:\n        length = b\"\"\n        while not length.endswith(b\"\\n\"):\n            length += connection.recv(1)\n        body = connection.recv(int(length))\n        observed.append(body)\n        response = b'{\"exit_code\":0,\"stdout\":\"cXVhbGlmaWVkXG4=\",\"stderr\":\"\"}'\n        connection.sendall(str(len(response)).encode() + b\"\\n\" + response)\nthread = threading.Thread(target=serve)\nthread.start()\nresult = subprocess.run([\"@out@/bin/aos-agent-rpc\", \"--driver\", \"qemu\", path, \"printf qualified\"], capture_output=True, text=True)\nthread.join()\nserver.close()\nassert result.returncode == 0 and json.loads(result.stdout)[\"exit_code\"] == 0\nassert observed == [b\"printf qualified\"]\nprint(\"aos-agent-rpc operation passed\")\n"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "aos-agent-rpc operation passed\n";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "The client rejects the unsupported driver with its command-line error status.";
      "files" = {};
      "input" = "An RPC request naming an unsupported transport driver.";
      "operation" = "Parse the invalid driver before opening a socket.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/aos-agent-rpc\", \"--driver\", \"invalid\", \"agent.sock\", \"true\"], capture_output=True, text=True)\nassert result.returncode == 2 and \"unknown driver\" in result.stderr, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"aos-agent-rpc rejected invalid input\\n\")\nraise SystemExit(7)\n"
          ];
          "exit_code" = 7;
          "observes_rejection" = true;
          "stderr" = {
            "exact" = "aos-agent-rpc rejected invalid input\n";
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

  phases = [
    {
      name = "build";
      script = ''
        mkdir -p $out/bin
        $CC -O2 -Wall -Wextra -o $out/bin/aos-agent-rpc ${./aos-agent-rpc.c}
      '';
    }
  ];

  passthru.evidenceSources = [
    ./aos-agent-rpc.nix
    ./aos-agent-rpc.c
  ];

  meta = {
    description = "Single-shot RPC client for the AOS VM test agent";
    license = "Apache-2.0";
  };
}
