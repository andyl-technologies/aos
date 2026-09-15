##! workerd — Cloudflare's Workers runtime built from source.
##!
##! The public package name retains a small target-native launcher output while
##! `workerd-source` owns the Bazel build. Keeping the names separate preserves
##! existing package references and exposes the complete source build as an
##! independently auditable release artifact.
{
  lib,
  mkDerivation,
  workerd-source,
}:
mkDerivation {
  pname = "workerd";
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "The Worker computes and returns the JSON result 42 with HTTP status 200.";
      "files" = {
        "worker.capnp" = "using Workerd = import \"/workerd/workerd.capnp\";\nconst config :Workerd.Config = (\n  services = [(name = \"main\", worker = (\n    modules = [(name = \"worker\", esModule = embed \"worker.js\")],\n    compatibilityDate = \"2024-09-09\"\n  ))],\n  sockets = [(name = \"http\", http = (), service = \"main\")]\n);\n";
        "worker.js" = "export default {\n  async fetch(request) {\n    const result = Number(await request.text()) + 2;\n    return new Response(JSON.stringify({ result }), {\n      headers: { \"content-type\": \"application/json\" }\n    });\n  }\n};\n";
      };
      "input" = "A local Worker module and an HTTP POST containing the number 40.";
      "operation" = "Start the runtime on an inherited loopback socket, execute the Worker through HTTP, and stop the service.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import http.client, json, socket, subprocess, tempfile, time\n\nwith socket.socket() as listener, tempfile.TemporaryFile() as log:\n    listener.bind((\"127.0.0.1\", 0))\n    listener.listen()\n    port = listener.getsockname()[1]\n    command = [\"@out@/bin/workerd\", \"serve\", \"worker.capnp\",\n               \"--socket-fd\", f\"http={listener.fileno()}\"]\n    process = subprocess.Popen(command, pass_fds=(listener.fileno(),),\n                               stdout=log, stderr=log)\n    try:\n        deadline = time.monotonic() + 20\n        while True:\n            if process.poll() is not None or time.monotonic() >= deadline:\n                log.seek(0)\n                raise AssertionError(log.read().decode(errors=\"replace\"))\n\n            connection = http.client.HTTPConnection(\"127.0.0.1\", port, timeout=2)\n            try:\n                connection.request(\"POST\", \"/qualification\", body=\"40\")\n                response = connection.getresponse()\n                body = response.read()\n                assert response.status == 200, (response.status, body)\n                assert response.getheader(\"content-type\") == \"application/json\"\n                assert json.loads(body) == {\"result\": 42}, body\n                break\n            except (OSError, http.client.HTTPException):\n                time.sleep(0.1)\n            finally:\n                connection.close()\n    finally:\n        process.terminate()\n        try:\n            process.wait(timeout=10)\n        except subprocess.TimeoutExpired:\n            process.kill()\n            process.wait(timeout=5)\n\nprint(\"workerd operation passed\")\n"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "workerd operation passed\n";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "Workerd rejects the malformed configuration with a parse error.";
      "files" = {
        "invalid.capnp" = "this is not capnp\n";
      };
      "input" = "A service configuration containing bytes that are not valid Cap'n Proto source.";
      "operation" = "Parse the malformed configuration before starting the runtime.";
      "steps" = [
        {
          "argv" = [
            "@python@"
            "-c"
            "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/workerd\", \"serve\", \"invalid.capnp\"], capture_output=True, text=True, timeout=10)\noutput = result.stdout + result.stderr\nassert result.returncode != 0 and (\"error\" in output.lower() or \"failed\" in output.lower())\n\nsys.stderr.write(\"workerd rejected invalid input\\n\")\nraise SystemExit(7)\n"
          ];
          "exit_code" = 7;
          "observes_rejection" = true;
          "stderr" = {
            "exact" = "workerd rejected invalid input\n";
          };
          "stdout" = {
            "exact" = "";
          };
        }
      ];
    };
  };

  version = workerd-source.version;
  src = null;

  buildDeps = [];
  runtimeDeps = [workerd-source];
  propagatedDeps = [];

  passthru.evidenceSources = workerd-source.passthru.evidenceSources;
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        ln -s "${workerd-source}/bin/workerd" "$out/bin/workerd"
      '';
    }
  ];

  meta = {
    description = "Cloudflare workerd Workers runtime built from source with AOS tools";
    homepage = "https://github.com/cloudflare/workerd";
    license = "Apache-2.0";
  };

  checks = {
    testing,
    self,
    pkgs,
  }: {
    version = testing.mkVMTest {
      name = "tools-workerd-version";
      rootfsDeps = [self];
      testScript = ''
        OUTPUT=$(workerd --version 2>&1)
        case "$OUTPUT" in
          *"2024-09-09"*)
            echo "==> workerd version: PASS ($OUTPUT)"
            ;;
          *)
            echo "==> ERROR: unexpected workerd version: $OUTPUT" >&2
            exit 1
            ;;
        esac
      '';
    };
  };
}
