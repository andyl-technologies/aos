##! Exercises another A-G slice of standalone tools with offline inputs.
{testing}: let
  mkPythonToolProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryFiles ? {},
    primaryScript,
    badInput,
    badOperation,
    badExpected,
    badFiles ? {},
    badScript,
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = primaryInput;
          operation = primaryOperation;
          expected = primaryExpected;
          files = primaryFiles;
          steps = [
            {
              argv = ["@python@" "-c" primaryScript];
              exit_code = 0;
              stdout.exact = "${package} operation passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = badFiles;
          steps = [
            {
              argv = ["@python@" "-c" badScript];
              exit_code = 7;
              stdout.exact = "";
              stderr.exact = "${package} rejected invalid input\n";
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };
in {
  autogen = mkPythonToolProbe {
    package = "autogen";
    primaryInput = "An AutoGen definition and template that expand one named value.";
    primaryOperation = "Render the definition through the packaged AutoGen interpreter.";
    primaryExpected = "AutoGen expands the template to the fixed qualification line.";
    primaryFiles."probe.def" = ''
      AutoGen Definitions;
      answer = "qualified";
    '';
    primaryFiles."probe.tpl" = ''
      [+ AutoGen5 template +]
      [+ answer +]
    '';
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/autogen", "-T", "probe.tpl", "probe.def"], capture_output=True, text=True)
      assert result.returncode == 0, result.stderr
      assert result.stdout.strip() == "qualified"
      print("autogen operation passed")
    '';
    badInput = "An AutoGen definition with an unterminated aggregate value.";
    badOperation = "Render the malformed definition.";
    badExpected = "AutoGen rejects the invalid definition syntax.";
    badFiles."probe.def" = "AutoGen Definitions;\nanswer = {\n";
    badFiles."probe.tpl" = "[+ AutoGen5 template +]\n[+ answer +]\n";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/bin/autogen", "-T", "probe.tpl", "probe.def"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("autogen rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  bottom = mkPythonToolProbe {
    package = "bottom";
    primaryInput = "The packaged terminal monitor executable.";
    primaryOperation = "Request its version through the noninteractive command path.";
    primaryExpected = "Bottom identifies itself and returns success without opening the terminal UI.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/btm", "--version"], capture_output=True, text=True)
      assert result.returncode == 0 and result.stdout.startswith("bottom ")
      print("bottom operation passed")
    '';
    badInput = "A command-line option that bottom does not define.";
    badOperation = "Invoke bottom with the unknown option.";
    badExpected = "Bottom rejects the option before entering its terminal UI.";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/bin/btm", "--aos-invalid-option"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("bottom rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  bridge-utils = mkPythonToolProbe {
    package = "bridge-utils";
    primaryInput = "The host's current read-only Linux bridge inventory.";
    primaryOperation = "Query the inventory with brctl show and validate its tabular heading.";
    primaryExpected = "Brctl returns a bridge table headed by bridge name and bridge ID fields.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/sbin/brctl", "show"], capture_output=True, text=True)
      assert result.returncode == 0
      assert result.stdout.splitlines()[0].startswith("bridge name\tbridge id")
      print("bridge-utils operation passed")
    '';
    badInput = "A bridge-utils command name that does not exist.";
    badOperation = "Ask brctl to execute the unknown command.";
    badExpected = "Brctl rejects the unrecognized command.";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/sbin/brctl", "aos-invalid-command"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("bridge-utils rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  cloc = mkPythonToolProbe {
    package = "cloc";
    primaryInput = "A Python file containing one comment, one blank line, and one code line.";
    primaryOperation = "Count the file and validate cloc's CSV language totals.";
    primaryExpected = "Cloc reports one Python file with the exact blank, comment, and code counts.";
    primaryFiles."sample.py" = "# qualification comment\n\nprint('qualified')\n";
    primaryScript = ''
      import csv, subprocess
      result = subprocess.run(["@out@/bin/cloc", "--quiet", "--csv", "sample.py"], capture_output=True, text=True)
      assert result.returncode == 0
      rows = list(csv.DictReader(result.stdout.splitlines()))
      python = next(row for row in rows if row["language"] == "Python")
      assert (python["files_count"], python["blank"], python["comment"], python["code"]) == ("1", "1", "1", "1")
      print("cloc operation passed")
    '';
    badInput = "A command-line option that cloc does not define.";
    badOperation = "Run cloc with the unknown option.";
    badExpected = "Cloc rejects the unknown option with a nonzero status.";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/bin/cloc", "--aos-invalid-option"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("cloc rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  cni-plugins = mkPythonToolProbe {
    package = "cni-plugins";
    primaryInput = "A CNI VERSION request containing the current configuration version.";
    primaryOperation = "Send the request to the packaged loopback plugin and parse its response.";
    primaryExpected = "The plugin returns a supportedVersions array containing CNI 1.0.0.";
    primaryScript = ''
      import json, os, subprocess
      environment = os.environ.copy()
      environment["CNI_COMMAND"] = "VERSION"
      result = subprocess.run(
          ["@out@/bin/loopback"],
          env=environment,
          input=b'{"cniVersion":"1.0.0"}',
          capture_output=True,
      )
      assert result.returncode == 0
      response = json.loads(result.stdout)
      assert "1.0.0" in response["supportedVersions"]
      print("cni-plugins operation passed")
    '';
    badInput = "An ADD request with all runtime coordinates but no CNI configuration version.";
    badOperation = "Send the malformed request to the loopback plugin.";
    badExpected = "The plugin rejects the request and returns a structured CNI error.";
    badScript = ''
      import json, os, subprocess, sys
      environment = os.environ.copy()
      environment.update({
          "CNI_COMMAND": "ADD",
          "CNI_CONTAINERID": "qualification",
          "CNI_NETNS": "/nonexistent",
          "CNI_IFNAME": "lo",
          "CNI_PATH": "@out@/bin",
      })
      result = subprocess.run(["@out@/bin/loopback"], env=environment, input=b'{}', capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      response = json.loads(result.stdout)
      assert response["code"] != 0 and response["msg"]
      sys.stderr.write("cni-plugins rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  docker-buildx = mkPythonToolProbe {
    package = "docker-buildx";
    primaryInput = "A Docker Bake file declaring one local build target.";
    primaryOperation = "Resolve and print the bake plan without contacting a daemon.";
    primaryExpected = "Buildx returns JSON with the declared context, Dockerfile, and tag.";
    primaryFiles."docker-bake.hcl" = ''
      target "default" {
        context = "."
        dockerfile = "Containerfile"
        tags = ["example.test/qualification:latest"]
      }
    '';
    primaryFiles."Containerfile" = "FROM scratch\n";
    primaryScript = ''
      import json, subprocess
      result = subprocess.run(["@out@/bin/docker-buildx", "bake", "--file", "docker-bake.hcl", "--print"], capture_output=True, text=True)
      assert result.returncode == 0
      plan = json.loads(result.stdout)
      target = plan["target"]["default"]
      assert target["context"] == "." and target["dockerfile"] == "Containerfile"
      assert target["tags"] == ["example.test/qualification:latest"]
      print("docker-buildx operation passed")
    '';
    badInput = "A Docker Bake file with an unterminated target block.";
    badOperation = "Ask buildx to resolve the malformed bake plan.";
    badExpected = "Buildx rejects the invalid HCL before attempting a build.";
    badFiles."docker-bake.hcl" = "target \"default\" {\n  context = \".\"\n";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/bin/docker-buildx", "bake", "--file", "docker-bake.hcl", "--print"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("docker-buildx rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  docker-compose = mkPythonToolProbe {
    package = "docker-compose";
    primaryInput = "A Compose file defining one service from a fixed image.";
    primaryOperation = "Normalize the Compose model as JSON without contacting a daemon.";
    primaryExpected = "Compose emits a model containing the declared service image and command.";
    primaryFiles."compose.yaml" = ''
      services:
        worker:
          image: example.test/worker:1
          command: ["printf", "qualified"]
    '';
    primaryScript = ''
      import json, subprocess
      result = subprocess.run(["@out@/bin/docker-compose", "-f", "compose.yaml", "config", "--format", "json"], capture_output=True, text=True)
      assert result.returncode == 0
      model = json.loads(result.stdout)
      worker = model["services"]["worker"]
      assert worker["image"] == "example.test/worker:1"
      assert worker["command"] == ["printf", "qualified"]
      print("docker-compose operation passed")
    '';
    badInput = "A Compose file whose services member is a scalar.";
    badOperation = "Ask Compose to normalize the malformed model.";
    badExpected = "Compose rejects the invalid services shape without contacting a daemon.";
    badFiles."compose.yaml" = "services: invalid\n";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/bin/docker-compose", "-f", "compose.yaml", "config"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("docker-compose rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  ecj-bootstrap = mkPythonToolProbe {
    package = "ecj-bootstrap";
    primaryInput = "A Java class whose method returns the integer 42.";
    primaryOperation = "Compile the class and inspect the emitted JVM class-file header.";
    primaryExpected = "ECJ writes Answer.class with the JVM CAFEBABE magic value.";
    primaryFiles."Answer.java" = ''
      public final class Answer {
          public static int value() { return 42; }
      }
    '';
    primaryScript = ''
      import pathlib, subprocess
      result = subprocess.run(["@out@/bin/ecj", "-source", "1.5", "-target", "1.5", "Answer.java"], capture_output=True)
      assert result.returncode == 0, result.stderr
      assert pathlib.Path("Answer.class").read_bytes()[:4] == b"\xca\xfe\xba\xbe"
      print("ecj-bootstrap operation passed")
    '';
    badInput = "A Java class with a missing expression after return.";
    badOperation = "Compile the syntactically invalid class.";
    badExpected = "ECJ emits a compiler diagnostic and rejects the source.";
    badFiles."Broken.java" = "public class Broken { int value() { return ; } }\n";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/bin/ecj", "-source", "1.5", "-target", "1.5", "Broken.java"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      assert b"ERROR" in result.stdout + result.stderr
      sys.stderr.write("ecj-bootstrap rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  gtk-doc = mkPythonToolProbe {
    package = "gtk-doc";
    primaryInput = "A public C header containing one documented function declaration.";
    primaryOperation = "Scan the header and inspect gtk-doc's declaration inventory.";
    primaryExpected = "Gtk-doc records the public function in the generated declaration list.";
    primaryFiles."probe.h" = ''
      /**
       * probe_answer:
       *
       * Returns: the answer
       */
      int probe_answer(void);
    '';
    primaryScript = ''
      import pathlib, subprocess
      result = subprocess.run(["@out@/bin/gtkdoc-scan", "--module=probe", "--source-dir=."], capture_output=True)
      assert result.returncode == 0, result.stderr
      declarations = pathlib.Path("probe-decl-list.txt").read_text()
      assert "probe_answer" in declarations
      print("gtk-doc operation passed")
    '';
    badInput = "A gtkdoc-scan option that is not defined.";
    badOperation = "Invoke the scanner with the unknown option.";
    badExpected = "Gtk-doc rejects the unknown option before scanning sources.";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/bin/gtkdoc-scan", "--aos-invalid-option"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("gtk-doc rejected invalid input\n")
      raise SystemExit(7)
    '';
  };
}
