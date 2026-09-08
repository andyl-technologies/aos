##! Exercises additional A-G build, debug, and configuration tools offline.
{testing}: let
  mkAntProbe = package:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = "An Ant project whose default target writes a fixed result file.";
          operation = "Execute the project with the packaged Ant launcher.";
          expected = "Ant runs the declared target and creates the exact artifact.";
          files."build.xml" = ''
            <project name="qualification" default="qualify">
              <target name="qualify">
                <echo file="result.txt" message="ant result&#10;"/>
              </target>
            </project>
          '';
          steps = [
            {
              argv = ["@out@/bin/ant" "-f" "build.xml" "qualify"];
              exit_code = 0;
            }
          ];
          artifacts = [
            {
              path = "result.txt";
              text = "ant result\n";
            }
          ];
        };
        bad_input = {
          input = "An Ant project containing a task name that is not defined.";
          operation = "Execute the target containing the unknown task.";
          expected = "Ant rejects the build file with status 1.";
          files."build.xml" = ''
            <project name="qualification" default="broken">
              <target name="broken">
                <aos-unknown-task/>
              </target>
            </project>
          '';
          steps = [
            {
              argv = ["@out@/bin/ant" "-f" "build.xml" "broken"];
              exit_code = 1;
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };
in {
  ant = mkAntProbe "ant";
  ant-bootstrap = mkAntProbe "ant-bootstrap";

  cython = testing.mkQualificationPackageProbe {
    name = "cython";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "cython";
      primary = {
        input = "A typed Cython function adding two C integers.";
        operation = "Translate the module to C and inspect its generated initialization entry point.";
        expected = "Cython emits a C extension implementation for the declared module.";
        files."probe.pyx" = ''
          cpdef int add(int left, int right):
              return left + right
        '';
        steps = [
          {
            argv = ["@out@/bin/cython" "--3str" "--output-file" "probe.c" "probe.pyx"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@python@" "-c" "from pathlib import Path; source = Path('probe.c').read_text(); assert 'PyInit_probe' in source; print('cython generation passed')"];
            exit_code = 0;
            stdout.exact = "cython generation passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A Cython function declaration with a missing parameter name.";
        operation = "Translate the malformed module to C.";
        expected = "Cython rejects the syntax error with status 1.";
        files."invalid.pyx" = "cpdef int broken(int):\n    return 42\n";
        steps = [
          {
            argv = ["@out@/bin/cython" "--3str" "--output-file" "invalid.c" "invalid.pyx"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  direnv = testing.mkQualificationPackageProbe {
    name = "direnv";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "direnv";
      primary = {
        input = "An approved .envrc exporting a fixed variable.";
        operation = "Approve the file, load it with direnv exec, and read the exported value.";
        expected = "Direnv executes the child with the exact declared environment value.";
        files.".envrc" = "export AOS_PROBE_VALUE=qualified\n";
        steps = [
          {
            argv = ["@out@/bin/direnv" "allow" "."];
            exit_code = 0;
          }
          {
            argv = ["@out@/bin/direnv" "exec" "." "@bash@" "-c" ''printf "%s\n" "$AOS_PROBE_VALUE"''];
            exit_code = 0;
            stdout.exact = "qualified\n";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A valid .envrc that has not been explicitly approved.";
        operation = "Attempt to load the unapproved environment with direnv exec.";
        expected = "Direnv enforces its trust boundary and rejects the file with status 1.";
        files.".envrc" = "export AOS_PROBE_VALUE=unapproved\n";
        steps = [
          {
            argv = ["@out@/bin/direnv" "exec" "." "@bash@" "-c" "true"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  envoy = testing.mkQualificationPackageProbe {
    name = "envoy";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "envoy";
      primary = {
        input = "An Envoy bootstrap configuration with empty static listener and cluster sets.";
        operation = "Validate the bootstrap configuration without starting the proxy.";
        expected = "Envoy accepts the complete offline configuration.";
        files."envoy.yaml" = ''
          static_resources:
            listeners: []
            clusters: []
        '';
        steps = [
          {
            argv = ["@out@/bin/envoy" "--mode" "validate" "--config-path" "envoy.yaml"];
            exit_code = 0;
            timeout_seconds = 120;
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "An Envoy bootstrap with an unknown top-level field.";
        operation = "Validate the malformed bootstrap configuration.";
        expected = "Envoy rejects the unknown field with status 1.";
        files."invalid.yaml" = "aos_unknown_field: 42\n";
        steps = [
          {
            argv = ["@out@/bin/envoy" "--mode" "validate" "--config-path" "invalid.yaml"];
            exit_code = 1;
            observes_rejection = true;
            timeout_seconds = 120;
          }
        ];
        artifacts = [];
      };
    };
  };

  fakeroot = testing.mkQualificationPackageProbe {
    name = "fakeroot";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "fakeroot";
      primary = {
        input = "A child process creating a file and assigning simulated root ownership.";
        operation = "Run the process under fakeroot and inspect the intercepted metadata.";
        expected = "The child observes UID and GID zero without privileged filesystem operations.";
        files = {};
        steps = [
          {
            argv = [
              "@out@/bin/fakeroot"
              "@python@"
              "-c"
              "import os; open('owned', 'w').close(); os.chown('owned', 0, 0); info = os.stat('owned'); print(f'{info.st_uid}:{info.st_gid}')"
            ];
            exit_code = 0;
            stdout.exact = "0:0\n";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A command-line option that fakeroot does not define.";
        operation = "Invoke the wrapper with the invalid option.";
        expected = "Fakeroot rejects the option with status 1.";
        files = {};
        steps = [
          {
            argv = ["@out@/bin/fakeroot" "--aos-invalid-option"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  gdb = testing.mkQualificationPackageProbe {
    name = "gdb";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "gdb";
      primary = {
        input = "A debug executable containing a global integer symbol.";
        operation = "Load its symbols with GDB and print the global value.";
        expected = "GDB decodes the debug object and emits the exact integer value.";
        files."program.c" = ''
          int qualification_value = 42;
          int main(void) { return 0; }
        '';
        steps = [
          {
            argv = ["@cc@" "-g" "program.c" "-o" "program"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/gdb" "--batch" "--quiet" "-ex" "file program" "-ex" "print qualification_value"];
            exit_code = 0;
            stdout.exact = "$1 = 42\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A text file that is not an executable or object file.";
        operation = "Load the malformed object with GDB's file command.";
        expected = "GDB rejects the file format with status 1.";
        files."invalid" = "not an executable\n";
        steps = [
          {
            argv = ["@out@/bin/gdb" "--batch" "--quiet" "-ex" "file invalid"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  gobject-introspection = testing.mkQualificationPackageProbe {
    name = "gobject-introspection";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "gobject-introspection";
      primary = {
        input = "A GIR repository declaring one namespace and record type.";
        operation = "Compile the XML repository to a binary typelib.";
        expected = "G-ir-compiler accepts the schema and writes the typelib representation.";
        files."Probe-1.0.gir" = ''
          <?xml version="1.0"?>
          <repository version="1.2"
              xmlns="http://www.gtk.org/introspection/core/1.0"
              xmlns:c="http://www.gtk.org/introspection/c/1.0">
            <namespace name="Probe" version="1.0" c:identifier-prefixes="Probe">
              <record name="Point" c:type="ProbePoint">
                <field name="x"><type name="gint" c:type="int"/></field>
              </record>
            </namespace>
          </repository>
        '';
        steps = [
          {
            argv = ["@out@/bin/g-ir-compiler" "--output=Probe-1.0.typelib" "Probe-1.0.gir"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A GIR document whose namespace element is not closed.";
        operation = "Compile the malformed XML repository.";
        expected = "G-ir-compiler rejects the document with status 1.";
        files."invalid.gir" = ''
          <repository version="1.2" xmlns="http://www.gtk.org/introspection/core/1.0">
            <namespace name="Probe" version="1.0">
          </repository>
        '';
        steps = [
          {
            argv = ["@out@/bin/g-ir-compiler" "--output=invalid.typelib" "invalid.gir"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  gptfdisk = testing.mkQualificationPackageProbe {
    name = "gptfdisk";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "gptfdisk";
      primary = {
        input = "A sparse 8 MiB disk image.";
        operation = "Create a GPT with one Linux partition and verify both tables.";
        expected = "Sgdisk writes and validates the primary and backup GPT metadata.";
        files = {};
        steps = [
          {
            argv = ["@python@" "-c" "with open('disk.img', 'wb') as disk: disk.truncate(8 * 1024 * 1024)"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/sgdisk" "--clear" "--new=1:2048:-2048" "--typecode=1:8300" "disk.img"];
            exit_code = 0;
          }
          {
            argv = ["@out@/bin/sgdisk" "--verify" "disk.img"];
            exit_code = 0;
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A one-sector disk image, too small to hold GPT headers and entries.";
        operation = "Create a new GPT on the undersized image.";
        expected = "Sgdisk rejects the geometry with status 4.";
        files = {};
        steps = [
          {
            argv = ["@python@" "-c" "with open('tiny.img', 'wb') as disk: disk.truncate(512)"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/sgdisk" "--clear" "tiny.img"];
            exit_code = 4;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
