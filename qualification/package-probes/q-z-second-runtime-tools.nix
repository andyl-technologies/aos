##! Exercises additional Q-through-Z runtime tools and archive APIs offline.
{testing}: {
  soelim = testing.mkQualificationPackageProbe {
    name = "soelim";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "soelim";
      primary = {
        input = "A roff document that includes a second local source file.";
        operation = "Expand the .so request through GNU soelim.";
        expected = "Soelim replaces the include request with the referenced file's exact contents.";
        files = {
          "answer.roff" = "answer=42\n";
          "document.roff" = ".so answer.roff\n";
        };
        steps = [
          {
            argv = ["@out@/bin/soelim" "document.roff"];
            exit_code = 0;
            stdout.exact = "answer=42\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A roff include request naming a file that does not exist.";
        operation = "Resolve the missing include through GNU soelim.";
        expected = "Soelim rejects the unresolved include with a failure status.";
        files."document.roff" = ".so missing.roff\n";
        steps = [
          {
            argv = ["@out@/bin/soelim" "document.roff"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  strace = testing.mkQualificationPackageProbe {
    name = "strace";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "strace";
      primary = {
        input = "A child shell that exits successfully without other work.";
        operation = "Trace only the child's exit_group system call into a local trace file.";
        expected = "Strace records the successful exit_group call.";
        files."verify.py" = ''
          trace = open("trace.log", encoding="utf-8").read()
          assert "exit_group(0)" in trace
          print("strace observation passed")
        '';
        steps = [
          {
            argv = ["@out@/bin/strace" "-qq" "-e" "trace=exit_group" "-o" "trace.log" "@bash@" "-c" "exit 0"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@python@" "verify.py"];
            exit_code = 0;
            stdout.exact = "strace observation passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A syscall filter naming a syscall that does not exist.";
        operation = "Parse the invalid trace expression.";
        expected = "Strace rejects the unknown syscall before starting the child.";
        files = {};
        steps = [
          {
            argv = ["@out@/bin/strace" "-e" "trace=qualification_missing_syscall" "@bash@" "-c" "exit 0"];
            exit_code = 1;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  tini = testing.mkQualificationPackageProbe {
    name = "tini";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "tini";
      primary = {
        input = "A child shell that prints one fixed line.";
        operation = "Run the child under Tini in subreaper mode.";
        expected = "Tini supervises the child and preserves its output and successful status.";
        files = {};
        steps = [
          {
            argv = ["@out@/bin/tini" "-s" "--" "@bash@" "-c" "printf 'answer=42\\n'"];
            exit_code = 0;
            stdout.exact = "answer=42\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "An absolute child path that does not exist.";
        operation = "Ask Tini to spawn the missing child.";
        expected = "Tini reports the spawn failure through status 127.";
        files = {};
        steps = [
          {
            argv = ["@out@/bin/tini" "-s" "--" "/qualification/missing-child"];
            exit_code = 127;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  wheel = testing.mkQualificationPackageProbe {
    name = "wheel";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "wheel";
      primary = {
        input = "A Python module payload written through WheelFile.";
        operation = "Create a wheel archive through the packaged API, reopen it, and read the module bytes.";
        expected = "WheelFile preserves the member bytes and emits the wheel RECORD metadata.";
        files."probe.py" = ''
          import glob
          import sys

          locations = glob.glob("@out@/lib/python*/site-packages")
          assert len(locations) == 1
          sys.path.insert(0, locations[0])

          from wheel.wheelfile import WheelFile

          wheel_path = "answer-1.0-py3-none-any.whl"
          with WheelFile(wheel_path, "w") as archive:
              archive.writestr("answer/__init__.py", b"VALUE = 42\n")
          with WheelFile(wheel_path) as archive:
              assert archive.read("answer/__init__.py") == b"VALUE = 42\n"
              assert "answer-1.0.dist-info/RECORD" in archive.namelist()
          print("wheel archive passed")
        '';
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 0;
            stdout.exact = "wheel archive passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A wheel-shaped filename containing plain text rather than a ZIP archive.";
        operation = "Open the malformed archive through WheelFile.";
        expected = "WheelFile propagates BadZipFile for the invalid container.";
        files = {
          "broken-1.0-py3-none-any.whl" = "not a wheel archive\n";
          "probe.py" = ''
            import glob
            import sys
            import zipfile

            locations = glob.glob("@out@/lib/python*/site-packages")
            assert len(locations) == 1
            sys.path.insert(0, locations[0])

            from wheel.wheelfile import WheelFile

            try:
                WheelFile("broken-1.0-py3-none-any.whl")
            except zipfile.BadZipFile:
                print("wheel rejected invalid archive")
            else:
                raise RuntimeError("WheelFile accepted an invalid archive")
          '';
        };
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 0;
            stdout.exact = "wheel rejected invalid archive\n";
            stderr.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
