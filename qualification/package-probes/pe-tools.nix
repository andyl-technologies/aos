##! Exercises the isolated runtime section inspector on a real target binary.
{testing}: {
  pe-tools = testing.mkQualificationPackageProbe {
    name = "pe-tools";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "pe-tools";
      primary = {
        input = "The target-hosted objcopy executable's nonempty text section.";
        operation = "Extract its text section into a raw binary file.";
        expected = "The runtime inspector executes and returns section bytes.";
        files = {};
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import pathlib
                import subprocess

                executable = "@out@/bin/objcopy"
                subprocess.run([
                    executable, "-O", "binary", "--only-section=.text",
                    executable, "text.bin",
                ], check=True, capture_output=True)
                assert pathlib.Path("text.bin").stat().st_size > 0
                print("pe-tools section extraction passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "pe-tools section extraction passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A text file that is not an executable object.";
        operation = "Attempt to extract a section from the malformed input.";
        expected = "The inspector rejects the unrecognized object format.";
        files."invalid.bin" = "not an executable object\n";
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import subprocess
                import sys

                result = subprocess.run([
                    "@out@/bin/objcopy", "-O", "binary", "--only-section=.text",
                    "invalid.bin", "invalid-output.bin",
                ], capture_output=True)
                assert result.returncode != 0
                assert b"file format not recognized" in result.stderr
                sys.stderr.write("pe-tools rejected invalid object\n")
                raise SystemExit(7)
              ''
            ];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "pe-tools rejected invalid object\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
