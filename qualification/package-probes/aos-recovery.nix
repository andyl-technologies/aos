##! Verifies the recovery executable identity before its image-bound exercise.
{testing}: {
  aos-recovery = testing.mkQualificationPackageProbe {
    name = "aos-recovery";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "aos-recovery";
      primary = {
        input = "The staged recovery executable.";
        operation = "Verify its executable format and bounded console identity.";
        expected = "The package contains the recovery console executable used by the boot scenario.";
        files = {};
        steps = [{
          argv = [
            "@python@"
            "-c"
            ''
              import pathlib
              binary = pathlib.Path("@out@/bin/aos-recovery").read_bytes()
              assert binary.startswith(bytes([0x7f]) + b"ELF")
              assert b"AOS signed recovery environment" in binary
              print("aos-recovery identity passed")
            ''
          ];
          exit_code = 0;
          stdout.exact = "aos-recovery identity passed\n";
          stderr.exact = "";
        }];
        artifacts = [];
      };
      bad_input = {
        input = "A request for an undeclared recovery helper.";
        operation = "Resolve the absent helper beneath the staged output.";
        expected = "The package exposes only its declared recovery executable.";
        files = {};
        steps = [{
          argv = [
            "@python@"
            "-c"
            ''
              import pathlib, sys
              if pathlib.Path("@out@/bin/aos-recovery-shell").exists():
                  raise SystemExit(2)
              sys.stderr.write("undeclared recovery helper rejected\n")
              raise SystemExit(7)
            ''
          ];
          exit_code = 7;
          stdout.exact = "";
          stderr.exact = "undeclared recovery helper rejected\n";
          observes_rejection = true;
        }];
        artifacts = [];
      };
    };
  };
}
