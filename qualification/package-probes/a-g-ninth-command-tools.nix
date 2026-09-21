##! Exercises ninth-slice A-G commands through deterministic offline paths.
{testing}: let
  mkCommandProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryCommand,
    primaryCheck,
    badInput,
    badOperation,
    badExpected,
    badCommand,
    badCheck ? "result.returncode != 0",
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
          files = {};
          steps = [
            {
              argv = [
                "@python@"
                "-c"
                ''
                  import subprocess
                  result = subprocess.run(${primaryCommand}, capture_output=True, text=True)
                  assert ${primaryCheck}, (result.returncode, result.stdout, result.stderr)
                  print("${package} operation passed")
                ''
              ];
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
          files = {};
          steps = [
            {
              argv = [
                "@python@"
                "-c"
                ''
                  import subprocess, sys
                  result = subprocess.run(${badCommand}, capture_output=True, text=True)
                  assert ${badCheck}, (result.returncode, result.stdout, result.stderr)
                  sys.stderr.write("${package} rejected invalid input\n")
                  raise SystemExit(7)
                ''
              ];
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

  mkHelpProbe = {
    package,
    executable ? package,
    helpNeedle ? "usage",
  }:
    mkCommandProbe {
      inherit package;
      primaryInput = "The packaged ${package} command-line interface.";
      primaryOperation = "Request its offline help text.";
      primaryExpected = "The command returns success and documents its invocation contract.";
      primaryCommand = ''["@out@/bin/${executable}", "--help"]'';
      primaryCheck = ''result.returncode == 0 and ${builtins.toJSON helpNeedle} in (result.stdout + result.stderr).lower()'';
      badInput = "A ${package} invocation containing an unsupported option.";
      badOperation = "Parse the invalid option without starting the service.";
      badExpected = "The command rejects the unsupported option before runtime initialization.";
      badCommand = ''["@out@/bin/${executable}", "--aos-invalid-option"]'';
    };
in {
  aos-hub-dialect-tests = mkCommandProbe {
    package = "aos-hub-dialect-tests";
    primaryInput = "The packaged Rust dialect contract test executable.";
    primaryOperation = "List its test inventory without connecting to PostgreSQL or MariaDB.";
    primaryExpected = "The libtest harness returns success and exposes dialect contract tests.";
    primaryCommand = ''["@out@/bin/aos-hub-dialect-contract", "--list"]'';
    primaryCheck = ''result.returncode == 0 and ": test" in result.stdout'';
    badInput = "A dialect-test invocation containing an unsupported libtest option.";
    badOperation = "Parse the invalid option without connecting to a database.";
    badExpected = "The libtest harness rejects the unsupported option.";
    badCommand = ''["@out@/bin/aos-hub-dialect-contract", "--aos-invalid-option"]'';
  };

  cloudcore = mkHelpProbe {
    package = "cloudcore";
  };

  crucible = mkHelpProbe {
    package = "crucible";
  };

  edgecore = mkHelpProbe {
    package = "edgecore";
  };

  garage = mkCommandProbe {
    package = "garage";
    primaryInput = "The packaged Garage server's release identity.";
    primaryOperation = "Request its version without opening storage or network listeners.";
    primaryExpected = "Garage returns success and reports its version.";
    primaryCommand = ''["@out@/bin/garage", "--version"]'';
    primaryCheck = ''result.returncode == 0 and "garage" in (result.stdout + result.stderr).lower()'';
    badInput = "A Garage invocation naming an unknown command.";
    badOperation = "Parse the unsupported command without opening storage.";
    badExpected = "Garage rejects the unsupported command.";
    badCommand = ''["@out@/bin/garage", "aos-invalid-command"]'';
  };

  gjavah = mkCommandProbe {
    package = "gjavah";
    primaryInput = "The packaged GNU Classpath JNI header generator interface.";
    primaryOperation = "Request its help without loading a Java class.";
    primaryExpected = "Gjavah returns success and documents its class and output options.";
    primaryCommand = ''["@out@/bin/gjavah", "--help"]'';
    primaryCheck = ''result.returncode == 0 and "usage" in (result.stdout + result.stderr).lower()'';
    badInput = "A request to generate a header for a Java class absent from the classpath.";
    badOperation = "Resolve the nonexistent class through the header generator.";
    badExpected = "Gjavah rejects the missing class and produces no header.";
    badCommand = ''["@out@/bin/gjavah", "aos.qualification.MissingClass"]'';
  };
}
