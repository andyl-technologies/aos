##! Exercises the Go language server through offline source diagnostics.
{testing}: {
  gopls = testing.mkQualificationPackageProbe {
    name = "gopls";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "gopls";
      primary = {
        input = "A self-contained Go module with a type-correct source file.";
        operation = "Analyze the source with gopls check.";
        expected = "Gopls accepts the module without diagnostics.";
        files."go.mod" = "module example.test/qualification\n\ngo 1.22\n";
        files."main.go" = ''
          package main

          import "fmt"

          func main() {
              values := []int{19, 23}
              fmt.Println(values[0] + values[1])
          }
        '';
        steps = [
          {
            argv = ["@out@/bin/gopls" "check" "main.go"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
            timeout_seconds = 120;
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A Go source file with an incomplete short variable declaration.";
        operation = "Analyze the malformed source with gopls check.";
        expected = "Gopls reports the exact source location and syntax diagnostic on standard output.";
        files."go.mod" = "module example.test/qualification\n\ngo 1.22\n";
        files."invalid.go" = "package qualification\n\nfunc broken() { value := ; _ = value }\n";
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import pathlib, subprocess
                result = subprocess.run(["@out@/bin/gopls", "check", "invalid.go"], capture_output=True, text=True)
                location = pathlib.Path("invalid.go").resolve()
                assert result.returncode == 0 and result.stderr == ""
                assert result.stdout == f"{location}:3:26: expected operand, found ';'\n"
                print("gopls syntax diagnostic passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "gopls syntax diagnostic passed\n";
            stderr.exact = "";
            observes_rejection = true;
            timeout_seconds = 120;
          }
        ];
        artifacts = [];
      };
    };
  };
}
