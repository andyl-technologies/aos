##! Exercises additional Q-through-Z archive tools with fixed local payloads.
{testing}: {
  zip = testing.mkQualificationPackageProbe {
    name = "zip";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "zip";
      primary = {
        input = "A text file containing a fixed answer.";
        operation = "Create a ZIP archive, then inspect its member through Python's independent ZIP reader.";
        expected = "The archive contains one member whose bytes exactly match the source payload.";
        files = {
          "payload.txt" = "answer=42\n";
          "verify.py" = ''
            import zipfile

            with zipfile.ZipFile("payload.zip") as archive:
                assert archive.namelist() == ["payload.txt"]
                assert archive.read("payload.txt") == b"answer=42\n"
            print("zip archive passed")
          '';
        };
        steps = [
          {
            argv = ["@out@/bin/zip" "-q" "payload.zip" "payload.txt"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@python@" "verify.py"];
            exit_code = 0;
            stdout.exact = "zip archive passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A source path that does not exist.";
        operation = "Attempt to add the missing file to a new archive.";
        expected = "Zip rejects the empty input set with its documented nothing-to-do status.";
        files = {};
        steps = [
          {
            argv = ["@out@/bin/zip" "-q" "missing.zip" "missing.txt"];
            exit_code = 12;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  unzip = testing.mkQualificationPackageProbe {
    name = "unzip";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "unzip";
      primary = {
        input = "A ZIP archive with one fixed text member, created by Python's standard library.";
        operation = "Stream the member through unzip without extracting it to disk.";
        expected = "Unzip emits the member bytes exactly.";
        files."create.py" = ''
          import zipfile

          info = zipfile.ZipInfo("payload.txt", date_time=(2000, 1, 1, 0, 0, 0))
          with zipfile.ZipFile("payload.zip", "w") as archive:
              archive.writestr(info, b"answer=42\n")
        '';
        steps = [
          {
            argv = ["@python@" "create.py"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/unzip" "-p" "payload.zip" "payload.txt"];
            exit_code = 0;
            stdout.exact = "answer=42\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "Plain text that does not contain a ZIP central directory.";
        operation = "Test the malformed file as a ZIP archive.";
        expected = "Unzip rejects the malformed archive with its invalid-archive status.";
        files."invalid.zip" = "not a zip archive\n";
        steps = [
          {
            argv = ["@out@/bin/unzip" "-tqq" "invalid.zip"];
            exit_code = 9;
            stdout.exact = "";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
