##! Exercises fifth-slice Q-through-Z policy and specification language tools.
{testing}: let
  mkProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryScript,
    badInput,
    badOperation,
    badExpected,
    badScript,
    primaryFiles ? {},
    badFiles ? {},
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
  reject = package: body: ''
    import sys
    ${body}
    sys.stderr.write("${package} rejected invalid input\n")
    raise SystemExit(7)
  '';
in {
  setools = mkProbe {
    package = "setools";
    primaryInput = "The extended-permission range 0x10-0x12.";
    primaryOperation = "Parse the range through SETools' public extended-permission utility API.";
    primaryExpected = "The API returns the inclusive numeric range from 16 through 18.";
    primaryScript = ''
      import glob, sys
      locations = glob.glob("@out@/lib/python*/site-packages")
      assert len(locations) == 1
      sys.path.insert(0, locations[0])
      import setools
      assert setools.xperm_str_to_tuple_ranges("0x10-0x12") == [(16, 18)]
      print("setools operation passed")
    '';
    badInput = "A three-byte file presented as a compiled SELinux policy.";
    badOperation = "Open the malformed policy through SETools' public SELinuxPolicy API.";
    badExpected = "SETools rejects the malformed policy image with its policy-loading exception.";
    badFiles."invalid.policy" = "bad";
    badScript = reject "setools" ''
      import glob, sys
      sys.path.insert(0, glob.glob("@out@/lib/python*/site-packages")[0])
      import setools
      try:
          setools.SELinuxPolicy("invalid.policy")
      except Exception:
          pass
      else:
          raise RuntimeError("SETools accepted a malformed policy")
    '';
  };

  tla-plus = mkProbe {
    package = "tla-plus";
    primaryInput = "A syntactically valid TLA+ module defining a constant expression.";
    primaryOperation = "Parse and semantically analyze the module with the packaged SANY launcher.";
    primaryExpected = "SANY completes parsing and semantic processing without errors.";
    primaryFiles."Qualified.tla" = "---- MODULE Qualified ----\nEXTENDS Naturals\nAnswer == 40 + 2\n====\n";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/bin/sany", "Qualified.tla"], capture_output=True, text=True)
      assert result.returncode == 0 and "Semantic processing of module Qualified" in result.stdout
      print("tla-plus operation passed")
    '';
    badInput = "A TLA+ module with an unterminated expression.";
    badOperation = "Parse the malformed module with SANY.";
    badExpected = "SANY reports a parse error and returns failure.";
    badFiles."Invalid.tla" = "---- MODULE Invalid ----\nBroken == (1 +\n====\n";
    badScript = reject "tla-plus" ''
      import subprocess
      result = subprocess.run(["@out@/bin/sany", "Invalid.tla"], capture_output=True, text=True)
      assert result.returncode != 0 and "Parse Error" in result.stdout
    '';
  };
}
