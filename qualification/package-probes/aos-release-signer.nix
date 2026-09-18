##! Checks evidence signatures against an independently verified Ed25519 vector.
{testing}: let
  script = builtins.readFile ./_release-signer.py;
in {
  aos-release-signer = testing.mkQualificationPackageProbe {
    name = "aos-release-signer";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "aos-release-signer";
      primary = {
        input = "Canonical JSON and a disposable public Ed25519 test seed.";
        operation = "Sign evidence, compare the complete envelope to a known answer, and attempt an overwrite.";
        expected = "The signature matches the independent vector and the existing envelope is preserved.";
        files."probe.py" = script;
        steps = [
          {
            argv = ["@python@" "probe.py" "primary"];
            exit_code = 0;
            stdout.exact = "Evidence signature and no-overwrite checks passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "Valid JSON encoded with noncanonical whitespace.";
        operation = "Attempt to sign the noncanonical evidence payload.";
        expected = "The signer rejects the payload and creates no envelope.";
        files."probe.py" = script;
        steps = [
          {
            argv = ["@python@" "probe.py" "bad-input"];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "Signer rejected noncanonical evidence without output\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
