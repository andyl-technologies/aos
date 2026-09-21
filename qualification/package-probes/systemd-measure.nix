##! Verifies offline PCR-11 derivation against a fixed kernel payload.
{testing}: {
  systemd-measure = testing.mkQualificationPackageProbe {
    name = "systemd-measure";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "systemd-measure";
      primary = {
        input = "A fixed kernel payload with a known SHA-256 PCR-11 policy.";
        operation = "Calculate the boot phase measurements without a TPM device.";
        expected = "The ready-phase PCR equals the independently recorded policy.";
        files."kernel.bin" = "AOS PCR qualification kernel\n";
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import subprocess

                result = subprocess.run([
                    "@out@/bin/systemd-measure", "calculate", "--bank=sha256",
                    "--linux=kernel.bin",
                ], check=True, capture_output=True, text=True)
                assert result.stdout.splitlines()[-1] == (
                    "11:sha256=409e5c39ec8c4f4e77ff36cdb794fafb"
                    "304dbb3f6ee3e3bc4c0535ce2b781c84"
                )
                print("PCR-11 known-answer calculation passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "PCR-11 known-answer calculation passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "An unsupported PCR bank name.";
        operation = "Attempt to calculate the policy with an invalid bank.";
        expected = "The tool rejects the unsupported digest algorithm.";
        files."kernel.bin" = "AOS PCR qualification kernel\n";
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import subprocess
                import sys

                result = subprocess.run([
                    "@out@/bin/systemd-measure", "calculate", "--bank=invalid-bank",
                    "--linux=kernel.bin",
                ], capture_output=True)
                assert result.returncode != 0
                assert b"invalid-bank" in result.stderr
                sys.stderr.write("PCR tool rejected invalid bank\n")
                raise SystemExit(7)
              ''
            ];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "PCR tool rejected invalid bank\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
