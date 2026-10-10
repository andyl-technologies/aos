# Production CLI plan/apply protocol against a closed local HTTP fixture.
{
  mkSystem,
  pkgs,
  ...
}: let
  runner = pkgs.writeTextFile {
    name = "package-assessment-review-cli-fleet-runner";
    text = builtins.readFile ./_assessment-review-cli.py;
    destination = "/runner.py";
  };
  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [pkgs.aos pkgs.git pkgs.python3 pkgs.nix];
    }
  ];
in {
  name = "package-assessment-review-cli";
  timeout = 900;
  bootTimeout = 300;
  machines.maintainer = {
    inherit system;
    memoryMiB = 4096;
    varSizeMiB = 2048;
  };
  testScript =
    # python
    ''
      maintainer.wait_for_unit("multi-user.target", timeout=240)
      maintainer.succeed("mkdir -p /var/lib/assessment-review/repository")
      maintainer.succeed("printf '%s\\n' '{}' > /var/lib/assessment-review/repository/default.nix")
      maintainer.succeed("git -C /var/lib/assessment-review/repository init")
      maintainer.succeed("git -C /var/lib/assessment-review/repository remote add origin https://example.org/assessment-review-fixture.git")
      output = maintainer.succeed(
          "${pkgs.python3}/bin/python3 ${runner}/runner.py "
          "/var/lib/assessment-review/repository ${pkgs.aos}/bin/aos",
          timeout=180,
      )
      assert "PASS: actual CLI plan/apply RPC separation" in output, output
    '';
}
