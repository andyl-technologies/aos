# Actual Hub CLI scan selection against a closed Connect-JSON protocol fixture.
{
  mkSystem,
  pkgs,
  ...
}: let
  runner = pkgs.writeTextFile {
    name = "package-assessment-selection-cli-fleet-runner";
    text = builtins.readFile ./_assessment-selection-cli.py;
    destination = "/runner.py";
  };
  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [pkgs.aos pkgs.git pkgs.python3 pkgs.nix runner];
    }
  ];
in {
  name = "package-assessment-selection-cli";
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
      maintainer.succeed("mkdir -p /var/lib/assessment-selection/repository")
      maintainer.succeed("printf '%s\\n' '{}' > /var/lib/assessment-selection/repository/default.nix")
      maintainer.succeed("git -C /var/lib/assessment-selection/repository init")
      output = maintainer.succeed(
          "${pkgs.python3}/bin/python3 ${runner}/runner.py "
          "/var/lib/assessment-selection/repository ${pkgs.aos}/bin/aos",
          timeout=180,
      )
      assert "PASS: actual CLI pinned selection, bounded pages and changed receipt refusal" in output, output
    '';
}
