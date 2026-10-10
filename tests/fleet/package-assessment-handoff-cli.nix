# Exact source-intent export and independent local planning through real CLI processes.
{
  mkSystem,
  pkgs,
  ...
}: let
  runner = pkgs.writeTextFile {
    name = "package-assessment-handoff-cli-fleet-runner";
    text = builtins.readFile ./_assessment-handoff-cli.py;
    destination = "/runner.py";
  };
  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [
        pkgs.aos
        pkgs.aos.testSupport
        pkgs.git
        pkgs.nix
        pkgs.python3
        runner
      ];
    }
  ];
in {
  name = "package-assessment-handoff-cli";
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
      output = maintainer.succeed(
          "${pkgs.python3}/bin/python3 ${runner}/runner.py "
          "/var/lib/assessment-handoff/repository "
          "/var/lib/assessment-handoff/state "
          "/var/lib/assessment-handoff/artifacts "
          "${pkgs.aos}/bin/aos "
          "${pkgs.aos.testSupport}/bin/aos-release-fleet-fixture",
          timeout=240,
      )
      assert "PASS: actual CLI exact assessment handoff, independent local discovery and stale-source refusal" in output, output
    '';
}
