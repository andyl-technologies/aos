# Production callback WASM with durable replay and paired protocol fixtures.
{
  mkSystem,
  pkgs,
  ...
}: let
  runner = pkgs.writeTextFile {
    name = "package-assessment-notification-worker-fleet-runner";
    text = builtins.readFile ./_assessment-notification-worker.cjs;
    destination = "/runner.cjs";
  };
  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [pkgs.nodejs pkgs.miniflare runner pkgs.aos-hub-worker-dist];
    }
  ];
in {
  name = "package-assessment-notifications-worker";
  timeout = 900;
  bootTimeout = 300;
  machines.executor = {
    inherit system;
    memoryMiB = 4096;
    varSizeMiB = 2048;
  };
  testScript =
    # python
    ''
      import json

      executor.wait_for_unit("multi-user.target", timeout=240)
      executor.succeed("mkdir -p /var/lib/assessment-notification-worker")
      output = executor.succeed(
          "node ${runner}/runner.cjs ${pkgs.miniflare} "
          "${pkgs.aos-hub-worker-dist}/shim.mjs /var/lib/assessment-notification-worker/state",
          timeout=180,
      )
      result = json.loads(output.strip().splitlines()[-1])
      assert result == {"status": "passed", "gatewayCalls": 4, "concurrentReceipts": 4}, result
    '';
}
