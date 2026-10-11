# Production provider WASM with executor-owned R2 and durable replay fencing.
{
  mkSystem,
  pkgs,
  ...
}: let
  runner = pkgs.writeTextFile {
    name = "package-assessment-worker-fleet-runner";
    text = builtins.readFile ./_assessment-worker.cjs;
    destination = "/runner.cjs";
  };
  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [pkgs.nodejs pkgs.miniflare runner pkgs.aos-hub-worker-dist];
    }
  ];
in {
  name = "package-assessment-worker";
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

      try:
          executor.wait_for_unit("multi-user.target", timeout=240)
      except Exception:
          print(executor.execute("systemctl list-jobs --no-pager; systemctl --failed --no-pager; journalctl -b -n 100 --no-pager", timeout=30))
          raise
      executor.succeed("mkdir -p /var/lib/assessment-worker")
      output = executor.succeed(
          "node ${runner}/runner.cjs ${pkgs.miniflare} "
          "${pkgs.aos-hub-worker-dist}/shim.mjs /var/lib/assessment-worker/state",
          timeout=180,
      )
      result = json.loads(output.strip().splitlines()[-1])
      assert result == {"status": "passed", "physicalCalls": 12, "concurrentReceipts": 4, "throttleReplay": True, "conditionalReplay": True, "missingCustody": True}, result
    '';
}
