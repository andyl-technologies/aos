##! Native snapshot services and timers preserve retention and preparation ordering.
{
  lib,
  pkgs,
}: let
  fixture = import ./_native-storage-evaluation.nix {inherit lib;};
  evaluate = enabled:
    fixture.evaluate {
      packages = [fixture.zfsProvider fixture.zfstools];
      modules = [
        {
          aos.filesystems.zfs = {
            enable = true;
            systemState = false;
            reservedSpace.enable = false;
            datasets.data.mountPoint = "/var/lib/data";
            autoSnapshot = {
              enable = enabled;
              datasets = ["aos-pool/data"];
            };
          };
        }
      ];
    };
  enabled = evaluate true;
  disabled = evaluate false;
  snapshotTimers = evaluated: builtins.filter (node: builtins.elem "scheduledActivation" node.identity && builtins.match "zfs-auto-snapshot-.*" node.input.name != null) (builtins.attrValues evaluated.deployment.graph.nodes);
  hourly = enabled.config.aos.services."zfs-auto-snapshot.hourly";
  prepare = enabled.config.aos.services."zfs-auto-snapshot.prepare";
  hourlyTimer = builtins.head (builtins.filter (node: node.input.name == "zfs-auto-snapshot-hourly") (snapshotTimers enabled));
in
  assert snapshotTimers disabled == [];
  assert builtins.length (snapshotTimers enabled) == 5;
  assert hourly.autoStart == false;
  assert hourly.lifecycle.start
  == [
    {
      executable = {
        path = "${fixture.zfstools}/bin/zfs-auto-snapshot";
        arguments = ["--utc" "hourly" "24"];
      };
      ignore_failure = false;
    }
  ];
  assert prepare.lifecycle.remain_after_exit;
  assert (builtins.head prepare.lifecycle.start).executable.arguments == ["set" "com.sun:auto-snapshot=true" "aos-pool/data"];
  assert hourlyTimer.input.schedule
  == {
    kind = "calendar";
    expression = "hourly";
  };
  assert hourlyTimer.input.persistent;
  assert hourlyTimer.input.randomized_delay_millis == 300000;
  assert builtins.length hourlyTimer.dependencies == 1;
  assert builtins.all (entry: entry.assertion) enabled.config.assertions; true
