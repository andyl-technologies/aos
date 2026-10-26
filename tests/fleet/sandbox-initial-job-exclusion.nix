# Exercises PID1's queued manual interval, without launching an initial producer.
{
  mkSystem,
  pkgs,
  ...
}: let
  hold = "aos-method46-exclusion-hold";
  target = "aos-method46-exclusion-target";
  victim = "aos-method46-exclusion-victim";
  normal = ["aos-sandboxd" "aos-storaged"];
  initial = [
    "aos-sandbox-controller-floor-initialize"
    "aos-sandbox-storage-floor-initialize"
  ];

  inactiveOwner = {
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.coreutils}/bin/false";
    };
  };
  blockedInitializer =
    inactiveOwner
    // {
      requires = ["${hold}.service"];
      after = ["${hold}.service"];
    };
  migrationOwner = {
    serviceConfig = {
      Type = "simple";
      ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
      Delegate = true;
    };
  };

  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [pkgs.systemd];
      systemd.services =
        {
          ${hold}.serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.coreutils}/bin/sleep 120";
          };
          ${target} = migrationOwner;
          ${victim} = migrationOwner;
        }
        // builtins.listToAttrs (map (name: {
            inherit name;
            value = inactiveOwner;
          })
          normal)
        // builtins.listToAttrs (map (name: {
            inherit name;
            value = blockedInitializer;
          })
          initial);
    }
  ];
in {
  name = "sandbox-initial-job-exclusion";
  timeout = 300;
  machines.vm = {inherit system;};

  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=120)
    normal = ["aos-sandboxd.service", "aos-storaged.service"]
    initial = [
        "aos-sandbox-controller-floor-initialize.service",
        "aos-sandbox-storage-floor-initialize.service",
    ]
    target = "${target}.service"
    victim = "${victim}.service"
    hold = "${hold}.service"

    def pending_job(unit):
        rows = vm.succeed("systemctl list-jobs --no-legend --plain").splitlines()
        matches = [row.split()[0] for row in rows if row.split()[1] == unit]
        assert len(matches) == 1, (unit, rows)
        return int(matches[0])

    def attach(unit, pid):
        return (
            "${pkgs.systemd}/bin/busctl call org.freedesktop.systemd1 "
            "/org/freedesktop/systemd1 org.freedesktop.systemd1.Manager "
            f'AttachProcessesToUnit ssau {unit} "" 1 {pid}'
        )

    vm.succeed("systemctl stop " + " ".join(normal))
    vm.succeed(f"systemctl start {target} {victim}")
    pid = int(vm.succeed(f"systemctl show --value --property=MainPID {victim}"))
    assert pid > 1
    original_group = vm.succeed(f"cat /proc/{pid}/cgroup")

    for unit in initial:
        # The pending real PID1 job owns exclusion before any producer birth.
        # This fixture never supplies Source, approval, journal or TPM authority.
        vm.succeed(f"systemctl --no-block start {unit}")
        job = pending_job(unit)
        assert vm.succeed(f"systemctl show --value --property=MainPID {unit}").strip() == "0"

        for owner in normal + [other for other in initial if other != unit]:
            output = vm.fail(f"systemctl --no-block start {owner}")
            assert "manual METHOD46 initialization interval" in output, output
        vm.fail(attach(target, pid))
        assert vm.succeed(f"cat /proc/{pid}/cgroup") == original_group
        assert pending_job(unit) == job

        vm.succeed(f"systemctl cancel {job}")
        vm.succeed(f"systemctl stop {hold}")
        assert vm.succeed(f"systemctl show --value --property=ActiveState {unit}").strip() == "inactive"

        # The identical root migration request succeeds once that interval ends.
        vm.succeed(attach(target, pid))
        assert vm.succeed(f"cat /proc/{pid}/cgroup") != original_group
        vm.succeed(attach(victim, pid))
        assert vm.succeed(f"cat /proc/{pid}/cgroup") == original_group

    vm.succeed(f"systemctl stop {victim} {target} {hold}")
  '';
}
