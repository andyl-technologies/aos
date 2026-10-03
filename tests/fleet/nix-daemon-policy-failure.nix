##! Retains the exact pending daemon invocation after an exhausted build slice.
{
  mkSystem,
  pkgs,
  ...
}: let
  fixture = import ./_nix-daemon-test.nix {inherit mkSystem pkgs;};
in
  fixture.spec
  // {
    name = "nix-daemon-policy-failure";
    testScript =
      fixture.scriptHelpers
      + ''
        try:
            ready()
            # A one-byte aggregate limit prevents the daemon's exec-condition from
            # starting. The failed native invocation must remain pending, not commit.
            tiny = 'resources.memoryHigh = "1"; resources.memoryMax = "1";'
            previous_generation = generation()
            result = apply(configuration(True, tiny), capture_result=True)
            assert result["exit_code"] != 0, result
            assert generation() == previous_generation

            pending_view = journal()
            pending = pending_view["pending"]
            assert pending is not None, pending_view
            assert pending["action"] == "apply", pending
            node = pending_view["desired"]["nodes"][pending["effect"]]
            assert node["identity"] == ["profile", "system", "nix-daemon", "serviceManagement", "realize", "nix-daemon"], node
            starts = dispatch_starts(pending_view, pending["effect"])
            assert starts[-1]["dispatch"] == pending, starts
            assert starts[-1]["sequence"] == pending["journalSequence"], starts
            assert property("nix-daemon-policy.service", "Slice") == "aos-pkg-nix-daemon.slice"
            assert property("nix-daemon.service", "Slice") == SLICE
            assert property("nix-daemon-policy.service", "Result") == "success"
            # Resource changes survive reload through one package-owned drop-in.
            # In particular, percentage defaults cannot override absolute limits.
            builder.succeed("systemctl daemon-reload")
            assert property(SLICE, "DropInPaths") == f"/etc/systemd/system/{SLICE}.d/30-aos-resources.conf"
            assert property(SLICE, "LoadState") == "loaded"
            memory_max = property(SLICE, "MemoryMax")
            assert memory_max == "1", {"unit": SLICE, "MemoryMax": memory_max}
            assert property(SLICE, "MemoryHigh") == "1"
            builder.wait_until_succeeds(
                f"test -r /sys/fs/cgroup$(systemctl show {SLICE} --property=ControlGroup --value)/memory.events "
                f"&& awk '$1 == \"oom\" && $2 > 0 {{ found = 1 }} END {{ exit !found }}' "
                f"/sys/fs/cgroup$(systemctl show {SLICE} --property=ControlGroup --value)/memory.events",
                timeout=60,
            )
            builder.succeed(
                "journalctl -u nix-daemon.service --no-pager "
                "| grep -q \"Failed to spawn 'exec-condition' task: Cannot allocate memory\""
            )

            # A different desired config cannot bypass recovery of the original
            # indeterminate invocation, or replace its durable intent with a new one.
            blocked_result = apply(configuration(False), capture_result=True)
            assert blocked_result["exit_code"] != 0, blocked_result
            assert generation() == previous_generation
            blocked_view = journal()
            assert blocked_view["pending"] == pending, (pending_view, blocked_view)
            assert blocked_view["transaction"] == pending_view["transaction"]
            assert blocked_view["completed"] == pending_view["completed"]
            assert dispatch_starts(blocked_view, pending["effect"]) == starts
            assert not any(record["event"] == "finished" and record["dispatch"] == pending
                           for record in blocked_view["records"]), blocked_view
            print("Nix daemon exhausted policy: committed generation and exact pending intent preserved PASS")
        except Exception:
            report_failure()
            raise
      '';
  }
