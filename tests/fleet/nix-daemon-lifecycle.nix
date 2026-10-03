##! Production APM evaluation, admission, activation, and retained-build policy.
{
  mkSystem,
  pkgs,
  ...
}: let
  fixture = import ./_nix-daemon-test.nix {inherit mkSystem pkgs;};
in
  fixture.spec
  // {
    name = "nix-daemon-lifecycle";
    testScript =
      fixture.scriptHelpers
      + ''
        try:
            ready()
            default_memory_high = property(SLICE, "MemoryHigh")
            default_memory_max = property(SLICE, "MemoryMax")
            apply(configuration(True, 'resources.cpuQuotaCores = 2; scheduling.cpuPolicy = "idle"; resources.memoryHigh = "512M"; resources.memoryMax = "1G";'))
            builder.succeed("systemctl daemon-reload")
            assert property(SLICE, "MemoryHigh") == "536870912"
            assert property(SLICE, "MemoryMax") == "1073741824"
            assert property(SLICE, "DropInPaths") == f"/etc/systemd/system/{SLICE}.d/30-aos-resources.conf"
            # Adding a runtime module preserves the boot-delivered operator tree.
            operator_sources = json.loads(builder.succeed(
                f"cat {PROFILE}/gen-{generation()}/evaluation.json"
            ))["runtimeConfiguration"]
            assert {path.rsplit("/", 1)[-1] for path in operator_sources} == {"host.nix", "daemon.nix"}, operator_sources
            builder.succeed("grep -q '^build-client:x:1000:1000:' /etc/passwd")
            builder.succeed("grep -q '^tier = \"privileged\"$' /etc/aos/policy.toml")
            builder.wait_until_succeeds(f"test -S '{SOCKET}'", timeout=60)
            builder.succeed(f"{SETPRIV} --reuid=1000 --regid=1000 --clear-groups "
                            f"{NIX} --store daemon --query --hash '${pkgs.bash}'")
            assert property("nix-daemon.service", "User") == "root"
            assert property("nix-daemon.service", "KillMode") == "process"
            assert property("nix-daemon.service", "CPUSchedulingPolicy") == "5"
            assert_quota(2)
            assert property("nix-daemon.service", "Slice") == SLICE
            assert property("nix-daemon-policy.service", "Slice") == "aos-pkg-nix-daemon.slice"
            assert property("nix-daemon-policy.service", "Result") == "success"
            builder.succeed("test -d /var/cache/nix-build")
            builder.succeed("test \"$(stat -c '%u:%a' /var/cache/nix-build)\" = 0:755")

            write_file("/tmp/retained-build.nix", r"""{ name }: let
              bash = builtins.storePath "${pkgs.bash}";
              coreutils = builtins.storePath "${pkgs.coreutils}";
            in builtins.derivation {
              inherit name;
              system = builtins.currentSystem;
              builder = "''${bash}/bin/bash";
              args = [ "-c" "set -euo pipefail; test ! -e /etc/aos/packages/nix-daemon/nix.conf; ''${coreutils}/bin/mkdir \"$out\"; ''${coreutils}/bin/mkfifo /tmp/nix-daemon-fixture-release; read -r release < /tmp/nix-daemon-fixture-release; echo complete > \"$out/complete\"" ];
            }
            """)
            builder.succeed("chmod 0644 /tmp/retained-build.nix")
            builder.succeed(
                f"{SETPRIV} --reuid=1000 --regid=1000 --clear-groups "
                "${pkgs.nix}/bin/nix-build --store daemon --no-out-link "
                "/tmp/retained-build.nix --argstr name retained-apm-build "
                "> /tmp/retained-build.out 2> /tmp/retained-build.log &"
            )
            builder.wait_until_succeeds(
                "for p in /proc/[0-9]*/status; do real_uid=; "
                "while read key uid rest; do "
                "case $key in Uid:) real_uid=$uid ;; esac; "
                "done 2>/dev/null < $p || continue; "
                "if test \"$real_uid\" -ge 30001 && test \"$real_uid\" -le 30064 "
                "&& test -p \"''${p%/status}/root/tmp/nix-daemon-fixture-release\"; then "
                "echo $p > /tmp/worker-status; exit 0; fi; "
                "done; exit 1", timeout=60,
            )
            worker = builder.succeed("cat /tmp/worker-status").strip()
            worker_pid = int(worker.split("/")[-2])
            worker_uid = int(builder.succeed(f"awk '/^Uid:/ {{ print $2 }}' '{worker}'"))
            assert 30001 <= worker_uid <= 30064, worker_uid
            try:
                # A sandbox's namespace init may ignore its own STOP. Signal from the
                # ancestor namespace after the private FIFO identifies a stable worker.
                builder.succeed(f"test \"$(awk '/^Uid:/ {{ print $2 }}' '{worker}')\" = {worker_uid} "
                                f"&& kill -STOP {worker_pid}")
                builder.wait_until_succeeds(f"grep -q '^State:.*T' '{worker}'", timeout=60)
                listener = property("nix-daemon.service", "MainPID")

                # A native setting changes the authenticated hash and restarts the listener,
                # while workers retain the package slice and its newly reconciled limits.
                apply(configuration(True, "settings.http-connections = 26; resources.cpuQuotaCores = 1;"))
                builder.succeed("systemctl daemon-reload")
                assert property(SLICE, "MemoryHigh") == default_memory_high
                assert property(SLICE, "MemoryMax") == default_memory_max
                assert property(SLICE, "DropInPaths") == f"/etc/systemd/system/{SLICE}.d/30-aos-resources.conf"
                builder.succeed(f"test -r '{worker}'")
                builder.succeed(f"grep -q '/aos-pkg-nix-daemon-builds.slice/' /proc/{worker_pid}/cgroup")
                assert property("nix-daemon.service", "MainPID") != listener
                assert_quota(1)
                builder.succeed("grep -qx 'http-connections = 26' /etc/aos/packages/nix-daemon/nix.conf")

                apply(configuration(False, 'resources.cpuQuotaCores = 3; resources.memorySwapMax = "1G";', count=2))
                assert_disabled()
                assert_quota(3)
                assert property(SLICE, "MemorySwapMax") == "1073741824"
                builder.succeed("grep -qx 'nixbld:x:30000:nixbld1,nixbld2' /etc/group")
                builder.succeed("grep -q '^nixbld64:x:30064:30000:' /etc/passwd")

                # Reset live retained-worker limits before beginning removal;
                # a pending removal cannot be bypassed by a new configuration.
                apply(configuration(False, count=2))
                assert_quota(2)
                assert property(SLICE, "MemorySwapMax") == "0"
                assert_disabled()

                removal_generation, daemon_effect = attempt_guarded_removal()
                builder.succeed(f"test -r '{worker}'")
                pending_view = journal()
                removal = pending_view["pending"]
                assert removal is not None, pending_view
                assert removal["effect"] == daemon_effect, removal
                assert removal["action"] == "remove", removal
                starts = dispatch_starts(pending_view, daemon_effect)
                assert starts[-1]["dispatch"] == removal, starts
                assert starts[-1]["sequence"] == removal["journalSequence"], starts
                assert generation() == removal_generation

                # Retry the clean authored worktree while the worker is stopped.
                # Recovery must preserve the original remove intent and fail.
                builder.fail(f"{APM} config apply --eval-root /run/daemon-blocked-recovery", timeout=600)
                blocked_view = journal()
                assert blocked_view["pending"] == removal, (pending_view, blocked_view)
                assert blocked_view["transaction"] == pending_view["transaction"]
                assert dispatch_starts(blocked_view, daemon_effect) == starts
                assert generation() == removal_generation
                # Release the stopped builder explicitly; evaluation speed cannot let the
                # worker disappear before the retained-build and removal assertions finish.
                # Avoid O_CREAT: protected_fifos rejects shell redirection into another
                # identity's FIFO in sticky /tmp even for the privileged test client.
                builder.succeed(f"test \"$(awk '/^Uid:/ {{ print $2 }}' '{worker}')\" = {worker_uid} "
                                f"&& kill -CONT {worker_pid} "
                                f"&& printf 'release\\n' | ${pkgs.coreutils}/bin/dd "
                                f"of=/proc/{worker_pid}/root/tmp/nix-daemon-fixture-release conv=nocreat status=none")
                builder.wait_until_succeeds("test -s /tmp/retained-build.out", timeout=240)
                output = builder.succeed("cat /tmp/retained-build.out").strip()
                builder.succeed(f"test -f '{output}/complete'")
                builder.wait_until_succeeds(f"test ! -e '{worker}'", timeout=60)

                builder.succeed(f"{APM} config apply --eval-root /run/daemon-drained-recovery", timeout=600)
                recovered_view = journal()
                assert recovered_view["pending"] is None, recovered_view
                assert any(record["event"] == "finished" and record["dispatch"] == removal
                           for record in recovered_view["records"]), recovered_view
                assert dispatch_starts(recovered_view, daemon_effect) == starts
                assert any(record["event"] == "commit" and record["transaction"] == pending_view["transaction"]
                           for record in recovered_view["records"]), recovered_view
                assert generation() != removal_generation
                module_names = json.loads(builder.succeed(
                    f"{JQ} -c '[.packages.modules[].name]' "
                    f"{PROFILE}/gen-{generation()}/evaluation.json"
                ))
                assert all(isinstance(name, str) for name in module_names), module_names
                assert "nix-daemon" not in module_names, module_names
                # Persistent worker resource policy and identity reservations survive
                # package departure; the listener's enabled lifecycle does not.
                builder.succeed("test -e /etc/systemd/system/aos-pkg-nix-daemon-builds.slice")
                builder.succeed("grep -q '^nixbld1:x:30001:30000:' /etc/passwd")
                builder.succeed(f"test -d '{output}' && test -d /nix/store")
                assert_disabled()
                print("Nix daemon APM lifecycle: activation, native restart, retained worker policy, disable, and drained removal PASS")
            except Exception:
                report_failure()
                raise
            finally:
                # Assertion failures must also release the stopped guest worker. Check
                # its reserved host identity before signalling a potentially reused PID.
                builder.execute(
                    f"if test -r '{worker}'; then "
                    "while read key uid rest; do "
                    f'if test "$key" = Uid: && test "$uid" = {worker_uid}; then '
                    f"kill -CONT '{worker_pid}' 2>/dev/null || true; "
                    f"kill -KILL '{worker_pid}' 2>/dev/null || true; "
                    f"fi; done < '{worker}'; fi",
                    timeout=20,
                )
        except Exception:
            report_failure()
            raise

      '';
  }
