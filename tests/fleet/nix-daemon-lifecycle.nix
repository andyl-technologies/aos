##! Production APM evaluation, admission, activation, and retained-build policy.
{
  mkSystem,
  pkgs,
  ...
}: let
  image = mkSystem ./_nix-daemon-image.nix;
in {
  name = "nix-daemon-lifecycle";
  timeout = 1800;
  bootTimeout = 600;
  systemReadyTimeout = 0;

  machines.builder = {
    system = image;
    memoryMiB = 4096;
    varSizeMiB = 2048;
    packages = ["aos-test-agent"];
    extraClosures = [pkgs.aos.apm pkgs.bash pkgs.coreutils pkgs.nix pkgs.util-linux];
    metadata."host.nix" = ''
      { config, lib, ... }: {
        aos.getty.autologin.enable = lib.mkForce false;
        aos.abilities.identity.operations.group.effects.build-clients.input = {
          name = "build-clients";
          requested_id = 1000;
        };
        aos.abilities.identity.operations.principal.effects.build-client.input = {
          name = "build-client";
          requested_id = 1000;
          primary_group = config.aos.abilities.identity.operations.group.effects.build-clients.outputs.name;
          home_directory = "/tmp";
        };
        aos.abilities.configuration.operations.file.effects.daemon-client-policy.input = {
          path = "/etc/aos/policy.toml";
          content = "tier = \"privileged\"\n";
          mode = "0644";
        };
      }
    '';
  };

  testScript = ''
    import base64
    import json

    APM = "${pkgs.aos.apm}/bin/apm"
    RUNTIME = "${pkgs.aos.packageRuntime}/bin/aos-package-runtime"
    PROFILE = "/var/lib/profiles/system"
    NIX = "${pkgs.nix}/bin/nix-store"
    SETPRIV = "${pkgs.util-linux}/bin/setpriv"
    SOCKET = "/nix/var/nix/daemon-socket/socket"
    SLICE = "aos-pkg-nix-daemon-builds.slice"
    sequence = 0
    added = False
    diagnostics_reported = False


    def report_failure():
        global diagnostics_reported
        if diagnostics_reported:
            return
        diagnostics_reported = True
        for command in [
            "cat /tmp/retained-build.log /tmp/retained-build.out 2>/dev/null || true",
            "systemctl status nix-daemon.service nix-daemon.socket nix-daemon-policy.service --no-pager || true",
            "journalctl -u nix-daemon.service -u nix-daemon-policy.service -n 80 --no-pager || true",
            f"{RUNTIME} deployment-current --profile {PROFILE} --committed-during-recovery; systemctl show aos-config.target --property=ActiveState",
            "for p in /proc/[0-9]*/status; do "
            "awk '$1 == \"Name:\" { name = $2 } $1 == \"State:\" { state = $2 } "
            "$1 == \"Uid:\" { uid = $2 } END { if (uid >= 30001 && uid <= 30064) "
            "print FILENAME, name, state, uid }' \"$p\" 2>/dev/null || true; done",
        ]:
            try:
                print(builder.succeed(command, timeout=30))
            except Exception as error:
                print(f"Lifecycle diagnostic failed: {error}")


    def write_file(path, text):
        encoded = base64.b64encode(text.encode()).decode()
        builder.succeed(f"printf '%s' '{encoded}' | base64 -d > '{path}'")


    def generation():
        return json.loads(builder.succeed(
            f"{RUNTIME} deployment-current --profile {PROFILE} --committed-during-recovery"
        ))["generation"]


    def stage(body):
        global added
        write_file("/run/daemon-fixture.nix", "{ lib, ... }: { " + body + " }")
        if added:
            builder.succeed(f"{APM} config replace daemon.nix /run/daemon-fixture.nix")
        else:
            builder.succeed(f"{APM} config add /run/daemon-fixture.nix --name daemon.nix")
            added = True


    def apply(body, succeeds=True, allow_degraded=False):
        global sequence
        sequence += 1
        stage(body)
        # The control plane must work from a daemon-selected login environment,
        # including when socket admission is closed.
        command = (
            "NIX_REMOTE=daemon NIX_CONF_DIR=/etc/aos/packages/nix-daemon "
            f"{APM} config apply --eval-root /run/daemon-eval-{sequence}"
        )
        if allow_degraded:
            builder.execute(command, timeout=600)
        elif succeeds:
            builder.succeed(command, timeout=600)
        else:
            builder.fail(command, timeout=600)


    def remove_daemon(succeeds=True):
        global added
        # Remove authored overrides before departing the package's module root.
        # An orphaned option definition must not substitute for the worker guard.
        if added:
            builder.succeed(f"{APM} config remove daemon.nix")
            builder.succeed(f"{APM} config apply --eval-root /run/daemon-remove-reset-{sequence}", timeout=600)
            added = False
        previous = generation()
        command = f"{APM} remove nix-daemon --yes"
        if succeeds:
            builder.succeed(command, timeout=600)
            descriptor = json.loads(builder.succeed(
                f"cat {PROFILE}/gen-{generation()}/evaluation.json"
            ))
            assert all(module["name"] != "nix-daemon" for module in descriptor["packages"]["modules"]), descriptor
        else:
            since = builder.succeed("date +%s").strip()
            result = builder.fail(command, timeout=600)
            journal = builder.succeed(
                f"journalctl -u aos-activate.service --since=@{since} --no-pager"
            )
            assert "identity is still running" in journal or "workers remain" in journal, (result, journal)
            assert generation() == previous


    def configuration(enabled, extra="", count=4):
        flag = "true" if enabled else "false"
        return (
            f'nix-daemon = {{ enable = {flag}; buildUsers.count = {count}; '
            f'settings.max-jobs = {count}; {extra} }};'
        )


    def property(unit, name):
        return builder.succeed(
            f"systemctl show '{unit}' --property='{name}' --value"
        ).strip()


    def assert_quota(cores):
        cgroup = property(SLICE, "ControlGroup")
        quota, period = map(int, builder.succeed(
            f"cat /sys/fs/cgroup{cgroup}/cpu.max"
        ).split())
        assert quota == cores * period, (quota, period, cores)


    def assert_disabled():
        builder.fail("systemctl is-active --quiet nix-daemon.socket")
        builder.fail("systemctl is-active --quiet nix-daemon.service")
        builder.fail(f"test -S '{SOCKET}'")
        builder.fail(f"{SETPRIV} --reuid=1000 --regid=1000 --clear-groups "
                     f"{NIX} --store daemon --query --hash '${pkgs.bash}'")
        builder.fail("systemctl is-active --quiet nix-daemon.service")


    try:
        builder.wait_until_succeeds("systemctl is-active --quiet aos-config.target", timeout=300)
        first_generation = generation()
        assert isinstance(first_generation, int) and first_generation > 0, first_generation
        builder.succeed(f"test -s {PROFILE}/gen-{first_generation}/native-deployment.json")
        builder.succeed(f"test -s {PROFILE}/gen-{first_generation}/evaluation.json")
        assert_disabled()
        builder.succeed("grep -q '^nixbld64:x:30064:30000:' /etc/passwd")
        shadow = builder.succeed(
            "awk -F: '$1 == \"nixbld64\" { print $2 }' /etc/shadow"
        ).strip()
        assert shadow.startswith("!") or shadow == "*", repr(shadow)

        # An accepted limit can be too small even for the listener. Policy runs
        # outside the build slice and must remain able to restore its limits.
        tiny = 'resources.memoryHigh = "1"; resources.memoryMax = "1";'
        before_exhaustion = generation()
        apply(configuration(True, tiny), allow_degraded=True)
        assert generation() != before_exhaustion
        assert property("nix-daemon-policy.service", "Slice") == "aos-pkg-nix-daemon.slice"
        assert property("nix-daemon.service", "Slice") == SLICE
        assert property("nix-daemon-policy.service", "Result") == "success"
        assert property(SLICE, "MemoryMax") == "1"
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
        apply(configuration(False))
        assert property(SLICE, "MemoryMax") != "1"
        assert property("nix-daemon-policy.service", "Result") == "success"
        assert_disabled()

        apply(configuration(True, 'resources.cpuQuotaCores = 2; scheduling.cpuPolicy = "idle";'))
        builder.wait_until_succeeds(f"test -S '{SOCKET}'", timeout=60)
        builder.succeed(f"{SETPRIV} --reuid=1000 --regid=1000 --clear-groups "
                        f"{NIX} --store daemon --query --hash '${pkgs.bash}'")
        assert property("nix-daemon.service", "User") == "root"
        assert property("nix-daemon.service", "KillMode") == "process"
        assert property("nix-daemon.service", "CPUSchedulingPolicy") == "5"
        assert_quota(2)
        assert property("nix-daemon.service", "Slice") == SLICE
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

            remove_daemon(succeeds=False)
            builder.succeed(f"test -r '{worker}'")
            builder.succeed(f"test -s {PROFILE}/deployment/effects.journal")

            # Reverting to defaults while disabled must reset transient live policy too.
            apply(configuration(False, count=2))
            assert_quota(2)
            assert property(SLICE, "MemorySwapMax") == "0"
            assert_disabled()
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

            remove_daemon()
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
