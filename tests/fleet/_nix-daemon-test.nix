##! Production APM evaluation, admission, activation, and retained-build policy.
{
  mkSystem,
  pkgs,
  ...
}: let
  image = mkSystem ./_nix-daemon-image.nix;
  hostActivator = image.config.aos.services.${image.config.aos.boot.hostActivatorService};
  hostActivatorName =
    if hostActivator.manager_identity != null
    then hostActivator.manager_identity.name
    else hostActivator.service;
  hostActivatorUnit = "${hostActivatorName}.service";
in {
  spec = {
    timeout = 1800;
    bootTimeout = 600;
    systemReadyTimeout = 0;

    machines.builder = {
      system = image;
      memoryMiB = 4096;
      varSizeMiB = 2048;
      packages = ["aos-test-agent"];
      extraClosures = [pkgs.aos pkgs.aos.apm pkgs.bash pkgs.coreutils pkgs.jq pkgs.nix pkgs.util-linux];
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
  };

  scriptHelpers = ''
    import base64
    import json
    import shlex

    AOS = "${pkgs.aos}/bin/aos"
    BASH = "${pkgs.bash}/bin/bash"
    JQ = "${pkgs.jq}/bin/jq"
    APM = "${pkgs.aos.apm}/bin/apm"
    RUNTIME = "${pkgs.aos.packageRuntime}/bin/aos-package-runtime"
    PROFILE = "/var/lib/profiles/system"
    NIX = "${pkgs.nix}/bin/nix-store"
    SETPRIV = "${pkgs.util-linux}/bin/setpriv"
    SOCKET = "/nix/var/nix/daemon-socket/socket"
    SLICE = "aos-pkg-nix-daemon-builds.slice"
    HOST_ACTIVATOR = "${hostActivatorUnit}"
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
            f"systemctl show {SLICE} --property=LoadState,ActiveState,FragmentPath,DropInPaths,MemoryMax,MemoryHigh,MemoryCurrent,ControlGroup",
            "cat /etc/aos/packages/nix-daemon/runtime.env "
            "/etc/systemd/system/aos-pkg-nix-daemon-builds.slice "
            "/etc/systemd/system/aos-pkg-nix-daemon-builds.slice.d/30-aos-resources.conf",
            "cat /run/systemd/system.control/aos-pkg-nix-daemon-builds.slice.d/* 2>/dev/null || true",
            f"group=$(systemctl show {SLICE} --property=ControlGroup --value); "
            "test -n \"$group\" && "
            "for name in memory.max memory.high memory.current memory.events cgroup.controllers; do "
            "printf '%s\\n' \"$name\"; cat \"/sys/fs/cgroup$group/$name\"; done",
            f"{RUNTIME} deployment-current --profile {PROFILE} --committed-during-recovery; systemctl show {HOST_ACTIVATOR} --property=ActiveState",
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


    JOURNAL_PROJECTION = """{
        schema, liveStateVerified, transaction, pending, completed,
        records: [.records[] | {sequence, event, transaction, dispatch}],
        desired: (if .desired == null then null else
            {nodes: (.desired.nodes | with_entries(.value = {identity: .value.identity}))}
            end)
    }"""
    GENERATION_PROJECTION = """{
        schema,
        daemonEffects: [.desired.graph.nodes | to_entries[] |
            select(.value.identity == ["profile", "system", "nix-daemon", "serviceManagement", "realize", "nix-daemon"]) |
            .key]
    }"""


    def public_json(command, projection):
        # Project only after the public CLI validates the retained document.
        # pipefail prevents an empty jq result from hiding a failed CLI read.
        pipeline = f"{command} | {JQ} -c {shlex.quote(projection)}"
        return json.loads(builder.succeed(
            f"{BASH} -o pipefail -c {shlex.quote(pipeline)}"
        ))


    def journal():
        view = public_json(
            f"{AOS} ability journal {PROFILE}/deployment/effects.journal --format json",
            JOURNAL_PROJECTION,
        )
        assert view["schema"] == "aos.activation.inspection", view
        assert not view["liveStateVerified"], view
        return view


    def dispatch_starts(view, effect):
        return [record for record in view["records"]
                if record["event"] == "started"
                and (record["dispatch"] or {}).get("effect") == effect]


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


    def apply(body, capture_result=False):
        global sequence
        sequence += 1
        stage(body)
        # The control plane must work from a daemon-selected login environment,
        # including when socket admission is closed.
        command = (
            "NIX_REMOTE=daemon NIX_CONF_DIR=/etc/aos/packages/nix-daemon "
            f"{APM} config apply --eval-root /run/daemon-eval-{sequence}"
        )
        if capture_result:
            exit_code, stdout, stderr = builder.execute(command, timeout=600)
            result = {
                "exit_code": exit_code,
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
            }
            print("Captured daemon apply result:", result, flush=True)
            return result
        builder.succeed(command, timeout=600)


    def attempt_guarded_removal():
        global added
        # Remove authored overrides before departing the package's module root.
        # An orphaned option definition must not substitute for the worker guard.
        if added:
            builder.succeed(f"{APM} config remove daemon.nix")
            builder.succeed(f"{APM} config apply --eval-root /run/daemon-remove-reset-{sequence}", timeout=600)
            added = False
        previous = generation()
        # The removal target graph omits the departed service. Bind its pending
        # effect to the checked committed source graph before dispatch instead.
        committed = public_json(
            f"{AOS} ability diagnostic {PROFILE} {previous} --audience deployment",
            GENERATION_PROJECTION,
        )
        assert committed["schema"] == "aos.package.generation.inspection", committed
        daemon_effects = committed["daemonEffects"]
        assert len(daemon_effects) == 1, committed
        command = f"{APM} remove nix-daemon --system --yes"
        exit_code, stdout, stderr = builder.execute(command, timeout=600)
        result = {
            "exit_code": exit_code,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
        }
        assert result["exit_code"] != 0, result
        assert "identity is still running" in result["stderr"] or "workers remain" in result["stderr"], result
        assert generation() == previous
        return previous, daemon_effects[0]


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


    def ready():
        builder.wait_until_succeeds(f"systemctl is-active --quiet {HOST_ACTIVATOR}", timeout=300)
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

  '';
}
