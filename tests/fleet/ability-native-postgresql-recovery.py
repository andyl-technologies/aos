# Executor loss and whole-guest reboot during an unrecorded PostgreSQL start.


def start_background_switch(host, label):
    status = f"/run/postgresql-{label}.status"
    log = f"/run/postgresql-{label}.log"
    runtime.succeed(
        f"{COREUTILS}/rm -f {status} {log}; "
        "( set +e; "
        f"{APM} switch --from {shlex.quote(host)} "
        f"--eval-root /run/postgresql-eval-{shlex.quote(label)}; "
        f"code=$?; printf '%s\\n' \"$code\" > {status} ) "
        f"> {log} 2>&1 < /dev/null &"
    )
    return status, log


def kill_exact_postgresql_activation_runtime():
    killed = runtime.succeed(textwrap.dedent(f"""
        set -eu
        matches=""
        for executable in /proc/[0-9]*/exe; do
          target=$({COREUTILS}/readlink "$executable" 2>/dev/null || true)
          [ "$target" = {shlex.quote(PACKAGE_RUNTIME)} ] || continue
          process=''${{executable#/proc/}}
          process=''${{process%/exe}}
          command=$({COREUTILS}/tr '\\000' ' ' \
            < "/proc/$process/cmdline" 2>/dev/null || true)
          case " $command " in
            *" __activate-config "*) matches="$matches $process" ;;
          esac
        done
        set -- $matches
        [ "$#" -eq 1 ]
        kill -KILL "$1"
        printf '%s\\n' "$1"
    """))
    assert killed.strip().isdigit(), killed


def kill_held_postgresql_control():
    killed = runtime.succeed(textwrap.dedent(f"""
        set -eu
        matches=""
        for command_line in /proc/[0-9]*/cmdline; do
          command=$({COREUTILS}/tr '\\000' ' ' \
            < "$command_line" 2>/dev/null || true)
          case " $command " in
            *"/bin/postgresql-control quarantine-start "*)
              process=''${{command_line#/proc/}}
              process=''${{process%/cmdline}}
              matches="$matches $process"
              ;;
          esac
        done
        set -- $matches
        [ "$#" -eq 1 ]
        kill -KILL "$1"
        printf '%s\\n' "$1"
    """))
    assert killed.strip().isdigit(), killed


def wait_for_unrecorded_quarantine_start(marker):
    runtime.wait_until_succeeds(
        f"{JQ} -e '.details.phase == \"quarantinestarting\" "
        "and .details.process == null' "
        f"{shlex.quote(marker)}",
        timeout=1200,
    )
    details = read_json(marker)["details"]
    runtime.wait_until_succeeds(
        f"test -s {shlex.quote(details['data_path'] + '/postmaster.pid')}",
        timeout=1200,
    )
    pid, executable = postmaster_identity(details)
    runtime.succeed(f"kill -0 {pid}")
    assert executable == details["postgres_executable"], (executable, details)
    return details, pid


recovery_release = "/run/aos-postgresql-quarantine-hold-release"
activation_executor_loss = generate_postgresql_activation(
    "/run/postgresql-executor-loss",
    "recovery_database",
    "recovery_role",
    "sha256:" + "55" * 32,
    "postgresql-executor-loss",
    "/run/postgresql-authority-executor-loss",
    fault="hold-quarantine-after-start",
)
provision_postgresql_authority(
    activation_executor_loss,
    "/run/postgresql-authority-executor-loss",
)
executor_loss_host = "/run/postgresql-host-executor-loss.nix"
write_postgresql_host(executor_loss_host, activation_executor_loss)
executor_loss_entry = resource_entries(activation_executor_loss)["postgresql"]
executor_loss_marker = state_path(executor_loss_entry)
runtime.succeed(f"{COREUTILS}/rm -f {recovery_release}")
executor_status, executor_log = start_background_switch(
    executor_loss_host,
    "executor-loss",
)
executor_held_details, executor_held_pid = wait_for_unrecorded_quarantine_start(
    executor_loss_marker
)

kill_exact_postgresql_activation_runtime()
kill_held_postgresql_control()
runtime.wait_until_succeeds(f"test -s {executor_status}", timeout=120)
assert runtime.succeed(f"{COREUTILS}/cat {executor_status}").strip() != "0", (
    runtime.succeed(f"{COREUTILS}/cat {executor_log}")
)
runtime.succeed(f"kill -0 {executor_held_pid}")
assert read_json(executor_loss_marker)["details"]["process"] is None

runtime.succeed(
    f"{COREUTILS}/install -o root -g root -m 0600 /dev/null "
    f"{recovery_release}"
)
generation_executor_loss = switch_postgresql_host(
    executor_loss_host,
    "executor-loss-recovery",
)
transaction_executor_loss, _, _, _ = assert_single_postgresql_reconciliation(
    generation_executor_loss,
    activation_executor_loss,
    "start",
)
states_executor_loss = resource_states(activation_executor_loss)
details_executor_loss = assert_cluster_layout(states_executor_loss)
secret_executor_loss = (
    "/run/postgresql-executor-loss/test-only/credential.secret"
)
assert_process_boundary(details_executor_loss)
assert_sql_ready(details_executor_loss, secret_executor_loss)
assert details_executor_loss["process"]["pid"] != int(executor_held_pid)

# Repeat the same persisted starting phase and remove power from the guest.
activation_power_loss = generate_postgresql_activation(
    "/run/postgresql-power-loss",
    "recovery_database",
    "recovery_role",
    "sha256:" + "56" * 32,
    "postgresql-power-loss",
    "/run/postgresql-authority-power-loss",
    fault="hold-quarantine-after-start",
)
provision_postgresql_authority(
    activation_power_loss,
    "/run/postgresql-authority-power-loss",
)
power_host = "/var/lib/aos/postgresql-host-power-loss.nix"
write_postgresql_host(power_host, activation_power_loss)
power_secret = "/var/lib/aos/postgresql-power-loss.secret"
runtime.succeed(
    f"{COREUTILS}/install -o root -g root -m 0600 "
    "/run/postgresql-power-loss/test-only/credential.secret "
    f"{power_secret}"
)
power_entry = resource_entries(activation_power_loss)["postgresql"]
power_marker = state_path(power_entry)
runtime.succeed(f"{COREUTILS}/rm -f {recovery_release}")
start_background_switch(power_host, "power-loss")
power_held_details, power_held_pid = wait_for_unrecorded_quarantine_start(
    power_marker
)
power_generation_before = current_generation()
runtime.power_cycle(timeout=600)
runtime.wait_for_unit("multi-user.target", timeout=300)
runtime.wait_until_succeeds(
    f"{JQ} -e '.details.phase == \"quarantinestarting\" "
    "and .details.process == null' "
    f"{shlex.quote(power_marker)}",
    timeout=1200,
)
runtime.succeed(
    f"{COREUTILS}/install -o root -g root -m 0600 /dev/null "
    f"{recovery_release}"
)
runtime.wait_until_succeeds(
    "systemctl is-active --quiet aos-activate.service",
    timeout=1200,
)
runtime.wait_until_succeeds(
    f"{JQ} -e '.details.phase == \"active\"' {shlex.quote(power_marker)}",
    timeout=1200,
)
generation_power_loss = current_generation()
assert generation_power_loss > power_generation_before
transaction_power_loss, _, _, _ = assert_single_postgresql_reconciliation(
    generation_power_loss,
    activation_power_loss,
    "restart",
)
states_power_loss = resource_states(activation_power_loss)
details_power_loss = assert_cluster_layout(states_power_loss)
assert_process_boundary(details_power_loss)
assert_sql_ready(details_power_loss, power_secret)
assert details_power_loss["process"]["pid"] != int(power_held_pid)
