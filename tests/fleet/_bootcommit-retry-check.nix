##! Exercises effective bootcommit retry dependencies with disposable manager units.
{
  lib,
  pkgs,
  configuration,
}: let
  services = configuration.aos.services;
  activation = services."control-plane.aos-activate";
  commit = services."configuration-evaluation.image-boot-commit";
  convergence = services."package-profile-convergence.package-profile-convergence" or null;
  unitName = service: "${service.manager_identity.name}.service";
  hasConvergence = convergence != null && builtins.elem (unitName convergence) commit.dependencies.requires;
  roles =
    {
      inherit activation commit;
    }
    // lib.optionalAttrs hasConvergence {inherit convergence;};
  names = lib.mapAttrs (role: _: "aos-bootcommit-retry-probe-${role}.service") roles;
  mapping = lib.listToAttrs (lib.mapAttrsToList (role: service: {
      name = unitName service;
      value = names.${role};
    })
    roles);
  project = values: map (name: mapping.${name}) (builtins.filter (name: builtins.hasAttr name mapping) values);
  policy =
    lib.mapAttrs (_: service: {
      inherit (service.lifecycle) execution_model remain_after_exit restart restart_delay_millis start_timeout_millis;
      dependencies = {
        wants = project service.dependencies.wants;
        requires = project service.dependencies.requires;
        after = project service.dependencies.after;
      };
    })
    roles;
in
  # python
  ''
    # This witnesses manager job semantics, not a second native activation or
    # TPM commit. All existing production qualification assertions precede it.
    RETRY_ROOT = "/run/aos-bootcommit-retry-probe"
    RETRY_NAMES = ${builtins.toJSON names}
    RETRY_POLICY = json.loads(${builtins.toJSON (builtins.toJSON policy)})
    RETRY_BASH = "${pkgs.bash}/bin/bash"
    RETRY_SYSTEMCTL = "${pkgs.systemd}/bin/systemctl"

    retry_scripts = {
        "activation": f"""set -eu
    if test ! -e {RETRY_ROOT}/attempted; then
        printf attempted > {RETRY_ROOT}/attempted
        printf 'failure\\n' >> {RETRY_ROOT}/events
        exit 1
    fi
    printf 'success\\n' >> {RETRY_ROOT}/events
    printf successful > {RETRY_ROOT}/activated
    """,
        "convergence": f"""set -eu
    test -e {RETRY_ROOT}/activated
    printf 'convergence\\n' >> {RETRY_ROOT}/events
    printf converged > {RETRY_ROOT}/converged
    """,
        "commit": f"""set -eu
    test -e {RETRY_ROOT}/activated
    """ + (f"test -e {RETRY_ROOT}/converged\n" if "convergence" in RETRY_NAMES else "")
        + f"printf 'commit\\n' >> {RETRY_ROOT}/events\n",
    }

    retry_setup = [
        "set -eu",
        "umask 077",
        f"test ! -e {RETRY_ROOT} && test ! -L {RETRY_ROOT}",
        f"{COREUTILS}/mkdir -m 0700 {RETRY_ROOT}",
    ]
    for role, name in RETRY_NAMES.items():
        policy = RETRY_POLICY[role]
        script = f"{RETRY_ROOT}/{role}.sh"
        unit = f"/run/systemd/system/{name}"
        lines = ["[Unit]", f"Description=Disposable bootcommit retry {role} witness"]
        for field, directive in (("wants", "Wants"), ("requires", "Requires"), ("after", "After")):
            if policy["dependencies"][field]:
                lines.append(f"{directive}=" + " ".join(policy["dependencies"][field]))
        lines += [
            "[Service]",
            f"Type={policy['execution_model']}",
            "RemainAfterExit=" + ("yes" if policy["remain_after_exit"] else "no"),
            "Restart=" + ("no" if policy["restart"] == "never" else policy["restart"]),
            f"RestartSec={policy['restart_delay_millis']}ms",
            f"TimeoutStartSec={policy['start_timeout_millis']}ms",
            f"ExecStart={RETRY_BASH} {script}",
        ]
        retry_setup += [
            f"test ! -e {unit} && test ! -L {unit}",
            f"printf %s {shlex.quote(retry_scripts[role])} > {script}",
            f"printf %s {shlex.quote(chr(10).join(lines) + chr(10))} > {unit}",
        ]
    target.succeed(f"{RETRY_BASH} -c " + shlex.quote("\n".join(retry_setup)))
    target.succeed(f"{RETRY_SYSTEMCTL} daemon-reload")

    # One initial job fails. Its automatic retry must pull the failed commit
    # job back in through the production-derived Wants edge.
    target.fail(f"{RETRY_SYSTEMCTL} start {RETRY_NAMES['activation']}")
    target.wait_for_unit(RETRY_NAMES["commit"], timeout=30)
    expected_retry_events = ["failure", "success"]
    if "convergence" in RETRY_NAMES:
        expected_retry_events.append("convergence")
    expected_retry_events.append("commit")
    retry_events = target.succeed(f"{COREUTILS}/cat {RETRY_ROOT}/events").splitlines()
    assert retry_events == expected_retry_events, retry_events
    assert target.succeed(
        f"{RETRY_SYSTEMCTL} show {RETRY_NAMES['activation']} --property=NRestarts --value"
    ).strip() == "1"
    for name in RETRY_NAMES.values():
        state = dict(line.split("=", 1) for line in target.succeed(
            f"{RETRY_SYSTEMCTL} show {name} --property=ActiveState,SubState"
        ).splitlines())
        assert state == {"ActiveState": "active", "SubState": "exited"}, (name, state)

    # Starting an already retained successful oneshot is a no-op, not a new
    # commit. No actual production service is restarted by this probe.
    target.succeed(f"{RETRY_SYSTEMCTL} start {RETRY_NAMES['activation']}")
    assert target.succeed(f"{COREUTILS}/cat {RETRY_ROOT}/events").splitlines() == retry_events
    target.succeed(f"{RETRY_SYSTEMCTL} stop " + " ".join(RETRY_NAMES.values()))
    target.succeed(
        f"{COREUTILS}/rm -- "
        + " ".join(f"/run/systemd/system/{name}" for name in RETRY_NAMES.values())
    )
    target.succeed(f"{RETRY_SYSTEMCTL} daemon-reload")
  ''
