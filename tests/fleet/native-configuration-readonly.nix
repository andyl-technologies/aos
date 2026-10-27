# Reconciles real read-only configuration mounts through the installed provider.
{
  mkSystem,
  pkgs,
  ...
}: let
  directory = "/run/aos/configuration-readonly-test";
  state = "${directory}/state";
  image = "${directory}/image";
  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [
        pkgs.aos-configuration-provider
        pkgs.coreutils
        pkgs.erofs-utils
        pkgs.util-linux
      ];
      systemd.services.aos-configuration-readonly-test = {
        description = "Qualify immutable configuration reconciliation";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.aos-configuration-provider}/bin/aos-configuration-provider --state-directory ${state} apply";
          StandardInput = "file:${directory}/invocation.json";
          BindReadOnlyPaths = [image];
          ProtectSystem = "strict";
          ReadWritePaths = [state];
          PrivateTmp = true;
          NoNewPrivileges = true;
        };
      };
    }
  ];
in {
  name = "native-configuration-readonly";
  timeout = 240;
  machines.machine = {inherit system;};
  testScript = ''
    import hashlib
    import json
    import shlex

    machine.wait_for_unit("multi-user.target", timeout=120)
    directory = "${directory}"
    state = "${state}"
    target = "${image}/configuration"
    unit = "aos-configuration-readonly-test.service"
    document = {
        "id": "immutable-configuration",
        "revision": "first",
        "action": "apply",
        "effect": {"identity": ["test", "configuration", "file", "immutable"]},
        "input": {
            "path": target,
            "content": "immutable configuration\n",
            "mode": "0444",
            "owner": "root",
            "group": "root",
        },
    }
    machine.succeed(f"install -d -m 0700 {directory} {state} ${image}")

    def write_invocation():
        machine.succeed(
            f"printf %s {shlex.quote(json.dumps(document))} > {directory}/invocation.json"
        )

    write_invocation()
    machine.succeed(f"touch {target}")

    def restore_image():
        machine.succeed(f"chown 0:0 {target}")
        machine.succeed(f"chmod 0644 {target}")
        machine.succeed(f"printf 'immutable configuration\\n' > {target}")
        machine.succeed(f"chmod 0444 {target}")

    def identity():
        return machine.succeed(f"stat -c '%d:%i:%u:%g:%a' {target}").strip()

    def contents():
        return machine.succeed(f"sha256sum {target}")

    receipt_name = hashlib.sha256(document["id"].encode()).hexdigest() + ".json"

    def receipt():
        return json.loads(machine.succeed(f"cat {state}/{receipt_name}"))

    def apply():
        machine.succeed(f"systemctl start {unit}", timeout=30)

    def refuse():
        before = (identity(), contents())
        machine.fail(f"systemctl start {unit}", timeout=30)
        assert (identity(), contents()) == before
        machine.succeed(f"systemctl reset-failed {unit}")

    restore_image()
    initial = (identity(), contents())
    apply()
    assert not receipt()["pending"]
    assert (identity(), contents()) == initial
    apply()
    assert (identity(), contents()) == initial

    # Bytes and every requested metadata field remain mandatory. The mount
    # restriction is installed by PID 1 in each actual provider execution.
    machine.succeed(f"printf 'foreign contents\\n' > {target}")
    previous_receipt = machine.succeed(f"sha256sum {state}/{receipt_name}")
    refuse()
    assert machine.succeed(f"sha256sum {state}/{receipt_name}") == previous_receipt

    restore_image()
    for change in ("chmod 0600", "chown 1:0", "chown 0:1"):
        machine.succeed(f"{change} {target}")
        refuse()
        assert receipt()["pending"]
        restore_image()
        apply()
        assert not receipt()["pending"]
        assert (identity(), contents()) == initial

    # The production initrd uses EROFS, whose native file operations differ
    # from a read-only bind of a writable filesystem. Exercise both directly.
    erofs = "/var/lib/aos-configuration-readonly-test"
    machine.succeed(f"install -d -m 0700 {erofs}")
    machine.succeed(f"cp -a ${image} {erofs}/root")
    machine.succeed(f"mkfs.erofs {erofs}/image.erofs {erofs}/root")
    machine.succeed(f"mount -t erofs -o loop,ro {erofs}/image.erofs ${image}")
    try:
        assert machine.succeed(f"stat -f -c %T {target}").strip() == "erofs"
        immutable_identity = (identity(), contents())
        apply()
        assert not receipt()["pending"]
        apply()
        assert (identity(), contents()) == immutable_identity

        for field, changed in (("content", "different contents\n"), ("mode", "0600")):
            original = document["input"][field]
            document["input"][field] = changed
            write_invocation()
            refuse()
            assert receipt()["pending"]

            document["input"][field] = original
            write_invocation()
            apply()
            assert not receipt()["pending"]
            assert (identity(), contents()) == immutable_identity
    finally:
        machine.succeed("umount ${image}")

    machine.succeed(f"rm -rf {erofs} {directory}")
  '';
}
