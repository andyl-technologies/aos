# Reconciles image-owned accounts without writing the immutable initrd database.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  directory = "/run/aos/identity-readonly-test";
  image = "${directory}/image";
  state = "${directory}/state";
  managerState = "/run/aos/initrd-systemd-resources";
  shells = import ../../pkgs/system/_systemd-abilities/identity-shells.nix {
    inherit (pkgs) bash util-linux;
  };
  program = pkgs.systemd.handlers // {meta.mainProgram = "aos-systemd-native-resources";};
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      ../../lib/effects/module.nix
      ../../pkgs/system/_service-management/identity.nix
      {
        aos.activation.scope = ["test" "initrd"];
        aos.abilities.identity.operations = {
          group = {
            handler = {inherit program;};
            effects = {
              image.input = {
                name = "image-service";
                requested_id = 888;
              };
              conflict.input = {
                name = "image-service";
                requested_id = 889;
              };
              missing.input = {
                name = "missing-service";
                requested_id = 889;
              };
            };
          };
          principal = {
            handler = {inherit program;};
            effects.image.input = {
              name = "image-service";
              requested_id = 888;
              primary_group = "image-service";
              description = "Image service";
            };
          };
        };
      }
    ];
  };
  invocations =
    lib.mapAttrsToList (id: effect: {
      name = "${builtins.elemAt effect.identity (builtins.length effect.identity - 2)}-${lib.last effect.identity}";
      value = {
        inherit id effect;
        inherit (effect) input revision;
        action = "apply";
        previous = null;
      };
    })
    evaluated.config.aos.activation.graph.nodes;
  system = mkSystem [
    ../../systems/server-test.nix
    {
      environment.systemPackages = [pkgs.coreutils pkgs.erofs-utils pkgs.util-linux];
      systemd.services.aos-identity-readonly-test = {
        description = "Qualify immutable account reconciliation";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.systemd.handlers}/bin/aos-systemd-native-resources apply";
          StandardInput = "file:${directory}/invocation.json";
          BindReadOnlyPaths = ["${image}:/etc"];
          BindPaths = ["${state}:${managerState}"];
          ProtectSystem = "strict";
          ReadWritePaths = [managerState];
          PrivateTmp = true;
          NoNewPrivileges = true;
        };
      };
    }
  ];
in {
  name = "native-identity-readonly";
  timeout = 240;
  machines.machine = {inherit system;};
  testScript = ''
    import hashlib
    import json
    import shlex

    machine.wait_for_unit("multi-user.target", timeout=120)
    directory = "${directory}"
    image = "${image}"
    state = "${state}"
    backing = "/var/lib/aos-identity-readonly-test"
    unit = "aos-identity-readonly-test.service"
    machine.succeed(f"install -d -m 0700 {directory} {image} {state} {backing}/root")

    rows = {
        "initrd-release": "NAME=AOS\\n",
        "passwd": "image-service:x:888:888:Image service:/var/empty:${shells.nologin}\\n",
        "group": "image-service:x:888:\\n",
        "shadow": "image-service:!:0:0:99999:7:::\\n",
        "gshadow": "image-service:!::\\n",
    }
    for name, contents in rows.items():
        machine.succeed(
            f"printf %b {shlex.quote(contents)} > {backing}/root/{name}"
        )
    machine.succeed(f"chmod 0600 {backing}/root/shadow {backing}/root/gshadow")

    invocations = json.loads(${builtins.toJSON (builtins.toJSON (builtins.listToAttrs invocations))})
    document = invocations["group-image"]

    def write_invocation():
        machine.succeed(
            f"printf %s {shlex.quote(json.dumps(document))} > {directory}/invocation.json"
        )

    def snapshot():
        return machine.succeed(
            f"stat -c '%n:%d:%i:%u:%g:%a' {image}/*; sha256sum {image}/*"
        )

    def receipt():
        name = hashlib.sha256(document["id"].encode()).hexdigest() + "-identity.json"
        return json.loads(machine.succeed(f"cat {state}/{name}"))

    def apply():
        write_invocation()
        machine.succeed(f"systemctl start {unit}", timeout=30)
        current = receipt()
        assert current["complete"]
        assert current["rows"] == {}, current
        assert current["additions"] == [], current

    # A read-only bind does not make its backing filesystem immutable. Its
    # database may have other writers, so failure to acquire .pwd.lock refuses.
    machine.succeed(f"mount --bind {backing}/root {image}")
    try:
        write_invocation()
        original = snapshot()
        machine.fail(f"systemctl start {unit}", timeout=30)
        machine.succeed(
            f"journalctl -u {unit} --no-pager -o cat | grep -F 'Read-only file system'"
        )
        assert snapshot() == original
        machine.succeed(f"test ! -e {image}/.pwd.lock")
        machine.succeed(f"systemctl reset-failed {unit}")
    finally:
        machine.succeed(f"umount {image}")

    machine.succeed(f"mkfs.erofs {backing}/image.erofs {backing}/root")
    machine.succeed(f"mount -t erofs -o loop,ro {backing}/image.erofs {image}")
    try:
        assert machine.succeed(f"stat -f -c %T {image}").strip() == "erofs"
        original = snapshot()
        apply()
        apply()
        assert snapshot() == original
        machine.succeed(f"test ! -e {image}/.pwd.lock")

        document = invocations["group-conflict"]
        write_invocation()
        machine.fail(f"systemctl start {unit}", timeout=30)
        machine.succeed(
            f"journalctl -u {unit} --no-pager -o cat "
            "| grep -F 'existing account numeric identity conflicts'"
        )
        machine.succeed(f"systemctl reset-failed {unit}")
        assert snapshot() == original

        document = invocations["principal-image"]
        apply()
        assert snapshot() == original

        document = invocations["group-missing"]
        write_invocation()
        machine.fail(f"systemctl start {unit}", timeout=30)
        assert not receipt()["complete"]
        assert snapshot() == original
        machine.succeed(f"systemctl reset-failed {unit}")
    finally:
        machine.succeed(f"umount {image}")

    machine.succeed(f"rm -rf {backing} {directory}")
  '';
}
