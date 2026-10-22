# Checks the distinct signed-DATA delivery profile without admitting hardware.
{
  lib,
  pkgs,
  systems,
}: let
  offline = import ../fleet/sandbox-nix-offline-key-preparation.nix {
    inherit lib pkgs systems;
  };
  caseFor = command: let
    system = offline.machines.vm.system.extendModules {
      modules = [{aos.sandbox.nixOfflinePrepare.command = command;}];
    };
    cfg = system.config;
    service = cfg.systemd.services.aos-sandbox-nix-floor-provision.serviceConfig;
    profile = builtins.head (lib.splitString ":" (builtins.elemAt service.OpenFile 1));
  in
    assert builtins.all (check: check.assertion) cfg.assertions;
    assert service.DeviceAllow == [];
    assert service.PrivateDevices;
    assert service.LoadCredential
    == [
      "node-id:/etc/credstore/node-id"
      "nix-floor-provision-approval-public-key-v3:/etc/credstore/nix-floor-provision-approval-public-key-v3"
      "nix-floor-provision-approved-job-v6:/etc/credstore/nix-floor-provision-approved-job-v6"
      "nix-floor-provision-approved-effect-v6:/etc/credstore/nix-floor-provision-approved-effect-v6"
    ];
    assert cfg.systemd.services.aos-sandbox-nix-floor-provision.wantedBy == [];
    assert cfg.systemd.services.aos-sandbox-nix-floor-provision.requiredBy == []; {
      inherit profile;
      unit = pkgs.writeTextFile {
        name = "sandbox-nix-offline-${command}-unit";
        text = cfg.systemd.units."aos-sandbox-nix-floor-provision.service".text;
      };
    };
  initialize = caseFor "import-initialize-v6";
  recover = caseFor "import-recovery-v6";
in
  pkgs.runCommand "sandbox-nix-offline-approval-delivery-profile-check" {
    buildDeps = [pkgs.python3];
  } ''
    ${pkgs.python3}/bin/python3 - \
      ${lib.escapeShellArg initialize.profile} ${initialize.unit} \
      ${lib.escapeShellArg recover.profile} ${recover.unit} <<'PY'
    import hashlib
    import json
    import pathlib
    import sys

    profiles = []
    for command, profile_name, unit_name in zip(
        ("import-initialize-v6", "import-recovery-v6"),
        sys.argv[1::2], sys.argv[2::2], strict=True,
    ):
        profile_path = pathlib.Path(profile_name)
        assert str(profile_path).endswith("-aos-nix-offline-startup-profile-6/profile.json")
        profile = json.loads(profile_path.read_bytes())
        assert profile["format"] == "AOS_NIX_OFFLINE_APPROVAL_DELIVERY_6"
        assert "hardware" not in profile
        unit = pathlib.Path(unit_name).read_bytes()
        original = f"OpenFile={profile_path}:aos-nix-offline-prepare-profile:read-only\n".encode()
        assert unit.splitlines(keepends=True).count(original) == 1
        measured = unit.replace(
            original,
            b"OpenFile=@AOS_NIX_OFFLINE_PREPARE_PROFILE@:aos-nix-offline-prepare-profile:read-only\n",
        )
        assert hashlib.sha256(measured).digest() == bytes(profile["unit_sha256"])
        assert [line for line in unit.splitlines() if line.startswith(b"ExecStart=")] == [
            f"ExecStart={profile['executable']['path']} {command}".encode()
        ]
        assert b"tpmrm0" not in unit
        for name in ("source_policy", "effective_matrix"):
            path = pathlib.Path(profile[name]["path"])
            assert path.parent.name.endswith("-aos-nix-offline-startup-profile-3")
            assert hashlib.sha256(path.read_bytes()).digest() == bytes(profile[name]["sha256"])
        profiles.append(profile)

    assert profiles[0]["unit_sha256"] != profiles[1]["unit_sha256"]
    profiles[1]["unit_sha256"] = profiles[0]["unit_sha256"]
    assert profiles[0] == profiles[1]
    PY
    mkdir -p "$out"
    printf '%s\n' 'PASS: distinct V6 approval delivery; no hardware admission' > "$out/result"
  ''
