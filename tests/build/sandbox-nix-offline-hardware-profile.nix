# Checks both manual hardware contracts without approving or executing a job.
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
    unit = pkgs.writeTextFile {
      name = "sandbox-nix-offline-${command}-unit";
      text = cfg.systemd.units."aos-sandbox-nix-floor-provision.service".text;
    };
  in
    assert builtins.all (check: check.assertion) cfg.assertions;
    assert service.DeviceAllow == ["/dev/tpmrm0 rw"];
    assert service.PrivateDevices == false;
    assert builtins.length service.OpenFile == 2;
    assert builtins.isString cfg.environment.etc."systemd/system/aos-sandboxd.service".source;
    assert cfg.systemd.services.aos-sandbox-nix-floor-provision.wantedBy == [];
    assert cfg.systemd.services.aos-sandbox-nix-floor-provision.requiredBy == []; {
      inherit profile unit;
      etcDump = cfg.system.build.etcDump;
    };
  initialize = caseFor "initialize";
  recover = caseFor "recover";
in
  pkgs.runCommand "sandbox-nix-offline-hardware-profile-check" {
    buildDeps = [pkgs.python3 initialize.etcDump recover.etcDump];
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
        ("initialize", "recover"), sys.argv[1::2], sys.argv[2::2], strict=True
    ):
        profile_path = pathlib.Path(profile_name)
        profile = json.loads(profile_path.read_bytes())
        unit = pathlib.Path(unit_name).read_bytes()
        original = (
            f"OpenFile={profile_path}:aos-nix-offline-prepare-profile:read-only\n"
        ).encode()
        assert unit.splitlines(keepends=True).count(original) == 1
        measured = unit.replace(
            original,
            b"OpenFile=@AOS_NIX_OFFLINE_PREPARE_PROFILE@:aos-nix-offline-prepare-profile:read-only\n",
        )
        assert hashlib.sha256(measured).digest() == bytes(profile["unit_sha256"])

        executable = profile["executable"]["path"]
        start = f"ExecStart={executable} {command}\n".encode()
        starts = [line for line in measured.splitlines(keepends=True) if line.startswith(b"ExecStart=")]
        assert starts == [start], starts
        neutral = measured.replace(start, b"ExecStart=@AOS_NIX_OFFLINE_HARDWARE_COMMAND@\n")
        hardware = profile["hardware"]
        assert hardware["format"] == "AOS_NIX_OFFLINE_HARDWARE_5"
        assert hashlib.sha256(neutral).digest() == bytes(hardware["unit_mode_neutral_sha256"])

        contract = pathlib.Path(hardware["helper"]["path"]).with_suffix(".contract").read_bytes()
        assert hashlib.sha256(contract).digest() == bytes(hardware["compiled_contract_sha256"])
        policy_paths = []
        for field, name in (
            ("source_policy", "source-policy.33"),
            ("effective_matrix", "effective-policy.tsv"),
        ):
            pin = profile[field]
            path = pathlib.Path(pin["path"])
            assert str(path).endswith(f"-aos-nix-offline-startup-profile-3/{name}")
            assert hashlib.sha256(path.read_bytes()).digest() == bytes(pin["sha256"])
            policy_paths.append(path.parent)
        assert policy_paths[0] == policy_paths[1]
        profiles.append(profile)

    # Recovery may change only its independently measured invocation hash.
    # This matches the installed consumer's exact initialize-profile comparison.
    assert profiles[0]["unit_sha256"] != profiles[1]["unit_sha256"]
    profiles[1]["unit_sha256"] = profiles[0]["unit_sha256"]
    assert profiles[0].keys() == profiles[1].keys(), "initialize/recover profile fields differ"
    differences = sorted(name for name in profiles[0] if profiles[0][name] != profiles[1][name])
    assert not differences, ("initialize/recover profile pins differ", differences)
    PY
    mkdir -p "$out"
    printf '%s\n' 'PASS: immutable offline hardware contracts; no job approval or TPM effect' > "$out/result"
  ''
