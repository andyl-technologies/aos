# Checks canonical external DATA against the actual selected credential roster.
{
  lib,
  pkgs,
  systems,
  ...
}: let
  credentials = import ../fleet/_method46-external-credentials.nix {inherit lib pkgs;};
  history = import ../fleet/_method46-external-history.nix {inherit lib pkgs;};
  initial = import ../fleet/_sandbox-method46-initial-system.nix {
    inherit lib pkgs systems;
    approvalPublicKeys = {
      controller = lib.genList (_: 11) 32;
      storage = lib.genList (_: 12) 32;
    };
  };
  roster =
    lib.genAttrs ["controller" "storage"] (purpose:
      initial.config.systemd.services."aos-sandbox-${purpose}-floor-initialize".serviceConfig.LoadCredential);
in
  pkgs.runCommand "sandbox-method46-external-credentials-check" {
    buildDeps = [pkgs.python3 pkgs.openssl credentials history];
    passAsFile = ["roster"];
    roster = builtins.toJSON roster;
    passthru = {inherit credentials;};
  } ''
    ${pkgs.python3}/bin/python3 - <<'PY'
    import hashlib
    import json
    import os
    import pathlib
    import subprocess

    root = pathlib.Path("inputs")
    root.mkdir(mode=0o700)
    node, epoch = root / "node", root / "epoch"
    node.write_bytes(bytes([0x11]) * 16)
    epoch.write_bytes(bytes([0x33]) * 16)
    tpm = root / "external-tpm"
    tpm.mkdir(mode=0o700)
    # Shape-only input records. Actual installed qualification must use records
    # observed from the independently prepared persistent vTPM state.
    records = [
        bytes([role + 1]) * 32 + b"\0\x0b" + bytes([role + 3]) * 32 + bytes(64)
        for role in (0, 1)
    ]
    for role, record in enumerate(records):
        path = tpm / f"endpoint-{role}"
        path.write_bytes(record)
        path.chmod(0o600)
    pins = []
    for role in ("controller", "storage"):
        private, public = root / f"{role}.pem", root / f"{role}.public"
        subprocess.run([
            "${pkgs.openssl}/bin/openssl", "genpkey", "-algorithm", "ED25519",
            "-out", str(private),
        ], check=True, capture_output=True)
        encoded = subprocess.check_output([
            "${pkgs.openssl}/bin/openssl", "pkey", "-in", str(private),
            "-pubout", "-outform", "DER",
        ])
        assert encoded[:12] == bytes.fromhex("302a300506032b6570032100")
        public.write_bytes(encoded[12:])
        pins.append(public)
    native = root / "history"
    subprocess.run(["${history}/bin/aos-method46-external-history", str(native)], check=True)
    cut = native / "expected-cut.json"
    arguments = [
        "${credentials}/bin/aos-method46-external-credentials",
        str(node), str(epoch), str(tpm), *map(str, pins), str(cut),
    ]

    def prepare(output):
        subprocess.run([*arguments, str(output)], check=True)
        return output / "system-credentials"

    delivered = prepare(root / "first")
    second = prepare(root / "second")
    roster = json.loads(pathlib.Path(os.environ["rosterPath"]).read_text())
    required = set()
    for purpose, entries in roster.items():
        assert len(entries) == 29, entries
        for entry in entries:
            alias, source = entry.split(":", 1)
            assert source.startswith("/run/credentials/@system/")
            path = delivered / pathlib.Path(source).name
            assert path.is_file(), (purpose, alias, path)
            required.add(path.name)
    assert len(required) == 25  # Shared normal pins; distinct per-purpose TPM inputs.
    for name in required:
        if "method46" not in name and name != "qualification-node-id":
            assert (delivered / name).read_bytes() != (second / name).read_bytes()
    for endpoint in ("Host", "Storage", "Mount", "Network"):
        client = delivered / f"qualification-{endpoint}-Manifest"
        broker = delivered / f"qualification-{endpoint.lower()}-broker-manifest"
        assert client.read_bytes() == broker.read_bytes()
        for client_suffix, broker_suffix in (("HelloKey", "hello"), ("RecordKey", "outcome")):
            client_key = delivered / f"qualification-{endpoint}-{client_suffix}"
            broker_key = delivered / f"qualification-{endpoint.lower()}-broker-{broker_suffix}"
            assert client_key.read_bytes() != broker_key.read_bytes()
    nix_broker = delivered / "qualification-nix-session-manifest"
    nix_client = delivered / "qualification-nix-session-clientManifest"
    assert nix_broker.read_bytes() == nix_client.read_bytes()
    for path in (root / "first").rglob("*"):
        assert path.stat().st_mode & 0o7777 == (0o700 if path.is_dir() else 0o600)
        if path.is_file():
            assert path.stat().st_nlink == 1

    native_cut = json.loads(cut.read_bytes())
    for role, purpose in enumerate(("controller", "storage")):
        prefix = f"qualification-method46-{purpose}"
        provision = (delivered / f"{prefix}-provision").read_bytes()
        assert len(provision) == 160 and provision[:12] == b"AOSBTD01\0\x01\0\0"
        assert provision[28:44] == node.read_bytes()
        assert provision[44:60] == epoch.read_bytes()
        assert provision[124:158] == records[role][32:66]
        assert provision[92:124] == hashlib.sha256(records[role][32:66]).digest()
        assert (delivered / f"{prefix}-index-auth").read_bytes() == records[role][:32]
        assert (delivered / f"{prefix}-approval-public").read_bytes() == pins[role].read_bytes()
        checkpoint_path = root / "first" / "operator-expectations" / f"{purpose}-checkpoint"
        checkpoint = checkpoint_path.read_bytes()
        assert len(checkpoint) == 156
        assert int.from_bytes(checkpoint[52:60], "big") == native_cut["next_sequence"]
        assert checkpoint[60:92] == bytes(native_cut["head"])
        sidecar = checkpoint_path.with_name(f"{purpose}-sidecar").read_bytes()
        assert len(sidecar) == 429 and sidecar.count(checkpoint) == 1
        assert len(checkpoint_path.with_name(f"{purpose}-nv").read_bytes()) == 32

    def output_bytes():
        return {
            path.relative_to(root / "first"): path.read_bytes()
            for path in (root / "first").rglob("*") if path.is_file()
        }

    retained = output_bytes()
    assert subprocess.run([*arguments, str(root / "first")], capture_output=True).returncode != 0
    assert retained == output_bytes()

    for changed in (bytes(16), bytes(17)):
        node.write_bytes(changed)
        refused = root / "invalid-node"
        assert subprocess.run([*arguments, str(refused)], capture_output=True).returncode != 0
        assert not refused.exists()
    node.write_bytes(bytes([0x11]) * 16)
    duplicate_pin = [*arguments]
    duplicate_pin[5] = duplicate_pin[4]
    refused = root / "shared-approver"
    assert subprocess.run([*duplicate_pin, str(refused)], capture_output=True).returncode != 0
    assert not refused.exists()
    original_cut = cut.read_bytes()
    changed_cut = dict(native_cut, next_sequence=1)
    cut.write_text(json.dumps(changed_cut))
    refused = root / "empty-history"
    assert subprocess.run([*arguments, str(refused)], capture_output=True).returncode != 0
    assert not refused.exists()
    cut.write_bytes(original_cut)
    (tpm / "endpoint-0").chmod(0o644)
    refused = root / "unsafe-record"
    assert subprocess.run([*arguments, str(refused)], capture_output=True).returncode != 0
    assert not refused.exists()
    PY
    mkdir -p "$out"
    printf '%s\n' 'PASS: canonical runtime external credentials cover both actual 29-member rosters; independent normal keys and expected native cuts; no installed Source or TPM authority' > "$out/result"
  ''
