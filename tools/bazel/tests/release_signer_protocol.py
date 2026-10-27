"""Exercises installed signing adapters with disposable keys and public verifiers."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile


REQUEST_DOMAIN = b"aos.release.signer-exchange/v1\0"
RESPONSE_DOMAIN = b"aos.release.signer-exchange-response/v1\0"
SIGNING_DOMAIN = b"aos.release.signing-request/v1\0"


def canonical(value):
    """Encodes the fixture's integer-and-string subset of canonical JSON."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def frame(data):
    return struct.pack(">Q", len(data)) + data


def exchange(request, payload):
    return REQUEST_DOMAIN + frame(canonical(request)) + frame(payload)


def response(data):
    """Rejects incomplete, noncanonical or trailing response frames."""
    if not data.startswith(RESPONSE_DOMAIN):
        raise ValueError("signer omitted its response domain")
    offset = len(RESPONSE_DOMAIN)
    frames = []
    for _ in range(2):
        length, = struct.unpack(">Q", data[offset:offset + 8])
        offset += 8
        selected = data[offset:offset + length]
        if len(selected) != length:
            raise ValueError("signer returned a truncated response")
        frames.append(selected)
        offset += length
    if offset != len(data) or canonical(json.loads(frames[0])) != frames[0]:
        raise ValueError("signer returned noncanonical or trailing response bytes")
    return json.loads(frames[0]), frames[1]


def qualify(packages, openssl, ssh_keygen, sbsign, sbverify, clang, lld_link):
    """Verifies signatures and fail-closed behavior for both installed builders."""
    def tool(arguments, data=None):
        result = subprocess.run(list(map(str, arguments)), input=data, capture_output=True, timeout=60)
        if result.returncode:
            raise ValueError("independent signing fixture tool failed: " + result.stderr.decode(errors="replace"))
        return result.stdout

    with tempfile.TemporaryDirectory(prefix="release-signer-qualification-") as temporary:
        root = Path(temporary)
        ed, ed_public = root / "ed.pem", root / "ed-public.pem"
        rsa, rsa_public, certificate = root / "rsa.pem", root / "rsa-public.pem", root / "rsa.crt"
        ssh = root / "ssh"
        tool([openssl, "genpkey", "-algorithm", "ED25519", "-out", ed])
        tool([openssl, "pkey", "-in", ed, "-pubout", "-out", ed_public])
        ed_der = tool([openssl, "pkey", "-in", ed, "-pubout", "-outform", "DER"])
        tool([openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", rsa])
        tool([openssl, "pkey", "-in", rsa, "-pubout", "-out", rsa_public])
        tool([openssl, "req", "-new", "-x509", "-key", rsa, "-subj", "/CN=Disposable qualification key",
              "-days", "1", "-out", certificate])
        tool([ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", ssh])
        for key in [ed, rsa, ssh]:
            key.chmod(0o600)
        ssh_public = (root / "ssh.pub").read_text().split()
        trust_line = "andyl-experimental:Ed25519:" + ssh_public[1]
        roles = ["release-evidence", "qualification", "cache", "provenance", "registry",
                 "kernel-module", "pcr-policy", "secure-boot-db"]
        material = {
            "ed": {"kind": "ed25519-pkcs8-pem", "private_key": str(ed)},
            "ssh": {"kind": "openssh-ed25519", "private_key": str(ssh), "trust_line": trust_line},
            "rsa": {"kind": "rsa-x509", "private_key": str(rsa), "certificate": str(certificate)},
        }
        material_digests = {"ed": digest(ed_der[-32:]), "ssh": digest(trust_line.encode()),
                            "rsa": digest(certificate.read_bytes())}
        config = {"schema_version": "aos.release.file-signer-config/v1", "provider_revision": "test-provider-v1",
                  "registries": ["andyl/experimental"], "tools": {"openssl": str(openssl), "sbsign": str(sbsign)},
                  "keys": [{"key_id": key, "roles": roles, "verification_identity": key,
                            "material": value} for key, value in material.items()]}
        config_path = root / "config.json"

        def write_config(value):
            config_path.write_bytes(canonical(value))
            config_path.chmod(0o600)

        write_config(config)
        records = []

        def run(arguments, data=b"", expected=0):
            results = []
            for driver in ["ordinary", "bazel"]:
                executable = Path(packages[driver]["out"]) / "bin/aos-release-signer"
                result = subprocess.run([str(executable), "--config", str(config_path), *arguments],
                                        input=data, capture_output=True, timeout=60,
                                        env={"PATH": "", "HOME": str(root), "TMPDIR": str(root)})
                results.append((result.returncode, result.stdout, result.stderr))
            if results[0] != results[1] or results[0][0] != expected:
                raise ValueError(f"installed signer behavior differs for {arguments}: {results!r}")
            if expected and (results[0][1] or not results[0][2]):
                raise ValueError("signer refusal emitted a result or omitted its diagnostic")
            return results[0]

        for arguments, expected in [(["--help"], 0), (["--version"], 0), (["unknown-operation"], 2),
                                    (["sign-evidence"], 2), (["show"], 0)]:
            status, stdout, stderr = run(arguments, expected=expected)
            if expected == 0 and stderr:
                raise ValueError("successful signer command emitted a diagnostic")
            if arguments == ["show"] and any(value.encode() not in stdout for value in material_digests.values()):
                raise ValueError("public inspection omitted the independently derived key identities")
            records.append({"case": "cli:" + " ".join(arguments), "status": status,
                            "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr)})

        def request(payload, key="ed", algorithm="ed25519", role="release-evidence",
                    operation="sign-payload", context=None):
            return {"schema_version": "aos.release.signing-request/v1", "request_id": "test/request-1",
                    "nonce": "ab" * 32, "registry": "andyl/experimental", "release_id": "release-1",
                    "plan_digest": digest(b"plan"), "manifest_digest": None, "role": role, "key_id": key,
                    "provider_revision": "test-provider-v1", "algorithm": algorithm, "operation": operation,
                    "context": context or {"kind": "payload", "artifact_kind": "evidence"},
                    "payload_digest": digest(payload), "approval_policy_digest": digest(b"approval")}

        def signed(name, selected, payload):
            _, stdout, stderr = run(["sign-exchange-v1"], exchange(selected, payload))
            if stderr:
                raise ValueError("successful signing emitted diagnostics")
            result, output = response(stdout)
            expected = {"schema_version": "aos.release.signature-response/v1",
                        "request_digest": digest(SIGNING_DOMAIN + canonical(selected)),
                        **{key: selected[key] for key in ["role", "key_id", "provider_revision", "algorithm"]},
                        "provider_operation_id": "file-signer-test-request-1",
                        "verification_identity": selected["key_id"],
                        "verification_material_digest": material_digests[selected["key_id"]],
                        "output_digest": digest(output) if output else None,
                        "signature_base64": result["signature_base64"]}
            if result != expected:
                raise ValueError("signer response is not bound to the complete public request")
            records.append({"case": name, "response": result, "output_bytes": len(output),
                            "output_sha256": digest(output)})
            return base64.b64decode(result["signature_base64"], validate=True), output

        def verify_ed(signature, payload):
            (root / "signature").write_bytes(signature)
            (root / "payload").write_bytes(payload)
            tool([openssl, "pkeyutl", "-verify", "-pubin", "-inkey", ed_public, "-rawin",
                  "-in", root / "payload", "-sigfile", root / "signature"])

        payload = b"qualification payload\0with exact framing\n"
        selected = request(payload)
        signature, output = signed("ed25519-request-digest", selected, payload)
        verify_ed(signature, hashlib.sha256(SIGNING_DOMAIN + canonical(selected)).digest())
        if output:
            raise ValueError("detached signer returned transformed bytes")
        selected_raw = request(payload, algorithm="ed25519-payload", role="cache",
                               context={"kind": "payload", "artifact_kind": "narinfo-fingerprint"})
        signature, _ = signed("ed25519-raw-payload", selected_raw, payload)
        verify_ed(signature, payload)
        signature, _ = signed("rsa-sha256-payload", request(payload, "rsa", "public-key-sha256"), payload)
        (root / "signature").write_bytes(signature)
        (root / "payload").write_bytes(payload)
        tool([openssl, "dgst", "-sha256", "-verify", rsa_public, "-signature", root / "signature", root / "payload"])

        allowed = root / "allowed-signers"
        allowed.write_text("qualification " + " ".join(ssh_public[:2]) + "\n")
        for name, context, operation, namespace, role in [
            ("openssh-git", {"kind": "git", "object_kind": "commit"},
             "sign-git-object", "git", "registry"),
            ("openssh-dsse", {"kind": "payload", "artifact_kind": "package-provenance-dsse"},
             "sign-payload", "aos-package-provenance-dsse-v1", "provenance"),
        ]:
            selected_ssh = request(payload, "ssh", "sshsig-ed25519", role, operation, context)
            signature, _ = signed(name, selected_ssh, payload)
            (root / "signature").write_bytes(signature)
            tool([ssh_keygen, "-Y", "verify", "-f", allowed, "-I", "qualification", "-n", namespace,
                  "-s", root / "signature"], payload)

        catalog_payload = canonical({"schema": "https://andyl.com/aos/registry/tuf/targets/v1",
                                     "spec_version": "aos-tuf-1", "registry": "andyl-experimental", "version": 1})
        catalog = request(catalog_payload, "ssh", "sshsig-ed25519", "registry", context={
            "kind": "catalog-tuf", "catalog_registry": "andyl-experimental",
            "metadata_role": "targets", "metadata_version": 1})
        signature, _ = signed("openssh-catalog", catalog, catalog_payload)
        (root / "signature").write_bytes(signature)
        tool([ssh_keygen, "-Y", "verify", "-f", allowed, "-I", "qualification",
              "-n", "aos-registry-tuf-v1", "-s", root / "signature"], catalog_payload)

        policy = canonical({"sha256": [{"pcrs": [7, 11], "pol": "ab" * 32}]})
        policy_request = request(policy, "rsa", "pcr-policy", "pcr-policy", "sign-pcr-policy", {
            "kind": "pcr-policy", "platform": "x86_64-linux", "system_variant": "qualification", "pcrs": [7, 11]})
        _, transformed = signed("rsa-pcr-policy", policy_request, policy)
        document = json.loads(transformed)
        public_der = tool([openssl, "pkey", "-pubin", "-in", rsa_public, "-outform", "DER"])
        record, = document["sha256"]
        if canonical(document) != transformed or record["pcrs"] != [7, 11] or record["pol"] != "ab" * 32:
            raise ValueError("PCR signing changed the selected policy")
        if record["pkfp"] != hashlib.sha256(public_der).hexdigest():
            raise ValueError("PCR signing omitted the independently derived public fingerprint")
        (root / "signature").write_bytes(base64.b64decode(record["sig"], validate=True))
        (root / "payload").write_bytes(bytes.fromhex(record["pol"]))
        tool([openssl, "dgst", "-sha256", "-verify", rsa_public, "-signature", root / "signature", root / "payload"])

        # These source-built object fixtures exercise formats, without claiming
        # a live kernel load or firmware boot with the disposable authority.
        source = root / "fixture.c"
        source.write_text("unsigned long efi_main(void *image, void *table) { return 0; }\n")
        module = root / "fixture.ko"
        tool([clang, "-ffreestanding", "-fno-stack-protector", "-c", source, "-o", module])
        module_bytes = module.read_bytes()
        module_request = request(module_bytes, "rsa", "kernel-module", "kernel-module", "sign-kernel-module", {
            "kind": "kernel-module", "platform": "x86_64-linux", "system_variant": "qualification",
            "kernel_release": "qualification-1", "module_id": "kernel/fixture.ko"})
        _, transformed = signed("rsa-kernel-module-cms", module_request, module_bytes)
        magic = b"~Module signature appended~\n"
        header = transformed[-len(magic) - 12:-len(magic)]
        if not transformed.startswith(module_bytes) or not transformed.endswith(magic) or header[:8] != bytes([0, 0, 2, 0, 0, 0, 0, 0]):
            raise ValueError("kernel module signing changed the original object or signature trailer")
        length, = struct.unpack(">I", header[8:])
        signature = transformed[len(module_bytes):-len(magic) - 12]
        if len(signature) != length:
            raise ValueError("kernel module signature length is not exact")
        (root / "signature").write_bytes(signature)
        tool([openssl, "cms", "-verify", "-binary", "-inform", "DER", "-in", root / "signature",
              "-content", module, "-certfile", certificate, "-noverify", "-out", root / "verified-module"])
        if (root / "verified-module").read_bytes() != module_bytes:
            raise ValueError("independent CMS verifier did not recover the exact module bytes")

        pe_object, unsigned_pe = root / "fixture.obj", root / "unsigned.efi"
        tool([clang, "--target=x86_64-pc-windows-msvc", "-ffreestanding", "-fno-stack-protector",
              "-c", source, "-o", pe_object])
        tool([lld_link, "/subsystem:efi_application", "/entry:efi_main", "/nodefaultlib",
              "/out:" + str(unsigned_pe), pe_object])
        pe_bytes = unsigned_pe.read_bytes()
        pe_request = request(pe_bytes, "rsa", "authenticode", "secure-boot-db", "sign-pe", {
            "kind": "pe", "platform": "x86_64-linux", "system_variant": "qualification",
            "pe_machine": "8664", "sbat_generation": 1, "artifact_kind": "bootloader"})
        _, transformed = signed("rsa-authenticode", pe_request, pe_bytes)
        signed_pe = root / "signed.efi"
        signed_pe.write_bytes(transformed)
        tool([sbverify, "--cert", certificate, signed_pe])

        evidence = root / "evidence.json"
        evidence.write_bytes(canonical({"schema_version": "qualification/v1", "result": "PASS"}))
        envelope = root / "envelope.json"
        arguments = ["sign-evidence", "--key-id", "ed", "--payload", str(evidence), "--output", str(envelope)]
        envelopes = []
        # Both builders use the same destination, so output diagnostics can be
        # compared exactly while create-new semantics remain observable.
        for driver in ["ordinary", "bazel"]:
            executable = Path(packages[driver]["out"]) / "bin/aos-release-signer"
            result = subprocess.run([str(executable), "--config", str(config_path), *arguments],
                                    capture_output=True, timeout=60)
            if result.returncode or result.stderr or not envelope.is_file():
                raise ValueError("installed signer did not write its evidence envelope")
            envelopes.append((result.stdout, envelope.read_bytes()))
            envelope.unlink()
        if envelopes[0] != envelopes[1]:
            raise ValueError("installed evidence envelopes differ")
        document = json.loads(envelopes[0][1])
        if document["schema_version"] != "aos.hub.signed-release-evidence/v1" or document["key_id"] != "ed" or document["payload"] != json.loads(evidence.read_bytes()):
            raise ValueError("evidence envelope changed its public document")
        verify_ed(base64.b64decode(document["signature_base64"], validate=True),
                  hashlib.sha256(b"aos.hub.release-evidence-signature/v1\0" + evidence.read_bytes()).digest())
        records.append({"case": "evidence-envelope", "envelope_sha256": digest(envelopes[0][1])})
        envelope.write_bytes(b"existing output must survive")
        run(arguments, expected=1)
        if envelope.read_bytes() != b"existing output must survive":
            raise ValueError("evidence signer overwrote an existing destination")
        envelope.unlink()
        evidence.write_bytes(evidence.read_bytes() + b"\n")
        run(arguments, expected=1)
        if envelope.exists():
            raise ValueError("noncanonical evidence created an output")
        records.extend([{"case": "refusal:evidence-overwrite", "status": 1},
                        {"case": "refusal:noncanonical-evidence", "status": 1}])

        malformed = [("empty", b""), ("domain", b"x" * len(REQUEST_DOMAIN)),
                     ("oversize-request-header", REQUEST_DOMAIN + struct.pack(">Q", 1024 * 1024 + 1)),
                     ("truncated-request", REQUEST_DOMAIN + struct.pack(">Q", 12) + b"{}"),
                     ("oversize-payload-header", REQUEST_DOMAIN + frame(canonical(selected)) + struct.pack(">Q", 2 * 1024**3 + 1)),
                     ("truncated-payload", exchange(selected, payload)[:-1]),
                     ("trailing-byte", exchange(selected, payload) + b"x"),
                     ("noncanonical-request", REQUEST_DOMAIN + frame(canonical(selected) + b"\n") + frame(payload)),
                     ("payload-mismatch", exchange(selected, payload + b"x"))]
        for field, value in [("provider_revision", "other"), ("key_id", "unknown"),
                             ("nonce", "AB" * 32), ("schema_version", "unknown"), ("algorithm", "authenticode")]:
            changed = {**selected, field: value}
            malformed.append(("request:" + field, exchange(changed, payload)))
        for name, data in malformed:
            run(["sign-exchange-v1"], data, 1)
            records.append({"case": "refusal:" + name, "stdin_bytes": len(data), "status": 1})

        changed = copy.deepcopy(config)
        changed["keys"][0]["roles"] = ["qualification"]
        write_config(changed)
        run(["sign-exchange-v1"], exchange(selected, payload), 1)
        records.append({"case": "refusal:unauthorized-role", "status": 1})
        write_config(config)
        for mode in [0o640, 0o604, 0o620]:
            ed.chmod(mode)
            run(["show"], expected=1)
            records.append({"case": "refusal:private-key-mode:" + oct(mode), "status": 1})
        ed.chmod(0o600)
        for kind in ["symlink", "hardlink"]:
            alias = root / "alias"
            alias.symlink_to(ed) if kind == "symlink" else os.link(ed, alias)
            changed = copy.deepcopy(config)
            changed["keys"][0]["material"]["private_key"] = str(alias)
            write_config(changed)
            run(["show"], expected=1)
            alias.unlink()
            records.append({"case": "refusal:private-key-" + kind, "status": 1})
        write_config(config)
        return {"cases": records, "independent_verifiers": [str(openssl), str(ssh_keygen), str(sbverify)],
                "private_keys": "Generated in a disposable sandbox directory and never retained."}
