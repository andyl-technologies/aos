# Dedicated native helper evidence. This artifact is deliberately outside gate
# auto-discovery and does not qualify complete cache admission or cancellation.
{
  pkgs,
  lib,
  sourceGateWithInputs,
}: let
  testing = import ../../lib/testing {inherit pkgs lib;};
  image =
    sourceGateWithInputs {
      runtimeDeps = [pkgs.rust pkgs.rust.dev] ++ (pkgs.rust.runtimeDeps or []);
      nukeRefsKeep = [pkgs.terrane.src];
    } "host-quota-proof-image" ''
      cd crates
      cargo test --frozen --offline -p terrane-fs --lib \
        --test host_quota_protocol --test host_quota_native \
        --no-run --message-format=json > "$TMPDIR/host-quota-build.jsonl"
      cargo test --frozen --offline -p aos-terrane --test host_quota_config \
        --no-run --message-format=json >> "$TMPDIR/host-quota-build.jsonl"
      rustc --print target-libdir > "$TMPDIR/host-quota-rust-libdir"
      python3 - "$TMPDIR/host-quota-build.jsonl" "$out" "$TMPDIR/host-quota-rust-libdir" <<'PY'
      import json
      import os
      import pathlib
      import shutil
      import subprocess
      import sys

      output = pathlib.Path(sys.argv[2])
      (output / "bin").mkdir()
      (output / "lib").mkdir()
      expected = {
          "terrane_fs": {
              "kernel_peer_identity_is_not_a_packet_assertion",
              "oversized_native_packet_is_rejected_after_receive_truncation",
              "descriptor_ancillary_is_rejected_without_returning_custody",
          },
          "host_quota_protocol": {
              "query_rejects_ambiguous_extended_or_truncated_packets",
              "error_response_cannot_smuggle_quota_evidence",
              "nonroot_helper_identity_cannot_mint_native_evidence",
              "provisioning_guard_excludes_factories_until_exclusive_custody_ends",
          },
          "host_quota_config": {
              "configuration_rejects_mutation_command_fields",
              "host_quota_admin_ledger_preserves_domain_and_project_vm",
          },
          "host_quota_native": {
              "host_quota_native_privilege_and_helper_vm",
              "host_quota_vm_role",
          },
      }
      artifacts = {}
      for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
          event = json.loads(line)
          name = event.get("target", {}).get("name")
          if (event.get("reason") == "compiler-artifact" and name in expected
                  and event.get("profile", {}).get("test") and event.get("executable")):
              if name in artifacts:
                  raise SystemExit("duplicate host-quota test artifact")
              artifacts[name] = pathlib.Path(event["executable"])
      if set(artifacts) != set(expected):
          raise SystemExit("missing host-quota proof executable")
      directories = {pathlib.Path(pathlib.Path(sys.argv[3]).read_text().strip())}
      directories.update(executable.parent for executable in artifacts.values())
      for directory in directories:
          for library in directory.glob("*.so*"):
              if library.is_file():
                  shutil.copy2(library, output / "lib" / library.name)
      environment = dict(os.environ, LD_LIBRARY_PATH=str(output / "lib"))
      evidence = {}
      for name, executable in artifacts.items():
          installed = output / "bin" / name
          shutil.copy2(executable, installed)
          listed = subprocess.run([str(installed), "--list", "--format", "terse"], check=True, text=True, capture_output=True, env=environment).stdout
          prefix = "host_quota::socket::tests::" if name == "terrane_fs" else ""
          actual = {line.removesuffix(": test").removeprefix(prefix) for line in listed.splitlines() if line.endswith(": test") and line.startswith(prefix)}
          if actual != expected[name]:
              raise SystemExit(f"host-quota exact inventory mismatch: {name}: {actual}")
          evidence[name] = {"inventory": sorted(actual), "executed": []}
          if name != "host_quota_native":
              for case in sorted(actual):
                  if case == "host_quota_admin_ledger_preserves_domain_and_project_vm":
                      continue
                  result = subprocess.run([str(installed), "--exact", prefix + case, "--nocapture"], check=True, text=True, capture_output=True, env=environment)
                  if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in result.stdout:
                      raise SystemExit(f"host-quota case did not execute exactly once: {case}")
                  evidence[name]["executed"].append({"case": case, "stdout": result.stdout, "stderr": result.stderr})
      (output / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
      PY
    '';
  native = testing.mkVMTest {
    name = "terrane-host-quota-helper-ext4";
    memory = 1024;
    rootfsDeps = [image pkgs.coreutils pkgs.util-linux pkgs.e2fsprogs];
    testScript = ''
      set -eu
      mount -o remount,rw /
      mkdir -p /var/lib/terrane-host-quota-proof /mnt/terrane-host-quota
      truncate -s 96M /var/lib/terrane-host-quota-proof/quota.img
      mkfs.ext4 -F -O project,quota,verity -E quotatype=prjquota /var/lib/terrane-host-quota-proof/quota.img
      mount -t ext4 -o loop,prjquota /var/lib/terrane-host-quota-proof/quota.img /mnt/terrane-host-quota
      trap 'umount /mnt/terrane-host-quota; rm -f /var/lib/terrane-host-quota-proof/quota.img; rmdir /mnt/terrane-host-quota /var/lib/terrane-host-quota-proof' EXIT
      export TERRANE_HOST_QUOTA_VM=1
      export TERRANE_HOST_QUOTA_ROOT=/mnt/terrane-host-quota/owner
      export LD_LIBRARY_PATH="${image}/lib"
      ${image}/bin/host_quota_native --exact host_quota_native_privilege_and_helper_vm --ignored --nocapture
      # An unsupported unprivileged user namespace fails this proof; it is
      # never reported as an executed negative witness.
      export TERRANE_HOST_QUOTA_ROLE=userns
      setpriv --reuid 840 --regid 840 --clear-groups \
        unshare --user --map-root-user \
        ${image}/bin/host_quota_native --exact host_quota_vm_role --ignored --nocapture
      rmdir /mnt/terrane-host-quota/owner
      export TERRANE_HOST_QUOTA_ADMIN_ROOT=/mnt/terrane-host-quota
      setpriv --bounding-set=-all,+sys_admin,+dac_read_search,+fowner,+chown,+fsetid \
        --clear-groups --inh-caps=-all --ambient-caps=-all \
        ${image}/bin/host_quota_config --exact host_quota_admin_ledger_preserves_domain_and_project_vm --ignored --nocapture
    '';
  };
in {
  inherit image native;
}
