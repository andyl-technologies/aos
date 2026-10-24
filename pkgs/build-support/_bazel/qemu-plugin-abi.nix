##! Exports checked QEMU identities as declared Rust compiler inputs.
{pkgs}: let
  pluginAbiSource = ../../../crates/crucible/crucible-qemu-plugin/src/abi.rs;
  shmemAbiSource = ../../../crates/crucible/crucible-qemu-shmem/src/lib.rs;
  qemu = pkgs.qemu-crucible;
  check = import ../../emulation/_crucible-qemu-plugin-abi.nix {
    inherit (pkgs) lib glib;
    inherit pluginAbiSource shmemAbiSource;
    qemu-crucible = qemu;
  };
in
  pkgs.mkDerivation {
    pname = "aos-bazel-qemu-plugin-abi";
    version = "1";
    src = null;
    buildDeps = [pkgs.glib.dev pkgs.glib.tools pkgs.pkg-config qemu pkgs.python3];
    sharedBuildCache = false;
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;
    phases = [
      {
        name = "check";
        script = check;
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          printf '%s\n' \
            "CRUCIBLE_QEMU_BUILD_ID=$CRUCIBLE_QEMU_BUILD_ID" \
            "CRUCIBLE_QEMU_ATOMIC_PATCH_HASH=$CRUCIBLE_QEMU_ATOMIC_PATCH_HASH" \
            "CRUCIBLE_SHMEM_HEADER_HASH=$CRUCIBLE_SHMEM_HEADER_HASH" \
            > "$out/plugin.env"
          ${pkgs.python3}/bin/python3 - "$out/identity.json" \
            "$qemu_plugin_api_version" "$shmem_abi_version" <<'PYTHON'
          import json
          from pathlib import Path
          import sys

          identity = json.loads(${builtins.toJSON (builtins.toJSON {
            schema_version = 1;
            qemu = toString qemu;
            qemu_build_id = qemu.passthru.qemuBuildIdentity;
            atomic_patch_sha256 = qemu.passthru.atomicPatchHash;
            shmem_header_sha256 = qemu.passthru.shmemHeaderHash;
            plugin_declarations_sha256 = builtins.hashFile "sha256" pluginAbiSource;
            shmem_declarations_sha256 = builtins.hashFile "sha256" shmemAbiSource;
          })})
          identity["qemu_plugin_api_version"] = int(sys.argv[2])
          identity["shmem_abi_version"] = int(sys.argv[3])
          Path(sys.argv[1]).write_text(json.dumps(identity, indent=2, sort_keys=True) + "\n")
          PYTHON
          cat > "$out/BUILD.bazel" <<'BUILD'
          exports_files(["plugin.env", "identity.json"], visibility = ["//visibility:public"])
          BUILD
          touch "$out/REPO.bazel"
        '';
      }
    ];
  }
