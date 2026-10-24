##! Rejects either Rust ABI version drifting from the packaged QEMU headers.
{pkgs}: let
  pluginAbiSource = ../../crates/crucible/qemu/crucible-qemu-plugin/src/abi.rs;
  shmemAbiSource = ../../crates/crucible/protocol/crucible-qemu-shmem/src/lib.rs;
  check = pluginSource: shmemSource:
    import ../../pkgs/emulation/_crucible-qemu-plugin-abi.nix {
      inherit (pkgs) lib glib qemu-crucible;
      pluginAbiSource = pluginSource;
      shmemAbiSource = shmemSource;
    };
  drift = source: declaration: let
    original = builtins.readFile source;
    changed = builtins.replaceStrings [declaration] ["${declaration}100000 + "] original;
  in
    assert changed != original;
      builtins.toFile "qemu-abi-version-drift.rs" changed;
  pluginDrift = drift pluginAbiSource "pub const QEMU_PLUGIN_API_VERSION: c_int = ";
  shmemDrift = drift shmemAbiSource "pub const ABI_VERSION: u32 = ";
  pluginScript = pkgs.writeTextFile {
    name = "qemu-plugin-version-drift";
    text = check pluginDrift shmemAbiSource;
  };
  shmemScript = pkgs.writeTextFile {
    name = "qemu-shmem-version-drift";
    text = check pluginAbiSource shmemDrift;
  };
  valid = import ../../pkgs/build-support/_bazel/qemu-plugin-abi.nix {inherit pkgs;};
in
  pkgs.runCommand "aos-bazel-qemu-plugin-abi-conformance" {
    buildDeps = [pkgs.glib.dev pkgs.glib.tools pkgs.pkg-config pkgs.qemu-crucible];
    sharedBuildCache = false;
  } ''
    mkdir -p "$out"
    cp ${valid}/identity.json "$out/identity.json"

    set +e
    ${pkgs.bash}/bin/bash -e ${pluginScript} > "$out/plugin-drift.log" 2>&1
    plugin_status=$?
    ${pkgs.bash}/bin/bash -e ${shmemScript} > "$out/shmem-drift.log" 2>&1
    shmem_status=$?
    set -e

    test "$plugin_status" -ne 0
    test "$shmem_status" -ne 0
    grep -q 'qemu-crucible header plugin API version does not match' "$out/plugin-drift.log"
    grep -q 'qemu-crucible generated shmem header ABI does not match' "$out/shmem-drift.log"
    printf '%s\n' 'matching headers: PASS' 'plugin version drift: rejected' \
      'shared-memory version drift: rejected' > "$out/results.txt"
  ''
