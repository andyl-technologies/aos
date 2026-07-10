{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginVcpuIntrospection",
  taskIds ? [],
  openTaskIds ? ["T-PLUG-26"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginVcpu = builtins.readFile ../../crates/crucible-qemu-plugin/src/vcpu_introspection.rs;
  pluginRoundRobin = builtins.readFile ../../crates/crucible-qemu-plugin/src/round_robin.rs;
  pluginAbi = builtins.readFile ../../crates/crucible-qemu-plugin/src/abi.rs;
  pluginAbiTests = builtins.readFile ../../crates/crucible-qemu-plugin/src/abi/tests.rs;
  pluginInertness = builtins.readFile ../../crates/crucible-qemu-plugin/src/inertness.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  patchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-26 remains open until live QEMU callback integration";
        needle = "- [ ] **T-PLUG-26**";
      }
      {
        label = "per-vCPU register wording";
        needle = "per-vCPU register-file";
      }
      {
        label = "round-robin cursor wording";
        needle = "round-robin cursor reads";
      }
      {
        label = "side-effect-free wording";
        needle = "side-effect-free wrt `S`/`T`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" patchSpec [
      {
        label = "PATCH-46 register export";
        needle = "qemu_plugin_read_vcpu_regs";
      }
      {
        label = "PATCH-46 cursor export";
        needle = "qemu_plugin_rr_cursor";
      }
      {
        label = "arbitrary vCPU wording";
        needle = "arbitrary vCPU index, not only the current one";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "QEMU-34 all-vCPU registers";
        needle = "all N vCPUs' register files";
      }
      {
        label = "QEMU-34 cursor";
        needle = "round-robin cursor";
      }
      {
        label = "first_cpu defect wording";
        needle = "reading only `first_cpu` is a defect";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "vCPU introspection module exported";
        needle = "pub mod vcpu_introspection;";
      }
      {
        label = "vCPU introspection API re-exported";
        needle = "PluginVcpuIntrospector";
      }
      {
        label = "module map documents vCPU introspection";
        needle = "`vcpu_introspection` owns side-effect-free per-vCPU register and RR cursor";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/vcpu_introspection.rs" pluginVcpu [
      {
        label = "register symbol";
        needle = "QEMU_PLUGIN_READ_VCPU_REGS_SYMBOL";
      }
      {
        label = "cursor symbol";
        needle = "QEMU_PLUGIN_RR_CURSOR_SYMBOL";
      }
      {
        label = "compat register-list symbol";
        needle = "QEMU_PLUGIN_CRUCIBLE_GET_VCPU_REGISTERS_SYMBOL";
      }
      {
        label = "register read function type";
        needle = "pub type QemuReadVcpuRegsFn";
      }
      {
        label = "cursor read function type";
        needle = "pub type QemuReadRrCursorFn";
      }
      {
        label = "required introspector";
        needle = "pub struct PluginVcpuIntrospector";
      }
      {
        label = "all-vCPU input read";
        needle = "pub fn read_nvcpu_fingerprint_inputs";
      }
      {
        label = "N-vCPU fingerprint inputs";
        needle = "pub struct PluginNvcpuFingerprintInputs";
      }
      {
        label = "register digest";
        needle = "pub struct PluginVcpuRegisterDigest";
      }
      {
        label = "RR cursor";
        needle = "pub struct PluginRoundRobinCursor";
      }
      {
        label = "fixed digest bytes";
        needle = "PLUGIN_REGISTER_DIGEST_BYTES";
      }
      {
        label = "stable register digest helper";
        needle = "pub fn digest_register_file";
      }
      {
        label = "current vCPU range validation";
        needle = "CurrentVcpuOutOfRange";
      }
      {
        label = "cursor quantum validation";
        needle = "CursorPastQuantum";
      }
      {
        label = "all-vCPU read test";
        needle = "vcpu_introspection_reads_all_vcpu_registers_and_rr_cursor";
      }
      {
        label = "bad input no partial read test";
        needle = "vcpu_introspection_rejects_bad_cursor_before_register_reads";
      }
      {
        label = "stable digest test";
        needle = "vcpu_introspection_register_digest_is_stable_and_vcpu_qualified";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/round_robin.rs" pluginRoundRobin [
      {
        label = "RR switch quantum accessor";
        needle = "pub const fn rr_switch_quantum";
      }
      {
        label = "RR cursor position accessor";
        needle = "pub const fn cursor_position";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi.rs" pluginAbi [
      {
        label = "vCPU introspection install scaffold";
        needle = "pub fn install_required_vcpu_introspection_scaffold";
      }
      {
        label = "vCPU introspection install from qemu info";
        needle = "pub fn install_required_vcpu_introspection_scaffold_from_qemu_info";
      }
      {
        label = "register resolver";
        needle = "pub fn resolve_qemu_read_vcpu_regs_symbol";
      }
      {
        label = "cursor resolver";
        needle = "pub fn resolve_qemu_rr_cursor_symbol";
      }
      {
        label = "ABI vCPU introspection error";
        needle = "VcpuIntrospectionCapability";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi/tests.rs" pluginAbiTests [
      {
        label = "ABI vCPU introspection test";
        needle = "abi_install_requires_vcpu_introspection_symbols";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/inertness.rs" pluginInertness [
      {
        label = "register-read inertness count";
        needle = "vcpu_register_reads";
      }
      {
        label = "cursor-read inertness count";
        needle = "rr_cursor_reads";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin vCPU introspection check";
        needle = "qemuPluginVcpuIntrospection = import ./phase2-plugin-vcpu-introspection.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 plugin vCPU introspection check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-vcpu-introspection";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.rust
        pkgs.sed
      ];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-plugin-vcpu-introspection";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi

            target_dir="$TMPDIR/crucible-plugin-vcpu-introspection-target"
            run_exact_test() {
              filter="$1"
              expected="$2"
              list_file="$TMPDIR/test-list"
              output_file="$TMPDIR/test-output"

              cargo test \
                --frozen \
                --offline \
                --target-dir "$target_dir" \
                --manifest-path crates/Cargo.toml \
                -p crucible-qemu-plugin \
                "$filter" \
                -- --list > "$list_file"
              if [ "$(grep -Fx "$expected: test" "$list_file" | wc -l | tr -d ' ')" != 1 ]; then
                echo "expected exactly one listed test: $expected" >&2
                cat "$list_file" >&2
                exit 1
              fi

              cargo test \
                --frozen \
                --offline \
                --target-dir "$target_dir" \
                --manifest-path crates/Cargo.toml \
                -p crucible-qemu-plugin \
                "$filter" \
                -- --exact --test-threads=1 > "$output_file"
              if ! grep -q 'test result: ok. 1 passed;' "$output_file"; then
                echo "expected exactly one passed test: $expected" >&2
                cat "$output_file" >&2
                exit 1
              fi
            }

            run_exact_test \
              vcpu_introspection::tests::vcpu_introspection_requires_register_and_cursor_capabilities \
              vcpu_introspection::tests::vcpu_introspection_requires_register_and_cursor_capabilities
            run_exact_test \
              vcpu_introspection::tests::vcpu_introspection_reads_all_vcpu_registers_and_rr_cursor \
              vcpu_introspection::tests::vcpu_introspection_reads_all_vcpu_registers_and_rr_cursor
            run_exact_test \
              vcpu_introspection::tests::vcpu_introspection_converts_reader_output_to_protocol_snapshot \
              vcpu_introspection::tests::vcpu_introspection_converts_reader_output_to_protocol_snapshot
            run_exact_test \
              vcpu_introspection::tests::vcpu_introspection_rejects_bad_cursor_before_register_reads \
              vcpu_introspection::tests::vcpu_introspection_rejects_bad_cursor_before_register_reads
            run_exact_test \
              vcpu_introspection::tests::vcpu_introspection_register_digest_is_stable_and_vcpu_qualified \
              vcpu_introspection::tests::vcpu_introspection_register_digest_is_stable_and_vcpu_qualified
            run_exact_test \
              vcpu_introspection::tests::vcpu_introspection_cursor_can_be_derived_from_local_round_robin_state \
              vcpu_introspection::tests::vcpu_introspection_cursor_can_be_derived_from_local_round_robin_state
            run_exact_test \
              abi::tests::abi_install_requires_vcpu_introspection_symbols \
              abi::tests::abi_install_requires_vcpu_introspection_symbols
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            open_tasks=${openTaskList}
            status=partial
            register_scope=all-vcpus-ascending
            rr_cursor=current-vcpu-position-and-quantum
            side_effects=S-and-T-neutral-reads
            fingerprint_input=N-vCPU-registers-plus-RR-cursor
            protocol_snapshot=crucible-protocol::PluginNvcpuFingerprintSnapshot
            RESULT
          '';
        }
      ];
    }
