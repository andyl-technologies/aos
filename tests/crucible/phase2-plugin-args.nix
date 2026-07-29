{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginArgs",
  taskIds ? ["T-PLUG-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginArgs = builtins.readFile ../../crates/crucible-qemu-plugin/src/args.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;


  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-2 checklist complete";
        needle = "- [x] **T-PLUG-2**";
      }
      {
        label = "simfd required by spec";
        needle = "`simfd=N`";
      }
      {
        label = "slot required by spec";
        needle = "`slot=N`";
      }
      {
        label = "fail-closed parser required by spec";
        needle = "total, fail-closed parser";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "args module exported";
        needle = "pub mod args;";
      }
      {
        label = "PluginArgs exported";
        needle = "PluginArgs";
      }
      {
        label = "PluginArgsParseError exported";
        needle = "PluginArgsParseError";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/args.rs" pluginArgs [
      {
        label = "parser type";
        needle = "pub struct PluginArgs";
      }
      {
        label = "public parser";
        needle = "pub fn parse(raw: &str)";
      }
      {
        label = "slot validation";
        needle = "pub fn validate_slot_index(&self, node_count: u32)";
      }
      {
        label = "simfd key";
        needle = "pub const PLUGIN_ARG_SIMFD: &str = \"simfd\";";
      }
      {
        label = "slot key";
        needle = "pub const PLUGIN_ARG_SLOT: &str = \"slot\";";
      }
      {
        label = "shmemfd key";
        needle = "pub const PLUGIN_ARG_SHMEMFD: &str = \"shmemfd\";";
      }
      {
        label = "wakefd key";
        needle = "pub const PLUGIN_ARG_WAKEFD: &str = \"wakefd\";";
      }
      {
        label = "whitebox key";
        needle = "pub const PLUGIN_ARG_WHITEBOX: &str = \"whitebox\";";
      }
      {
        label = "coverage key";
        needle = "pub const PLUGIN_ARG_COVERAGE: &str = \"coverage\";";
      }
      {
        label = "missing required key error";
        needle = "MissingRequiredKey";
      }
      {
        label = "unknown key error";
        needle = "UnknownKey";
      }
      {
        label = "duplicate key error";
        needle = "DuplicateKey";
      }
      {
        label = "malformed argument error";
        needle = "MalformedArgument";
      }
      {
        label = "invalid fd error";
        needle = "InvalidFd";
      }
      {
        label = "invalid slot error";
        needle = "InvalidSlot";
      }
      {
        label = "invalid switch error";
        needle = "InvalidSwitch";
      }
      {
        label = "partial descriptor pair error";
        needle = "IncompleteInheritedDescriptors";
      }
      {
        label = "slot range error";
        needle = "SlotOutOfRange";
      }
      {
        label = "known key allowlist";
        needle = "fn is_known_key";
      }
      {
        label = "minimal parse test";
        needle = "plugin_args_parse_required_simfd_and_slot";
      }
      {
        label = "optional fd parse test";
        needle = "plugin_args_parse_optional_fds_and_switches";
      }
      {
        label = "missing required test";
        needle = "plugin_args_reject_missing_required_keys";
      }
      {
        label = "malformed unknown duplicate test";
        needle = "plugin_args_reject_malformed_unknown_and_duplicate_keys";
      }
      {
        label = "bad value test";
        needle = "plugin_args_reject_bad_fd_slot_and_switch_values";
      }
      {
        label = "partial fd pair test";
        needle = "plugin_args_reject_partial_inherited_descriptor_pair";
      }
      {
        label = "slot node count test";
        needle = "plugin_args_validate_slot_against_node_count";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin args check";
        needle = "qemuPluginArgs = import ./phase2-plugin-args.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 plugin-args check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-args";
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
          name = "run-plugin-args";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-args-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              args \
              -- --test-threads=1
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
            parser=crucible-qemu-plugin::args
            required_keys=simfd,slot
            optional_keys=shmemfd,wakefd,whitebox,coverage
            defaults=whitebox-off,coverage-off,setup-fds-via-scm-rights
            rejection_coverage=missing-required,unknown-key,duplicate-key,malformed-argument,invalid-fd,invalid-slot,invalid-switch,partial-fd-pair,slot-out-of-range
            fail_closed=true
            RESULT
          '';
        }
      ];
    }
