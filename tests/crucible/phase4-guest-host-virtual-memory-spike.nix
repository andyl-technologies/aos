{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostVirtualMemorySpike",
  taskIds ? ["T-GHC-13"],
  phase0S5 ? import ./phase0-s5.nix {inherit pkgs lib;},
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  pluginLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/lib.rs;
  };
  pluginWhitebox = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu-plugin/src/whitebox_doorbell.rs;
  };
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  riskDoc = builtins.readFile ../../docs/rfcs/0010-crucible/30-risks-spikes.md;
  decisionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/31-decision-register.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-13 completion note";
        needle = "Completed by `checks.crucible.phase4.guestHostVirtualMemorySpike`";
      }
      {
        label = "S5 dependency named";
        needle = "`checks.crucible.phase0.s5VirtualMemory`";
      }
      {
        label = "fallback retained wording";
        needle = "physical / pinned identity-mapped shared-page fallback";
      }
      {
        label = "fallback retained condition";
        needle = "retained if that evidence is absent or invalidated";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/30-risks-spikes.md" riskDoc [
      {
        label = "RISK-12 retired";
        needle = "**RISK-12** is retired by `T-RISK-5`";
      }
      {
        label = "S5 check";
        needle = "`checks.crucible.phase0.s5VirtualMemory`";
      }
      {
        label = "virtual read pass";
        needle = "`virtual_address_read_result=pass`";
      }
      {
        label = "three placements";
        needle = "`placements=3`";
      }
      {
        label = "resident read pass";
        needle = "`resident_read=pass`";
      }
      {
        label = "page spanning read pass";
        needle = "`page_spanning_read=pass`";
      }
      {
        label = "paged mmap read pass";
        needle = "`paged_mmap_read=pass`";
      }
      {
        label = "hashes reproducible";
        needle = "`read_hashes_reproducible=true`";
      }
      {
        label = "fingerprint nonperturbation";
        needle = "`side_effect_free_fingerprint_match=true`";
      }
      {
        label = "fallback not adopted after pass";
        needle = "`physical_pinned_fallback_adopted=false`";
      }
      {
        label = "production channel still separate";
        needle = "`production_whitebox_channel_implemented=false`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/31-decision-register.md" decisionDoc [
      {
        label = "decision register S5 status";
        needle = "RISK-12 / T-RISK-5";
      }
      {
        label = "decision register fallback scope";
        needle = "physical / pinned identity-mapped page remains a specified fallback";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "unresolved addressing re-export";
        needle = "WHITEBOX_GUEST_MEMORY_ADDRESSING_UNRESOLVED";
      }
      {
        label = "addressing resolution re-export";
        needle = "WhiteboxGuestMemoryAddressingResolution";
      }
      {
        label = "addressing mode re-export";
        needle = "WhiteboxPayloadAddressingMode";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "S5 check constant";
        needle = "WHITEBOX_GUEST_MEMORY_VADDR_SPIKE_CHECK";
      }
      {
        label = "fail-closed unresolved default";
        needle = "pub const WHITEBOX_GUEST_MEMORY_ADDRESSING_UNRESOLVED";
      }
      {
        label = "addressing resolution type";
        needle = "pub struct WhiteboxGuestMemoryAddressingResolution";
      }
      {
        label = "virtual soundness predicate";
        needle = "pub const fn virtual_pointer_length_is_sound";
      }
      {
        label = "S5 check identity in soundness predicate";
        needle = "static_str_eq(self.check, WHITEBOX_GUEST_MEMORY_VADDR_SPIKE_CHECK)";
      }
      {
        label = "default addressing mode";
        needle = "pub const fn default_payload_addressing_mode";
      }
      {
        label = "default source helper";
        needle = "pub const fn default_payload_source";
      }
      {
        label = "trap event default helper";
        needle = "pub const fn from_default_payload_addressing";
      }
      {
        label = "supplied S5 pass selects virtual pointer length";
        needle = "whitebox_guest_memory_addressing_uses_supplied_s5_virtual_pointer_length_evidence";
      }
      {
        label = "unresolved default falls back";
        needle = "whitebox_guest_memory_addressing_unresolved_default_is_physical_shared_page";
      }
      {
        label = "non-S5 evidence falls back";
        needle = "whitebox_guest_memory_addressing_rejects_non_s5_evidence";
      }
      {
        label = "app-random second client follows addressing resolution";
        needle = "whitebox_guest_memory_addressing_app_random_reply_range_tracks_payload_resolution";
      }
      {
        label = "virtual path selected";
        needle = "WhiteboxPayloadAddressingMode::VirtualPointerLength";
      }
      {
        label = "physical fallback selected";
        needle = "WhiteboxPayloadAddressingMode::PhysicalSharedPage";
      }
      {
        label = "virtual range selected";
        needle = "GuestMemoryAddressSpace::Virtual";
      }
      {
        label = "physical fallback range selected";
        needle = "GuestMemoryAddressSpace::Physical";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 virtual memory spike import";
        needle = "guestHostVirtualMemorySpike = import ./phase4-guest-host-virtual-memory-spike.nix";
      }
      {
        label = "phase4 virtual memory spike attr path";
        needle = "checks.crucible.phase4.guestHostVirtualMemorySpike";
      }
      {
        label = "phase4 virtual memory spike task id";
        needle = "taskIds = [\"T-GHC-13\"]";
      }
      {
        label = "phase4 virtual memory spike depends on S5";
        needle = "phase0S5 = phase0.s5VirtualMemory;";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 guest-host virtual memory spike check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-virtual-memory-spike";
      version = "0";
      src = crucibleSrc;
      buildDeps = [pkgs.coreutils pkgs.grep pkgs.rust pkgs.sed];
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
            set -eu
            export CARGO_HOME="$TMPDIR/cargo-home"
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
          name = "run-guest-host-virtual-memory-spike";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            require_line() {
              result="$1"
              line="$2"
              grep -Fxq "$line" "$result" || {
                printf 'dependency missing evidence: %s\n' "$line" >&2
                cat "$result" >&2
                exit 1
              }
            }
            require_listed() {
              listed="$1"
              test_name="$2"
              if [ -z "$(sed -n "/$test_name/p" "$listed")" ]; then
                printf 'missing expected test: %s\n' "$test_name" >&2
                exit 1
              fi
            }
            s5_result="${phase0S5}/result"
            require_line "$s5_result" "PASS"
            require_line "$s5_result" "spike=guest-virtual-memory-read"
            require_line "$s5_result" "check=checks.crucible.phase0.s5VirtualMemory"
            require_line "$s5_result" "qemu_plugin_read_memory_vaddr_available=true"
            require_line "$s5_result" "doorbell_surface=phase0_instruction_marker_double"
            require_line "$s5_result" "payload_source=register_triplet_kind_ptr_len"
            require_line "$s5_result" "virtual_address_read_result=pass"
            require_line "$s5_result" "placements=3"
            require_line "$s5_result" "resident_read=pass"
            require_line "$s5_result" "page_spanning_read=pass"
            require_line "$s5_result" "paged_mmap_read=pass"
            require_line "$s5_result" "marker_icounts_reproducible=true"
            require_line "$s5_result" "read_bytes_match_expected=true"
            require_line "$s5_result" "read_hashes_reproducible=true"
            require_line "$s5_result" "side_effect_free_fingerprint_match=true"
            require_line "$s5_result" "physical_pinned_fallback_adopted=false"
            require_line "$s5_result" "s5_complete=true"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-virtual-memory-spike-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib \
              -- --list > "$TMPDIR/plugin-tests"
            require_listed \
              "$TMPDIR/plugin-tests" \
              "whitebox_doorbell::tests::whitebox_guest_memory_addressing_uses_supplied_s5_virtual_pointer_length_evidence"
            require_listed \
              "$TMPDIR/plugin-tests" \
              "whitebox_doorbell::tests::whitebox_guest_memory_addressing_unresolved_default_is_physical_shared_page"
            require_listed \
              "$TMPDIR/plugin-tests" \
              "whitebox_doorbell::tests::whitebox_guest_memory_addressing_rejects_non_s5_evidence"
            require_listed \
              "$TMPDIR/plugin-tests" \
              "whitebox_doorbell::tests::whitebox_guest_memory_addressing_app_random_reply_range_tracks_payload_resolution"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-virtual-memory-spike-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib whitebox_guest_memory_addressing \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cp "${phase0S5}/result" "$out/phase0-s5.result"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            spike_dependency=checks.crucible.phase0.s5VirtualMemory
            virtual_pointer_length_default=selected-by-phase0-s5-result
            unresolved_default=physical-shared-page
            app_random_reply_addressing=same-resolution-as-payload
            physical_pinned_fallback=retained-if-S5-absent-or-invalidated
            qemu_plugin_read_memory_vaddr_available=true
            virtual_address_read_result=pass
            RESULT
          '';
        }
      ];
    }
