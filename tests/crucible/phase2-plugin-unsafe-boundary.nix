{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginUnsafeBoundary",
  taskIds ? ["T-PLUG-21"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginAbi = builtins.readFile ../../crates/crucible-qemu-plugin/src/abi.rs;
  pluginSetup = import ./_qemu-plugin-setup-source.nix {inherit lib;};
  pluginWhitebox =
    builtins.readFile ../../crates/crucible-qemu-plugin/src/whitebox_doorbell.rs
    + builtins.readFile ../../crates/crucible-qemu-plugin/src/whitebox_doorbell/tests.rs;
  pluginNetworkTx = builtins.readFile ../../crates/crucible-qemu-plugin/src/network_tx.rs;
  pluginNetworkRx = builtins.readFile ../../crates/crucible-qemu-plugin/src/network_rx.rs;
  pluginBlockIo = builtins.readFile ../../crates/crucible-qemu-plugin/src/block_io.rs;
  pluginNinePIo = builtins.readFile ../../crates/crucible-qemu-plugin/src/ninep_io.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "PLUG-46 unsafe boundary wording";
        needle = "Every `unsafe` block in the plugin MUST be minimal";
      }
      {
        label = "PLUG-47 guest memory wording";
        needle = "Guest memory MUST be read only through the QEMU plugin memory API";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "unsafe operation lint";
        needle = "#![deny(unsafe_op_in_unsafe_fn)]";
      }
      {
        label = "typed descriptor and mmap lifetimes";
        needle = "lifetimes with typed tokens";
      }
      {
        label = "guest memory through API adapters";
        needle = "read or written only through QEMU plugin API adapters";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi.rs" pluginAbi [
      {
        label = "single-threaded RR callback serialization";
        needle = "QEMU serializes registered vCPU-thread callbacks";
      }
      {
        label = "MTTCG rejection";
        needle = "QemuTcgThreading::MultiThreadedTcg";
      }
      {
        label = "callback contract";
        needle = "callback contract: single-threaded round-robin TCG";
      }
      {
        label = "callback state serialization";
        needle = "process-local callback state remains serialized on the vCPU thread";
      }
      {
        label = "raw install boundary validation";
        needle = "validate_install_boundary(info, argc, argv)?;";
      }
      {
        label = "QEMU info dereference SAFETY";
        needle = "QEMU's plugin ABI";
      }
      {
        label = "owned scalar copy below the raw boundary";
        needle = "only scalar data is copied into owned state";
      }
      {
        label = "unsafe C install trampoline";
        needle = "pub unsafe extern \"C\" fn qemu_plugin_install";
      }
      {
        label = "install safety contract";
        needle = "# Safety";
      }
      {
        label = "dlsym safety";
        needle = "The symbol name is a static NUL-terminated byte string.";
      }
      {
        label = "clock transmute safety";
        needle = "int64_t qemu_plugin_clock_deadline_ns(void)";
      }
      {
        label = "queued advance transmute safety";
        needle = "int qemu_plugin_advance_time_ns(int64_t)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/setup.rs" pluginSetup [
      {
        # The doc sentence wraps across comment lines; anchor on the unwrapped
        # prefix of each clause.
        label = "descriptor handoff validity";
        needle = "Descriptor validity comes from the fixed SCM_RIGHTS";
      }
      {
        label = "mmap lifetime token";
        needle = "mmap lifetime is owned by the returned";
      }
      {
        label = "mapped region lifetime";
        needle = "The mapped shared-memory region stays live while this token is live";
      }
      {
        label = "mapped region owner";
        needle = "The mmap lifetime is carried by `MappedSetupRegion`";
      }
      {
        label = "exact setup mmap";
        needle = "mmap_setup_region(shmem_fd.as_fd(), region_len)";
      }
      {
        label = "validated-region token";
        needle = "the validated-region token";
      }
      {
        label = "owned setup wake descriptor";
        needle = "owned setup wake descriptor";
      }
      {
        label = "descriptor flag safety";
        needle = "`fcntl(F_GETFD)` reads descriptor flags only";
      }
      {
        label = "descriptor status safety";
        needle = "`fcntl(F_SETFL)` updates only descriptor status flags";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhitebox [
      {
        label = "guest memory read API";
        needle = "read_guest_memory";
      }
      {
        label = "guest memory write API";
        needle = "write_whitebox_input";
      }
      {
        label = "opaque guest address";
        needle = "opaque to Rust and meaningful only to QEMU";
      }
      {
        label = "payload range validation";
        needle = "validate_payload_range";
      }
      {
        label = "shared frame bound";
        needle = "MAX_FRAME_DATA";
      }
      {
        label = "read length mismatch";
        needle = "GuestMemoryReadLengthMismatch";
      }
      {
        label = "write length mismatch";
        needle = "InputPayloadLengthMismatch";
      }
      {
        label = "oversize before read test";
        needle = "whitebox_doorbell_rejects_oversized_payload_before_guest_memory_read";
      }
      {
        label = "oversize before write test";
        needle = "whitebox_guest_input_rejects_oversized_payload_before_guest_memory_write";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/network_tx.rs" pluginNetworkTx [
      {
        label = "network TX frame constructor";
        needle = "FrameEntry::new(emit_icount, self.src_slot, seq, payload)";
      }
      {
        label = "network TX oversize error";
        needle = "NetworkTxError::PayloadTooLarge";
      }
      {
        label = "network TX oversize test";
        needle = "network_tx_rejects_oversized_payload_without_truncation_or_sequence_advance";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/network_rx.rs" pluginNetworkRx [
      {
        label = "network RX payload accessor validation";
        needle = "frame.payload().map_err";
      }
      {
        label = "network RX invalid payload test";
        needle = "network_rx_rejects_invalid_payload_before_queue_or_flush";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/block_io.rs" pluginBlockIo [
      {
        label = "block request frame constructor";
        needle = "FrameEntry::new(submit_icount, self.vm_slot, request_id, &payload)";
      }
      {
        label = "block response payload accessor";
        needle = "let payload = match head.payload()";
      }
      {
        label = "block trailing payload validation";
        needle = "block_response_decode_rejects_nonzero_reserved_and_trailing_payload";
      }
      {
        label = "block request frame payload bound";
        needle = "payload_len > MAX_FRAME_DATA";
      }
      {
        label = "block oversized write before copy test";
        needle = "block_submit_rejects_oversized_write_before_copying_payload";
      }
      {
        label = "block frame capacity assertion";
        needle = "usize::from(frame.len) <= MAX_FRAME_DATA";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/ninep_io.rs" pluginNinePIo [
      {
        label = "9p request frame constructor";
        needle = "FrameEntry::new(submit_icount, self.vm_slot, request_id, request.payload())";
      }
      {
        label = "9p response payload accessor";
        needle = "let payload = match head.payload()";
      }
      {
        label = "9p frame capacity assertion";
        needle = "usize::from(frame.len) <= MAX_FRAME_DATA";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin unsafe-boundary check";
        needle = "qemuPluginUnsafeBoundary = import ./phase2-plugin-unsafe-boundary.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 plugin unsafe-boundary check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-unsafe-boundary";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.grep
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
          name = "run-plugin-unsafe-boundary";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi

            grep -RnlE 'unsafe[[:space:]]*(\{|fn|extern|impl|trait)' \
              crates/crucible-qemu-plugin/src > "$TMPDIR/plugin-unsafe-files" || true
            while IFS= read -r file; do
              case "$file" in
                crates/crucible-qemu-plugin/src/abi.rs|\
                crates/crucible-qemu-plugin/src/abi/tests.rs|\
                crates/crucible-qemu-plugin/src/coverage.rs|\
                crates/crucible-qemu-plugin/src/coverage/tests.rs|\
                crates/crucible-qemu-plugin/src/coverage/tests/live_callback_cases.rs|\
                crates/crucible-qemu-plugin/src/fingerprint_sampler.rs|\
                crates/crucible-qemu-plugin/src/fingerprint_sampler/tests.rs|\
                crates/crucible-qemu-plugin/src/registration/tests.rs|\
                crates/crucible-qemu-plugin/src/runtime.rs|\
                crates/crucible-qemu-plugin/src/runtime/live_whitebox.rs|\
                crates/crucible-qemu-plugin/src/runtime/live_whitebox/api.rs|\
                crates/crucible-qemu-plugin/src/runtime/live_whitebox/error.rs|\
                crates/crucible-qemu-plugin/src/runtime/live_whitebox/marker.rs|\
                crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs|\
                crates/crucible-qemu-plugin/src/runtime/live_callbacks/devices.rs|\
                crates/crucible-qemu-plugin/src/runtime/tests.rs|\
                crates/crucible-qemu-plugin/src/runtime/tests/support.rs|\
                crates/crucible-qemu-plugin/src/setup.rs|\
                crates/crucible-qemu-plugin/src/setup/tests.rs|\
                crates/crucible-qemu-plugin/src/network_rx.rs|\
                crates/crucible-qemu-plugin/src/network_tx.rs|\
                crates/crucible-qemu-plugin/src/raw_state_dump.rs|\
                crates/crucible-qemu-plugin/src/vcpu_introspection.rs)
                  ;;
                *)
                  echo "$file: unexpected unsafe boundary outside audited FFI/setup adapters" >&2
                  exit 1
                  ;;
              esac
            done < "$TMPDIR/plugin-unsafe-files"

            while IFS= read -r file; do
              grep -nE 'unsafe[[:space:]]*(\{|fn|extern|impl|trait)' "$file" > "$TMPDIR/plugin-unsafe-lines" || true
              while IFS=: read -r line match; do
                if [ -z "$line" ]; then
                  continue
                fi
                if printf '%s\n' "$match" \
                  | grep -qE 'unsafe[[:space:]]+(extern[[:space:]]+"C"[[:space:]]+)?fn'; then
                  start=$((line - 16))
                  if [ "$start" -lt 1 ]; then
                    start=1
                  fi
                  if ! sed -n "''${start},''${line}p" "$file" | grep -q '# Safety'; then
                    echo "$file:$line: unsafe function lacks a nearby # Safety contract" >&2
                    exit 1
                  fi
                  continue
                fi
                start=$((line - 8))
                if [ "$start" -lt 1 ]; then
                  start=1
                fi
                end=$((line + 8))
                if ! sed -n "''${start},''${end}p" "$file" | grep -q 'SAFETY:'; then
                  echo "$file:$line: unsafe block lacks nearby SAFETY comment" >&2
                  exit 1
                fi
              done < "$TMPDIR/plugin-unsafe-lines"
            done < "$TMPDIR/plugin-unsafe-files"

            if grep -RIn 'transmute' crates/crucible-qemu-plugin/src \
              | grep -Ev 'src/(abi|coverage|fingerprint_sampler|network_rx|network_tx|raw_state_dump)\.rs:|src/coverage/tests(\.rs|/live_callback_cases\.rs):|src/runtime/live_whitebox(\.rs|/api\.rs):'; then
              echo "transmute is confined to audited QEMU FFI adapters and tests" >&2
              exit 1
            fi
            for pattern in \
              'guest_address() as *' \
              'guest_address as *' \
              'guest_physical_address as *'
            do
              if grep -RIn "$pattern" crates/crucible-qemu-plugin/src; then
                echo "forbidden raw pointer guest-memory pattern: $pattern" >&2
                exit 1
              fi
            done
            if grep -RIn 'as_ptr().cast' crates/crucible-qemu-plugin/src \
              | grep -Ev 'src/(abi|fingerprint_sampler|network_rx|network_tx|raw_state_dump)\.rs:|src/abi/tests\.rs:|src/runtime/live_whitebox(\.rs|/api\.rs|/error\.rs):'; then
              echo "pointer casts are confined to audited QEMU FFI adapters and tests" >&2
              exit 1
            fi
            if grep -RIn 'read_guest_memory' crates/crucible-qemu-plugin/src \
              | grep -v 'src/whitebox_doorbell.rs' \
              | grep -v 'src/whitebox_doorbell/tests.rs' \
              | grep -v 'src/runtime/live_whitebox.rs' \
              | grep -v 'src/lib.rs'; then
              echo "guest memory reads must route through whitebox_doorbell API adapters" >&2
              exit 1
            fi
            if grep -RIn 'write_whitebox_input' crates/crucible-qemu-plugin/src \
              | grep -v 'src/whitebox_doorbell.rs' \
              | grep -v 'src/whitebox_doorbell/tests.rs' \
              | grep -v 'src/runtime/live_whitebox/app_random.rs' \
              | grep -v 'src/lib.rs'; then
              echo "guest memory writes must route through whitebox_doorbell API adapters" >&2
              exit 1
            fi

            target_dir="$TMPDIR/crucible-plugin-unsafe-boundary-target"
            for filter in abi setup whitebox_ network_tx network_rx block_ ninep_ coverage_; do
              cargo test \
                --frozen \
                --offline \
                --target-dir "$target_dir" \
                --manifest-path crates/Cargo.toml \
                -p crucible-qemu-plugin \
                "$filter" \
                -- --test-threads=1
            done
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
            task_status=complete
            unsafe_boundary=abi,coverage,fingerprint,registration,runtime,runtime-live-callbacks,runtime-device-callbacks,test-support,setup,network-rx,network-tx,vcpu-introspection
            unsafe_comments=blocks-require-nearby-SAFETY-functions-require-Safety-contract
            callback_contract=single-threaded-round-robin-vcpu-thread
            setup_lifetimes=typed-descriptor-and-mmap-tokens
            guest_memory=plugin-api-adapters-only
            callback_foundation=live-vcpu-time-slice;remaining-device-adapters-fail-closed
            RESULT
          '';
        }
      ];
    }
