{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.blockWireAbi",
  taskIds ? ["T-IO-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  blockIo = builtins.readFile ../../crates/crucible-qemu-plugin/src/block_io.rs;
  ioWireFuzz = builtins.readFile ../../crates/crucible-qemu-plugin/src/io_wire_fuzz.rs;
  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  shmem =
    builtins.readFile ../../crates/crucible-shmem/src/lib.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node.rs;
  ioDoc = builtins.readFile ../../docs/rfcs/0010-crucible/15-io-subnodes.md;
  defaultChecks = builtins.readFile ./default.nix;

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

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/15-io-subnodes.md" ioDoc [
      {
        label = "T-IO-3 checked off";
        needle = "- [x] **T-IO-3**";
      }
      {
        label = "T-IO-3 completion note";
        needle = "Completed by `checks.crucible.phase3.blockWireAbi`";
      }
      {
        label = "fixed little-endian wire note";
        needle = "fixed little-endian field order";
      }
      {
        label = "reserved rejection note";
        needle = "reserved bytes are zero on emit and rejected on decode";
      }
      {
        label = "SLOT_BLK_IO routing note";
        needle = "`SLOT_BLK_IO` shared-memory rings";
      }
      {
        label = "delivery icount note";
        needle = "`FrameEntry.delivery_icount` is the computed completion icount";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/block_io.rs" blockIo [
      {
        label = "wire version";
        needle = "const BLOCK_WIRE_VERSION: u8 = 1";
      }
      {
        label = "request header length";
        needle = "const BLOCK_REQUEST_HEADER_LEN: usize = 20";
      }
      {
        label = "response header length";
        needle = "const BLOCK_RESPONSE_HEADER_LEN: usize = 12";
      }
      {
        label = "operation wire values";
        needle = "fn wire_type(self) -> u8";
      }
      {
        label = "request decode";
        needle = "pub fn decode(payload: &[u8]) -> Result<(u32, Self), BlockWireError>";
      }
      {
        label = "response decode";
        needle = "pub fn decode(payload: &[u8]) -> Result<Self, BlockWireError>";
      }
      {
        label = "little-endian request id";
        needle = "request_id.to_le_bytes()";
      }
      {
        label = "little-endian offset";
        needle = "self.offset.to_le_bytes()";
      }
      {
        label = "little-endian count";
        needle = "self.count.to_le_bytes()";
      }
      {
        label = "reserved zero emit";
        needle = "out.extend_from_slice(&0_u16.to_le_bytes())";
      }
      {
        label = "reserved reject";
        needle = "BlockWireError::NonZeroReserved";
      }
      {
        label = "unknown op reject";
        needle = "BlockWireError::UnknownOperation";
      }
      {
        label = "bounds checked request count";
        needle = "RequestCountExceedsPayload";
      }
      {
        label = "trailing request payload reject";
        needle = "RequestCountPayloadMismatch";
      }
      {
        label = "trailing response payload reject";
        needle = "ResponseCountPayloadMismatch";
      }
      {
        label = "frame capacity check";
        needle = "MAX_FRAME_DATA";
      }
      {
        label = "block slot constant";
        needle = "const BLOCK_IO_SLOT_U32: u32 = SLOT_BLK_IO as u32";
      }
      {
        label = "outbound block ring check";
        needle = "outbound_ring.dst_slot != BLOCK_IO_SLOT_U32";
      }
      {
        label = "inbound block ring check";
        needle = "inbound_ring.src_slot != BLOCK_IO_SLOT_U32";
      }
      {
        label = "submit frame stamps icount";
        needle = "FrameEntry::new(submit_icount, self.vm_slot, request_id, &payload)";
      }
      {
        label = "poll waits for delivery icount";
        needle = "if head.delivery_icount > current_icount";
      }
      {
        label = "reserved request test";
        needle = "block_request_decode_rejects_nonzero_reserved_and_trailing_payload";
      }
      {
        label = "reserved response test";
        needle = "block_response_decode_rejects_nonzero_reserved_and_trailing_payload";
      }
      {
        label = "delivery icount frame test";
        needle = "block_response_frames_are_stamped_by_reserved_block_slot_and_delivery_icount";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu-plugin/src/block_io.rs" blockIo [
      {
        label = "wall-clock dependency";
        needle = "SystemTime";
      }
      {
        label = "instant dependency";
        needle = "std::time::Instant";
      }
      {
        label = "host path dependency";
        needle = "PathBuf";
      }
      {
        label = "filesystem metadata dependency";
        needle = "std::fs::Metadata";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/io_wire_fuzz.rs" ioWireFuzz [
      {
        label = "block request corpus";
        needle = "IoWireFuzzChannel::BlockRequest";
      }
      {
        label = "block response corpus";
        needle = "IoWireFuzzChannel::BlockResponse";
      }
      {
        label = "unknown operation regression";
        needle = "block-request-unknown-operation";
      }
      {
        label = "nonzero reserved regression";
        needle = "block-request-nonzero-reserved";
      }
      {
        label = "count exceeds regression";
        needle = "block-request-write-count-exceeds-payload";
      }
      {
        label = "response trailing regression";
        needle = "block-response-trailing-payload";
      }
      {
        label = "no panic fuzz target";
        needle = "io_wire_fuzz_target_never_panics_on_regression_corpus";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "block API exported";
        needle = "BlockRequest";
      }
      {
        label = "block response exported";
        needle = "BlockResponse";
      }
      {
        label = "wire error exported";
        needle = "BlockWireError";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/lib.rs" shmem [
      {
        label = "max frame data";
        needle = "pub const MAX_FRAME_DATA: usize = 4608";
      }
      {
        label = "block slot";
        needle = "pub const SLOT_BLK_IO";
      }
      {
        label = "frame delivery icount";
        needle = "pub struct FrameEntry";
      }
      {
        label = "payload length check";
        needle = "PayloadLengthExceedsCapacity";
      }
      {
        label = "delivery check";
        needle = "pub fn is_deliverable_at";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes block wire check";
        needle = "blockWireAbi = import ./phase3-block-wire-abi.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 block wire ABI check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-block-wire-abi";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
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
          name = "run-block-wire-unit-tests";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-block-wire-abi-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              block_io \
              -- --test-threads=1
          '';
        }
        {
          name = "run-block-wire-fuzz-corpus";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-block-wire-abi-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              io_wire_fuzz \
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
            component=crucible-block-wire-abi
            gate=gate:abi-conformance,gate:layer1-injection
            block_wire_version=1
            fixed_endianness=little
            reserved_bytes=zero-emit-reject-on-receive
            route=vm-slot-to-SLOT_BLK_IO-and-back
            delivery=FrameEntry.delivery_icount
            RESULT
          '';
        }
      ];
    }
