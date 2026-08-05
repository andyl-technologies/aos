{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.protocolDescriptorHandover",
  taskIds ? ["T-PROTO-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  protocolCargo = builtins.readFile ../../crates/crucible-protocol/Cargo.toml;
  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  descriptorTest = builtins.readFile ../../crates/crucible-protocol/tests/descriptor_handover.rs;
  protocolSpec = builtins.readFile ../../docs/rfcs/0010-crucible/14-protocol.md;
  crateSpec = builtins.readFile ../../docs/rfcs/0010-crucible/27-crate-structure.md;
  unsafeFenceRust = builtins.readFile ../../crates/crucible-harness/tests/crate_unsafe_fence.rs;
  unsafeFenceNix = builtins.readFile ./phase1-crate-unsafe-fence.nix;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible-protocol/Cargo.toml" protocolCargo [
      {
        label = "libc workspace dependency";
        needle = "libc = { workspace = true }";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/lib.rs" protocolLib [
      {
        label = "unsafe-boundary fence";
        needle = "#![deny(unsafe_op_in_unsafe_fn)]";
      }
      {
        label = "safe-wrapper contract";
        needle = "Unsafe boundary discipline:";
      }
      {
        label = "descriptor handover wrapper contract";
        needle = "public callers use safe setup descriptor handover wrappers";
      }
      {
        label = "two-fd validation contract";
        needle = "validate the fixed two-fd order and descriptor count";
      }
      {
        label = "outbound descriptor type";
        needle = "pub struct SetupDescriptorFds";
      }
      {
        label = "inbound descriptor type";
        needle = "pub struct ReceivedSetupDescriptors";
      }
      {
        label = "received setup type";
        needle = "pub struct ReceivedSetup";
      }
      {
        label = "handover error type";
        needle = "pub enum DescriptorHandoverError";
      }
      {
        label = "wrong descriptor count error";
        needle = "WrongDescriptorCount";
      }
      {
        label = "ancillary truncation error";
        needle = "AncillaryTruncated";
      }
      {
        label = "send wrapper";
        needle = "pub fn send_setup_with_descriptors";
      }
      {
        label = "receive wrapper";
        needle = "pub fn recv_setup_with_descriptors";
      }
      {
        label = "SCM_RIGHTS level";
        needle = "libc::SCM_RIGHTS";
      }
      {
        label = "sendmsg syscall";
        needle = "libc::sendmsg";
      }
      {
        label = "recvmsg syscall";
        needle = "libc::recvmsg";
      }
      {
        label = "CMSG_SPACE sizing";
        needle = "libc::CMSG_SPACE";
      }
      {
        label = "CMSG_LEN sizing";
        needle = "libc::CMSG_LEN";
      }
      {
        label = "CMSG_DATA access";
        needle = "libc::CMSG_DATA";
      }
      {
        label = "no-sigpipe send flag";
        needle = "libc::MSG_NOSIGNAL";
      }
      {
        label = "received close-on-exec flag";
        needle = "libc::FD_CLOEXEC";
      }
      {
        label = "OwnedFd wrapping";
        needle = "OwnedFd::from_raw_fd";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/tests/descriptor_handover.rs" descriptorTest [
      {
        label = "fixed-order transfer test";
        needle = "setup_handover_transfers_two_descriptors_in_fixed_order";
      }
      {
        label = "wrong descriptor count test";
        needle = "setup_handover_rejects_wrong_descriptor_count";
      }
      {
        label = "closed peer send regression";
        needle = "setup_handover_reports_closed_peer_on_send";
      }
      {
        label = "split SCM_RIGHTS regression";
        needle = "setup_handover_accepts_split_descriptor_control_messages";
      }
      {
        label = "Unix socketpair exercise";
        needle = "UnixStream::pair";
      }
      {
        label = "SCM_RIGHTS sender exercise";
        needle = "send_setup_with_descriptors";
      }
      {
        label = "SCM_RIGHTS receiver exercise";
        needle = "recv_setup_with_descriptors";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/14-protocol.md" protocolSpec [
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/27-crate-structure.md" crateSpec [
      {
        label = "protocol unsafe crate table entry";
        needle = "| `crucible-protocol` | **UNSAFE**";
      }
      {
        label = "five unsafe crate count";
        needle = "five UNSAFE crates";
      }
      {
        # crucible-cas registered as the ninth safe crate.
        label = "nine safe crate count";
        needle = "nine SAFE crates";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/crate_unsafe_fence.rs" unsafeFenceRust [
      {
        label = "Rust unsafe-fence protocol spec";
        needle = "package: \"crucible-protocol\"";
      }
      {
        label = "Rust unsafe-fence protocol boundary";
        needle = "unsafe_boundary: true";
      }
      {
        label = "Rust unsafe-fence protocol contract";
        needle = "public callers use safe setup descriptor handover wrappers";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-crate-unsafe-fence.nix" unsafeFenceNix [
      {
        label = "Nix unsafe-fence protocol spec";
        needle = "package = \"crucible-protocol\";";
      }
      {
        label = "Nix unsafe-fence protocol boundary";
        needle = "unsafeBoundary = true;";
      }
      {
        # crucible-cas registered as the ninth safe crate.
        label = "Nix unsafe-fence safe count";
        needle = "runtime_safe_crates=9";
      }
      {
        label = "Nix unsafe-fence unsafe count";
        needle = "runtime_unsafe_boundary_crates=5";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes descriptor handover check";
        needle = "protocolDescriptorHandover = import ./phase2-protocol-descriptor-handover.nix";
      }
      {
        label = "canonical ABI conformance gate is implemented";
        needle = "abiConformance = import ./phase2-abi-conformance.nix";
      }
      {
        label = "canonical ABI conformance task list";
        needle = "taskIds = [\"T-HARN-17\" \"T-API-11\" \"T-API-12\" \"T-PAT-8\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 protocol descriptor-handover check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-protocol-descriptor-handover";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-protocol-descriptor-handover";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-protocol-descriptor-handover-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-protocol \
              --test descriptor_handover \
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
            gate=gate:abi-conformance
            rust_tests=crucible-protocol::descriptor_handover
            descriptor_handover=SCM_RIGHTS
            setup_fds=shmem_fd,wake_fd
            setup_fd_count=exactly-two
            RESULT
          '';
        }
      ];
    }
