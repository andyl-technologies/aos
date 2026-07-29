{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostOsAgnostic",
  taskIds ? ["T-GHC-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  osAgnosticTest = builtins.readFile ../../crates/crucible/tests/guest_host_os_agnostic.rs;
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-2 checked off";
        needle = "- [x] **T-GHC-2**";
      }
      {
        label = "T-GHC-2 completion note";
        needle = "Completed by `checks.crucible.phase4.guestHostOsAgnostic`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "guest-host phase4 task range";
        needle = "Guest↔host channel + optional agent";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "black-box observation contract type";
        needle = "pub struct BlackBoxObservationContract";
      }
      {
        label = "black-box observation source type";
        needle = "pub enum BlackBoxObservationSource";
      }
      {
        label = "closed black-box observation contracts";
        needle = "BLACK_BOX_OBSERVATION_CONTRACTS";
      }
      {
        label = "kind contract projection";
        needle = "pub const fn contract(self) -> BlackBoxObservationContract";
      }
      {
        label = "guest OS assumption marker";
        needle = "requires_guest_os_contract";
      }
      {
        label = "guest init assumption marker";
        needle = "requires_guest_init_contract";
      }
      {
        label = "guest filesystem assumption marker";
        needle = "requires_guest_filesystem_contract";
      }
      {
        label = "guest ABI assumption marker";
        needle = "requires_guest_abi_contract";
      }
      {
        label = "host-to-guest payload direction marker";
        needle = "carries_host_to_guest_payload";
      }
      {
        label = "console output sink source";
        needle = "ExternalConsoleSerialSink";
      }
      {
        label = "observable event contract projection";
        needle = "black_box_observation_contract";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "black-box observation contracts export";
        needle = "BLACK_BOX_OBSERVATION_CONTRACTS";
      }
      {
        label = "black-box observation contract export";
        needle = "BlackBoxObservationContract";
      }
      {
        label = "black-box observation source export";
        needle = "BlackBoxObservationSource";
      }
    ]
    ++ failuresFor "crates/crucible/tests/guest_host_os_agnostic.rs" osAgnosticTest [
      {
        label = "contract catalog assumption test";
        needle = "black_box_contract_catalog_has_no_guest_software_assumptions";
      }
      {
        label = "non-Linux opaque image test";
        needle = "non_linux_opaque_image_uses_black_box_observation_without_guest_contract";
      }
      {
        label = "console output-only test";
        needle = "console_serial_observation_is_output_only";
      }
      {
        label = "non-Linux architecture fixture";
        needle = "VmArchitecture::Aarch64";
      }
      {
        label = "raw non-Linux image bytes fixture";
        needle = "AARCH64_BARE_METAL_NON_LINUX_IMAGE";
      }
      {
        label = "raw image bytes content hash";
        needle = "ContentHash::from_bytes";
      }
      {
        label = "opaque content-addressed raw image fixture";
        needle = "ContentAddressedBlobRef::from_hash";
      }
      {
        label = "black-box default fixture";
        needle = "WhiteBoxPolicy::Disabled";
      }
      {
        label = "no Linux command-line fixture";
        needle = "cmdline: String::new()";
      }
      {
        label = "raw root image fixture";
        needle = "root_image: Some";
      }
      {
        label = "no Linux kernel fixture";
        needle = "kernel: None";
      }
      {
        label = "no Linux initrd fixture";
        needle = "initrd: None";
      }
      {
        label = "no guest OS contract assertion";
        needle = "requires_guest_os_contract";
      }
      {
        label = "no guest init contract assertion";
        needle = "requires_guest_init_contract";
      }
      {
        label = "no guest filesystem contract assertion";
        needle = "requires_guest_filesystem_contract";
      }
      {
        label = "no guest ABI contract assertion";
        needle = "requires_guest_abi_contract";
      }
      {
        label = "console has no host-to-guest payload assertion";
        needle = "carries_host_to_guest_payload";
      }
      {
        label = "concrete crash hang observation";
        needle = "NodeLifecycle::Hung";
      }
      {
        label = "guest software oracle guard";
        needle = "NoGuestSoftwareLeaves";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 OS-agnostic import";
        needle = "guestHostOsAgnostic = import ./phase4-guest-host-os-agnostic.nix";
      }
      {
        label = "phase4 OS-agnostic attr path";
        needle = "checks.crucible.phase4.guestHostOsAgnostic";
      }
      {
        label = "phase4 OS-agnostic task id";
        needle = "taskIds = [\"T-GHC-2\"]";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/guest_host_os_agnostic.rs" osAgnosticTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
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
      crucible phase4 guest-host OS-agnostic check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-os-agnostic";
      version = "0";
      src = crucibleSrc;
      buildDeps = [pkgs.coreutils pkgs.rust pkgs.sed];
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
          name = "run-guest-host-os-agnostic";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-os-agnostic-target" \
              -p crucible \
              --test guest_host_os_agnostic \
              --test guest_host_black_box_surface \
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
            os_agnostic_black_box=true
            guest_assumptions=none
            console_direction=output-only
            RESULT
          '';
        }
      ];
    }
