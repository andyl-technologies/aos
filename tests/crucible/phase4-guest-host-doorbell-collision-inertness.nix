{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostDoorbellCollisionInertness",
  taskIds ? [],
  openTaskIds ? ["T-GHC-6"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginWhiteboxDoorbell = builtins.readFile ../../crates/crucible-qemu-plugin/src/whitebox_doorbell.rs;
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
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
  openTaskList = builtins.concatStringsSep "," openTaskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-6 remains open";
        needle = "- [ ] **T-GHC-6**";
      }
      {
        label = "T-GHC-6 partial-evidence note";
        needle = "Partial callback-core evidence is provided by";
      }
      {
        label = "collision setup error";
        needle = "a collision is a setup error";
      }
      {
        label = "disabled inertness";
        needle = "disabled doorbell remains uninstalled and inert";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "collision type exported";
        needle = "WhiteboxDoorbellCollision";
      }
      {
        label = "setup resources exported";
        needle = "WhiteboxDoorbellSetupResources";
      }
      {
        label = "setup outcome exported";
        needle = "WhiteboxDoorbellSetupOutcome";
      }
      {
        label = "setup validation exported";
        needle = "WhiteboxDoorbellSetupValidation";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhiteboxDoorbell [
      {
        label = "setup resources type";
        needle = "pub struct WhiteboxDoorbellSetupResources";
      }
      {
        label = "observed setup resources constructor";
        needle = "pub const fn from_observed_resources";
      }
      {
        label = "x86 observed port accessor";
        needle = "pub const fn x86_mapped_ports";
      }
      {
        label = "aarch64 observed immediate accessor";
        needle = "pub const fn aarch64_reserved_immediates_in_use";
      }
      {
        label = "setup validation type";
        needle = "pub struct WhiteboxDoorbellSetupValidation";
      }
      {
        label = "setup validator";
        needle = "pub fn validate(";
      }
      {
        label = "setup outcome enum";
        needle = "pub enum WhiteboxDoorbellSetupOutcome";
      }
      {
        label = "collision enum";
        needle = "pub enum WhiteboxDoorbellCollision";
      }
      {
        label = "x86 collision model";
        needle = "X86PortMapped";
      }
      {
        label = "aarch64 collision model";
        needle = "Aarch64ReservedImmediateInUse";
      }
      {
        label = "registration requires setup validation argument";
        needle = "setup_validation: WhiteboxDoorbellSetupValidation";
      }
      {
        label = "on-mode validates setup collision";
        needle = "self.validate_setup_collision(setup_validation)?;";
      }
      {
        label = "unchecked setup error";
        needle = "SetupCollisionUnchecked";
      }
      {
        label = "collision setup error";
        needle = "SetupCollision";
      }
      {
        label = "trap mismatch setup error";
        needle = "SetupValidationTrapMismatch";
      }
      {
        label = "off mode checks switch first";
        needle = "if !self.mode.is_on()";
      }
      {
        label = "off mode disabled plan";
        needle = "WhiteboxDoorbellRegistrationPlan::Disabled";
      }
      {
        label = "resource-backed setup validation";
        needle = "WhiteboxDoorbellSetupValidation::validate";
      }
      {
        label = "observed x86 collision resource test vector";
        needle = "WhiteboxDoorbellSetupResources::from_observed_resources(&[0xe7], &[])";
      }
      {
        label = "observed aarch64 collision resource test vector";
        needle = "WhiteboxDoorbellSetupResources::from_observed_resources(&[], &[0x4c1])";
      }
      {
        label = "collision validation test";
        needle = "whitebox_registration_on_mode_requires_setup_collision_validation";
      }
      {
        label = "off-mode inertness test";
        needle = "whitebox_registration_off_mode_installs_no_trap_and_preserves_black_box";
      }
      {
        label = "off mode bypasses validation test";
        needle = "whitebox_registration_off_mode_bypasses_whitebox_payload_validation";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 collision inertness import";
        needle = "guestHostDoorbellCollisionInertness = import ./phase4-guest-host-doorbell-collision-inertness.nix";
      }
      {
        label = "phase4 collision inertness attr path";
        needle = "checks.crucible.phase4.guestHostDoorbellCollisionInertness";
      }
      {
        label = "phase4 collision inertness task id";
        needle = "openTaskIds = [\"T-GHC-6\"]";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu-plugin/src/whitebox_doorbell.rs" pluginWhiteboxDoorbell [
      {
        label = "public self-attested collision-free validation";
        needle = "pub const fn collision_free";
      }
      {
        label = "public hand-built x86 collision validation";
        needle = "pub const fn x86_port_collision";
      }
      {
        label = "public hand-built aarch64 collision validation";
        needle = "pub const fn aarch64_reserved_immediate_collision";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 guest-host doorbell collision/inertness check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-doorbell-collision-inertness";
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
          name = "run-guest-host-doorbell-collision-inertness";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-doorbell-collision-inertness-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              --lib whitebox_registration \
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
            open_tasks=${openTaskList}
            status=partial
            evidence_scope=doorbell-collision-plan-model
            gate=gate:any-guest,gate:abi-conformance
            setup_collision=validated-before-trap-install
            off_mode=disabled-plan-installs-no-trap
            inertness=disabled-doorbell-uninstalled
            RESULT
          '';
        }
      ];
    }
