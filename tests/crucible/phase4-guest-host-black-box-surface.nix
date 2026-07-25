{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostBlackBoxSurface",
  taskIds ? ["T-GHC-1"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  model = import ./_crucible-model-source.nix {inherit lib;};
  surfaceTest = builtins.readFile ../../crates/crucible/tests/guest_host_black_box_surface.rs;
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
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
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-1 checked off";
        needle = "- [x] **T-GHC-1**";
      }
      {
        label = "T-GHC-1 completion note";
        needle = "Completed by `checks.crucible.phase4.guestHostBlackBoxSurface`";
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
        label = "black-box observation enum";
        needle = "pub enum BlackBoxObservationKind";
      }
      {
        label = "closed black-box surface constant";
        needle = "BLACK_BOX_OBSERVATION_KINDS";
      }
      {
        label = "network surface kind";
        needle = "BlackBoxObservationKind::NetworkTraffic";
      }
      {
        label = "disk 9p surface kind";
        needle = "BlackBoxObservationKind::DiskOrNinePIo";
      }
      {
        label = "console surface kind";
        needle = "BlackBoxObservationKind::ConsoleSerialOutput";
      }
      {
        label = "architectural state surface kind";
        needle = "BlackBoxObservationKind::ArchitecturalStateSample";
      }
      {
        label = "run outcome surface kind";
        needle = "BlackBoxObservationKind::RunOutcome";
      }
      {
        label = "crash hang surface kind";
        needle = "BlackBoxObservationKind::CrashOrHangDetection";
      }
      {
        label = "coverage surface kind";
        needle = "BlackBoxObservationKind::BasicBlockCoverage";
      }
      {
        label = "event classifier method";
        needle = "pub fn black_box_observation_kind(&self) -> Option<BlackBoxObservationKind>";
      }
      {
        label = "condition prefix black-box surface projection";
        needle = "black_box_observation_kinds";
      }
      {
        label = "black-box stamp validation error";
        needle = "InvalidBlackBoxObservationStamp";
      }
      {
        label = "event-log monotonic order validation";
        needle = "OutOfOrderEventLogEntry";
      }
      {
        label = "white-box markers excluded";
        needle = "Self::GuestMarker { .. }";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "hung lifecycle variant";
        needle = "Hung,";
      }
      {
        label = "hung lifecycle binary tag";
        needle = "NodeLifecycle::Hung => 3";
      }
      {
        label = "hung lifecycle TOML";
        needle = "NodeLifecycleToml::Hung";
      }
      {
        label = "hung lifecycle material label";
        needle = "NodeLifecycle::Hung => \"hung\"";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "black-box observation kind export";
        needle = "BlackBoxObservationKind";
      }
      {
        label = "black-box observation catalog export";
        needle = "BLACK_BOX_OBSERVATION_KINDS";
      }
    ]
    ++ failuresFor "crates/crucible/tests/guest_host_black_box_surface.rs" surfaceTest [
      {
        label = "closed catalog test";
        needle = "black_box_surface_catalog_is_closed_and_complete";
      }
      {
        label = "stamped observation test";
        needle = "black_box_surface_events_are_icount_stamped_observational_entries";
      }
      {
        label = "condition prefix surface stamp enforcement test";
        needle = "condition_prefix_enforces_black_box_surface_stamps";
      }
      {
        label = "condition prefix ordering enforcement test";
        needle = "condition_prefix_rejects_out_of_order_observation_stamps";
      }
      {
        label = "white-box exclusion test";
        needle = "white_box_markers_are_not_required_black_box_surface";
      }
      {
        label = "io wildcard exclusion test";
        needle = "io_wildcard_is_not_a_concrete_black_box_surface_category";
      }
      {
        label = "hung lifecycle serialization test";
        needle = "hung_lifecycle_round_trips_through_property_serialization";
      }
      {
        label = "observational class assertion";
        needle = "EventClass::Observational";
      }
      {
        label = "hung surface assertion";
        needle = "NodeLifecycle::Hung";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 black-box surface import";
        needle = "guestHostBlackBoxSurface = import ./phase4-guest-host-black-box-surface.nix";
      }
      {
        label = "phase4 black-box surface attr path";
        needle = "checks.crucible.phase4.guestHostBlackBoxSurface";
      }
      {
        label = "phase4 black-box surface task id";
        needle = "taskIds = [\"T-GHC-1\"]";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/guest_host_black_box_surface.rs" surfaceTest [
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
      crucible phase4 guest-host black-box surface check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-black-box-surface";
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
          name = "run-guest-host-black-box-surface";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-black-box-surface-target" \
              -p crucible \
              --test guest_host_black_box_surface \
              --test observable_condition_leaves \
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
            surface=network,disk-9p,console-serial,qmp-state,run-outcome,crash-hang,basic-block-coverage
            determinism_class=observational
            RESULT
          '';
        }
      ];
    }
