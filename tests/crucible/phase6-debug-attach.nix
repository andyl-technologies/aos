{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.debugAttach",
  taskIds ? ["T-DBG-1"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  debugDoc = builtins.readFile ../../docs/rfcs/0010-crucible/36-time-travel-debugging.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  engineLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/lib.rs;
  };
  # The launch module was split into a `launch/` directory; concatenate the
  # control-channel submodule so gdbstub/QMP channel needles remain scannable.
  qemuLaunch =
    (import ./_rust-module-source.nix {
      inherit lib;
      entry = ../../crates/crucible-qemu/src/launch.rs;
    })
    + (import ./_rust-module-source.nix {
      inherit lib;
      entry = ../../crates/crucible-qemu/src/launch/control_channels.rs;
    });
  qemuProxy = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/gdbstub_proxy.rs;
  };
  qemuLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/lib.rs;
  };
  qemuNode = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/node.rs;
  };
  cliMain = import ./_cli-source.nix {inherit lib;};
  modelTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/gate_debug_attach.rs;
  };
  qemuTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/tests/debug_gdbstub.rs;
  };
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/rfcs/0010-crucible/36-time-travel-debugging.md" debugDoc [
      {
        label = "T-DBG-1 partial-evidence note";
        needle = "Completed under `checks.crucible.phase6.debugAttach`";
      }
      {
        label = "attach is instantiate";
        needle = "A debug attach MUST be an `instantiate`";
      }
      {
        label = "gdb listen endpoint";
        needle = "--gdb-listen";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "debug attach API";
        needle = "pub fn debug_attach";
      }
      {
        label = "attach delegates to resume";
        needle = "let runtime = self.resume(&request.configuration)?;";
      }
      {
        label = "debug attach request";
        needle = "pub struct DebugAttachRequest";
      }
      {
        label = "debug attach report";
        needle = "pub struct DebugAttachReport";
      }
      {
        label = "gdb endpoint validation";
        needle = "pub struct DebugGdbEndpoint";
      }
      {
        label = "four-channel set";
        needle = "DebugAttachChannelSet::four_channel_debug_session";
      }
      {
        label = "gdbstub channel";
        needle = "pub struct DebugGdbstubChannel";
      }
      {
        label = "no timing data";
        needle = "carries_per_quantum_timing: false";
      }
      {
        label = "no frame data";
        needle = "carries_frame_data: false";
      }
      {
        label = "ordinary instantiated runtime predicate";
        needle = "uses_instantiated_runtime";
      }
      {
        label = "unknown node error";
        needle = "DebugAttachUnknownNode";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" engineLib [
      {
        label = "debug attach request export";
        needle = "DebugAttachRequest";
      }
      {
        label = "debug attach report export";
        needle = "DebugAttachReport";
      }
      {
        label = "debug gdbstub channel export";
        needle = "DebugGdbstubChannel";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch.rs" qemuLaunch [
      {
        label = "QEMU gdbstub config";
        needle = "pub struct QemuGdbstubChannelConfig";
      }
      {
        label = "QEMU gdbstub builder hook";
        needle = "pub fn with_gdbstub";
      }
      {
        label = "QEMU -gdb option";
        needle = "\"-gdb\".to_owned()";
      }
      {
        label = "operator endpoint retained for proxy";
        needle = "operator_listen";
      }
      {
        label = "mediated channel";
        needle = "pub const fn mediated_by_crucible";
      }
      {
        label = "out-of-band channel";
        needle = "pub const fn out_of_band";
      }
      {
        label = "no QEMU timing payload";
        needle = "pub const fn carries_per_quantum_timing";
      }
      {
        label = "no QEMU frame payload";
        needle = "pub const fn carries_frame_data";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/gdbstub_proxy.rs" qemuProxy [
      {
        label = "QEMU gdbstub proxy type";
        needle = "pub struct QemuGdbstubProxy";
      }
      {
        label = "operator listener type";
        needle = "pub struct QemuGdbstubProxyListener";
      }
      {
        label = "operator bind";
        needle = "TcpListener::bind";
      }
      {
        label = "QEMU gdbstub connect";
        needle = "TcpStream::connect";
      }
      {
        label = "serve one mediated session";
        needle = "pub fn serve_one";
      }
      {
        label = "bidirectional forwarding";
        needle = "io::copy";
      }
      {
        label = "operator-to-qemu report";
        needle = "operator_to_qemu_bytes";
      }
      {
        label = "qemu-to-operator report";
        needle = "qemu_to_operator_bytes";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "QEMU gdbstub config export";
        needle = "QemuGdbstubChannelConfig";
      }
      {
        label = "QEMU gdbstub proxy export";
        needle = "QemuGdbstubProxy";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node.rs" qemuNode [
      {
        label = "ordinary node remains three-channel";
        needle = "pub const fn roles(&self) -> [QemuNodeChannelPlane; 3]";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "debug gdb listen flag";
        needle = "gdb_listen: Option<String>";
      }
      {
        label = "gdb listen long flag";
        needle = "#[arg(long, value_name = \"ADDR\")]";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_debug_attach.rs" modelTest [
      {
        label = "model debug attach gate";
        needle = "debug_attach_instantiates_checkpoint_and_reports_fourth_channel";
      }
      {
        label = "invalid endpoint and unknown node gate";
        needle = "debug_attach_rejects_invalid_endpoint_and_unknown_node";
      }
      {
        label = "four-channel assertion";
        needle = "has_four_channel_debug_boundary";
      }
      {
        label = "ordinary instantiate assertion";
        needle = "uses_instantiated_runtime";
      }
      {
        label = "gdb listen assertion";
        needle = "operator_listen.as_str()";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/debug_gdbstub.rs" qemuTest [
      {
        label = "QEMU debug gdbstub gate";
        needle = "debug_gdbstub_is_fourth_out_of_band_launch_channel";
      }
      {
        label = "QEMU proxy mediation gate";
        needle = "debug_gdbstub_proxy_mediates_operator_listen_to_qemu_endpoint";
      }
      {
        label = "QEMU invalid endpoint gate";
        needle = "debug_gdbstub_rejects_unstable_endpoint_text";
      }
      {
        label = "QEMU -gdb assertion";
        needle = "\"-gdb\",";
      }
      {
        label = "operator endpoint not in argv";
        needle = "!command.args().iter().any";
      }
      {
        label = "operator connects to proxy listener";
        needle = "TcpStream::connect(operator_addr)";
      }
      {
        label = "proxy byte-count assertion";
        needle = "report.operator_to_qemu_bytes";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "green debug attach gate";
        needle = "debugAttach = greenBeforeAdvance";
      }
      {
        label = "explicit task id";
        needle = "taskIds = [\"T-DBG-1\"]";
      }
      {
        label = "unifying view raw dependency";
        needle = "phase6.unifyingView.rawGate";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "debug attach timing payload";
        needle = "carries_per_quantum_timing: true";
      }
      {
        label = "debug attach frame payload";
        needle = "carries_frame_data: true";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-qemu/tests/debug_gdbstub.rs" qemuTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 debug-attach check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-debug-attach";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      DEPENDENCIES = builtins.concatStringsSep ":" dependencies;

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
            : "$DEPENDENCIES"
            export CARGO_HOME="$TMPDIR/cargo-home"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-debug-attach";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-debug-attach-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_debug_attach \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-debug-attach-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test debug_gdbstub \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-debug-attach-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-cli \
              cli_failure_artifact_writer_emits_replay_and_debug_commands \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${taskList}
            open_tasks=${openTaskList}
            status=complete
            evidence_scope=debug-attach-model-and-proxy
            gate=gate:debug-attach
            attach=instantiate-via-temporal-graph-resume
            channel=gdbstub-fourth-out-of-band
            proxy=mediated-gdb-listen
            payloads=no-per-quantum-timing-no-frame-data
            RESULT
          '';
        }
      ];
    }
