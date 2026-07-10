{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginTeardown",
  taskIds ? [],
  openTaskIds ? ["T-PLUG-19"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginTeardown = builtins.readFile ../../crates/crucible-qemu-plugin/src/teardown.rs;
  pluginIdleLoop = builtins.readFile ../../crates/crucible-qemu-plugin/src/idle_loop.rs;
  protocol = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  shmemRegion = builtins.readFile ../../crates/crucible-shmem/src/shmem/region.rs;
  shmemFrameNode = builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  protocolSpec = builtins.readFile ../../docs/rfcs/0010-crucible/14-protocol.md;
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

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenTeardownApis = [
    "std::time"
    "Instant::now"
    "SystemTime::now"
    "thread::sleep"
    "sleep("
    "pub fn from_lifecycle_state"
  ];

  failures =
    forbiddenFor "crates/crucible-qemu-plugin/src/teardown.rs" pluginTeardown
    (map (needle: {
        label = "wall-clock wait or sleep fallback";
        inherit needle;
      })
      forbiddenTeardownApis)
    ++ failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-19 remains open until live QEMU callback integration";
        needle = "- [ ] **T-PLUG-19**";
      }
      {
        label = "PLUG-43 teardown requirement";
        needle = "**[PLUG-43]** The plugin MUST observe the global `shutdown_requested` flag";
      }
      {
        label = "stop touching shmem wording";
        needle = "stop touching shmem";
      }
      {
        label = "orderly QEMU shutdown wording";
        needle = "initiate orderly QEMU shutdown";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/14-protocol.md" protocolSpec [
      {
        label = "Quit protocol requirement";
        needle = "`Quit` MUST be encoded as a tag-only frame";
      }
      {
        label = "Quit lifecycle step";
        needle = "Quit         host -> plugin";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/lib.rs" protocol [
      {
        label = "host Quit message";
        needle = "HostMsg::Quit";
      }
      {
        label = "plugin run reader accepts Quit";
        needle = "plugin_read_run_control_frame";
      }
      {
        label = "Quit lifecycle state";
        needle = "ControlLifecycleState::QuitSent";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/shmem/region.rs" shmemRegion [
      {
        label = "shutdown request API";
        needle = "pub fn request_shutdown";
      }
      {
        label = "shutdown acquire load";
        needle = "pub fn shutdown_requested";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/shmem/frame_node.rs" shmemFrameNode [
      {
        label = "done marker";
        needle = "pub fn mark_done";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "teardown module";
        needle = "pub mod teardown;";
      }
      {
        label = "teardown type exported";
        needle = "PluginTeardown";
      }
      {
        label = "host Quit proof exported";
        needle = "PluginHostQuit";
      }
      {
        label = "shutdown requested proof exported";
        needle = "PluginShutdownRequested";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/teardown.rs" pluginTeardown [
      {
        label = "teardown trigger enum";
        needle = "pub enum PluginTeardownTrigger";
      }
      {
        label = "shutdown requested trigger";
        needle = "ShutdownRequested";
      }
      {
        label = "host Quit trigger";
        needle = "HostQuit";
      }
      {
        label = "shutdown flag proof";
        needle = "pub struct PluginShutdownRequested";
      }
      {
        label = "shutdown flag acquire check";
        needle = "PluginShmemOrdering::observe_shutdown_requested";
      }
      {
        label = "host Quit proof";
        needle = "pub struct PluginHostQuit";
      }
      {
        label = "host Quit stream reader";
        needle = "pub fn read_from_run_control";
      }
      {
        label = "host Quit proof consumes lifecycle reader";
        needle = ".plugin_read_run_control_frame()";
      }
      {
        label = "host Quit lifecycle proof";
        needle = "ControlLifecycleState::QuitSent";
      }
      {
        label = "done status publication";
        needle = "PluginShmemOrdering::mark_done_after_shutdown";
      }
      {
        label = "orderly QEMU shutdown hook";
        needle = "initiate_orderly_qemu_shutdown";
      }
      {
        label = "shmem access guard";
        needle = "pub struct PluginShmemAccess";
      }
      {
        label = "post-teardown shmem rejection";
        needle = "ShmemAccessAfterTeardown";
      }
      {
        label = "single-shot teardown";
        needle = "AlreadyComplete";
      }
      {
        label = "shutdown_requested test";
        needle = "teardown_shutdown_requested_marks_done_shutdowns_qemu_and_blocks_shmem_access";
      }
      {
        label = "host Quit test";
        needle = "teardown_host_quit_marks_done_shutdowns_qemu_and_blocks_shmem_access";
      }
      {
        label = "real control Quit proof test";
        needle = "teardown_host_quit_proof_reads_real_run_control_quit";
      }
      {
        label = "single-shot test";
        needle = "teardown_is_single_shot_and_does_not_touch_shmem_again";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop.rs" pluginIdleLoop [
      {
        label = "parked shutdown wake marks done";
        needle = "idle_loop_shutdown_wake_marks_done_and_returns_teardown_outcome";
      }
      {
        label = "idle-loop shutdown outcome";
        needle = "IdleWaitOutcome::ShutdownRequested";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin teardown check";
        needle = "qemuPluginTeardown = import ./phase2-plugin-teardown.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 plugin teardown check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-teardown";
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
          name = "run-plugin-teardown";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-teardown-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              teardown \
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
            gates=gate:control-responsive
            rust_tests=crucible-qemu-plugin::teardown
            triggers=shutdown_requested,control-Quit
            shmem_after_teardown=blocked
            qemu_shutdown=orderly-hook-trait-invoked
            RESULT
          '';
        }
      ];
    }
