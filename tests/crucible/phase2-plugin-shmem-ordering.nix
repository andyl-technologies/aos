{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginShmemOrdering",
  taskIds ? ["T-PLUG-20"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginShmemOrdering = builtins.readFile ../../crates/crucible-qemu-plugin/src/shmem_ordering.rs;
  pluginBootBarrier = builtins.readFile ../../crates/crucible-qemu-plugin/src/boot_barrier.rs;
  pluginDeviceIo = builtins.readFile ../../crates/crucible-qemu-plugin/src/device_io.rs;
  pluginIdleLoop = builtins.readFile ../../crates/crucible-qemu-plugin/src/idle_loop.rs;
  pluginInbound = builtins.readFile ../../crates/crucible-qemu-plugin/src/inbound.rs;
  pluginNetworkTx = builtins.readFile ../../crates/crucible-qemu-plugin/src/network_tx.rs;
  pluginBlockIo = builtins.readFile ../../crates/crucible-qemu-plugin/src/block_io.rs;
  pluginNinePIo = builtins.readFile ../../crates/crucible-qemu-plugin/src/ninep_io.rs;
  pluginSetup = import ./_qemu-plugin-setup-source.nix {inherit lib;};
  pluginTeardown = builtins.readFile ../../crates/crucible-qemu-plugin/src/teardown.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  shmemLib = builtins.readFile ../../crates/crucible-shmem/src/lib.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

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

  occurrences = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0 || maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.length (builtins.filter (index:
      builtins.substring index needleLen haystack == needle)
    indexes);

  firstIndexOf = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0 || maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
    matches =
      builtins.filter (index:
        builtins.substring index needleLen haystack == needle)
      indexes;
  in
    if matches == []
    then null
    else builtins.head matches;

  productionRust = content: let
    testIndex = firstIndexOf "mod tests {" content;
  in
    if testIndex == null
    then content
    else builtins.substring 0 testIndex content;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  rawShmemSources = [
    {
      label = "crates/crucible-qemu-plugin/src/boot_barrier.rs";
      content = productionRust pluginBootBarrier;
    }
    {
      label = "crates/crucible-qemu-plugin/src/device_io.rs";
      content = productionRust pluginDeviceIo;
    }
    {
      label = "crates/crucible-qemu-plugin/src/idle_loop.rs";
      content = productionRust pluginIdleLoop;
    }
    {
      label = "crates/crucible-qemu-plugin/src/inbound.rs";
      content = productionRust pluginInbound;
    }
    {
      label = "crates/crucible-qemu-plugin/src/network_tx.rs";
      content = productionRust pluginNetworkTx;
    }
    {
      label = "crates/crucible-qemu-plugin/src/block_io.rs";
      content = productionRust pluginBlockIo;
    }
    {
      label = "crates/crucible-qemu-plugin/src/ninep_io.rs";
      content = productionRust pluginNinePIo;
    }
    {
      label = "crates/crucible-qemu-plugin/src/setup.rs";
      content = productionRust pluginSetup;
    }
    {
      label = "crates/crucible-qemu-plugin/src/teardown.rs";
      content = productionRust pluginTeardown;
    }
  ];

  forbiddenRawShmemCalls = [
    ".control_action()"
    ".shutdown_requested()"
    ".load_node_ceiling()"
    ".publish_reached_icount("
    ".publish_idle("
    ".prepare_futex_wait()"
    ".futex_wait_nonprivate("
    ".mark_running()"
    ".mark_done()"
    ".load_device_io_active()"
    ".mark_device_io_active()"
    ".clear_device_io_active()"
    ".wake_for_device_io_release()"
    ".read_index()"
    ".write_index()"
    ".snapshot()"
    ".header_snapshot()"
    ".validate_header()"
    ".publish_scheduler_ceiling("
    ".futex_wait_still_valid("
    ".enqueue("
    ".peek_delivery_icount("
    ".dequeue("
  ];

  forbiddenRawShmemFailures =
    lib.concatMap (
      source:
        lib.concatMap (
          call:
            lib.optionals (hasInfix call source.content) [
              "${source.label}: direct shared-memory method outside PluginShmemOrdering facade: `${call}`"
            ]
        )
        forbiddenRawShmemCalls
    )
    rawShmemSources;

  forbiddenRawOrderingSources = [
    {
      label = "crates/crucible-qemu-plugin/src/boot_barrier.rs";
      content = productionRust pluginBootBarrier;
    }
    {
      label = "crates/crucible-qemu-plugin/src/idle_loop.rs";
      content = productionRust pluginIdleLoop;
    }
    {
      label = "crates/crucible-qemu-plugin/src/inbound.rs";
      content = productionRust pluginInbound;
    }
    {
      label = "crates/crucible-qemu-plugin/src/network_tx.rs";
      content = productionRust pluginNetworkTx;
    }
    {
      label = "crates/crucible-qemu-plugin/src/block_io.rs";
      content = productionRust pluginBlockIo;
    }
    {
      label = "crates/crucible-qemu-plugin/src/ninep_io.rs";
      content = productionRust pluginNinePIo;
    }
    {
      label = "crates/crucible-qemu-plugin/src/setup.rs";
      content = productionRust pluginSetup;
    }
    {
      label = "crates/crucible-qemu-plugin/src/teardown.rs";
      content = productionRust pluginTeardown;
    }
  ];

  forbiddenRawOrderingNeedles = [
    "Ordering::Acquire"
    "Ordering::Release"
    "Ordering::AcqRel"
    "Ordering::SeqCst"
    "std::sync::atomic"
    "core::sync::atomic"
  ];

  forbiddenRawOrderingFailures =
    lib.concatMap (
      source:
        lib.concatMap (
          needle:
            lib.optionals (hasInfix needle source.content) [
              "${source.label}: raw atomic ordering outside shmem ABI/facade: `${needle}`"
            ]
        )
        forbiddenRawOrderingNeedles
    )
    forbiddenRawOrderingSources;

  deviceIoProduction = productionRust pluginDeviceIo;
  deviceIoRelaxedCount = occurrences "Ordering::Relaxed" deviceIoProduction;
  deviceIoOrderingFailures =
    lib.concatMap (
      needle:
        lib.optionals (hasInfix needle deviceIoProduction) [
          "crates/crucible-qemu-plugin/src/device_io.rs: forbidden shared-memory atomic ordering in production device-I/O code: `${needle}`"
        ]
    )
    [
      "Ordering::Acquire"
      "Ordering::Release"
      "Ordering::AcqRel"
      "Ordering::SeqCst"
      "std::sync::atomic"
    ]
    ++ lib.optionals (deviceIoRelaxedCount != 1) [
      "crates/crucible-qemu-plugin/src/device_io.rs: expected exactly one plugin-local `Ordering::Relaxed`, found ${toString deviceIoRelaxedCount}"
    ];

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-20 checklist complete";
        needle = "- [x] **T-PLUG-20**";
      }
      {
        label = "cross-process ordering wording";
        needle = "Enforce the cross-process atomic-ordering rules";
      }
      {
        label = "relaxed single-threaded wording";
        needle = "self-owned counters outside shmem";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "shmem ordering module exported";
        needle = "pub mod shmem_ordering;";
      }
      {
        label = "shmem ordering facade exported";
        needle = "pub use shmem_ordering::PluginShmemOrdering;";
      }
      {
        label = "module map names ordering contract";
        needle = "`shmem_ordering` owns the plugin-side shared-memory access";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/shmem_ordering.rs" pluginShmemOrdering [
      {
        label = "facade type";
        needle = "pub struct PluginShmemOrdering;";
      }
      {
        label = "relaxed-local documentation";
        needle = "Plugin-local diagnostics may use relaxed";
      }
      {
        label = "control action observer";
        needle = "pub fn observe_control_action";
      }
      {
        label = "shutdown observer";
        needle = "pub fn observe_shutdown_requested";
      }
      {
        label = "setup header snapshot helper";
        needle = "pub fn setup_header_snapshot";
      }
      {
        label = "setup header validation helper";
        needle = "pub fn validate_setup_header";
      }
      {
        label = "ceiling acquire helper";
        needle = "pub fn load_scheduler_ceiling";
      }
      {
        label = "reached publish helper";
        needle = "pub fn publish_reached_icount";
      }
      {
        label = "idle publish helper";
        needle = "pub fn publish_idle_wait";
      }
      {
        label = "futex wait helper";
        needle = "pub fn wait_on_wake_signal";
      }
      {
        label = "running publish helper";
        needle = "pub fn mark_running_after_wake";
      }
      {
        label = "done publish helper";
        needle = "pub fn mark_done_after_shutdown";
      }
      {
        label = "device I/O acquire helper";
        needle = "pub fn device_io_active";
      }
      {
        label = "device I/O active publish helper";
        needle = "pub fn publish_device_io_active";
      }
      {
        label = "device I/O clear helper";
        needle = "pub fn clear_device_io_active";
      }
      {
        label = "device I/O wake helper";
        needle = "pub fn wake_for_device_io_release";
      }
      {
        label = "SPSC enqueue helper";
        needle = "pub fn enqueue_outbound_frame";
      }
      {
        label = "SPSC peek helper";
        needle = "pub fn peek_inbound_delivery_icount";
      }
      {
        label = "SPSC dequeue helper";
        needle = "pub fn dequeue_inbound_frame";
      }
      {
        label = "SPSC read-index helper";
        needle = "pub fn consumer_read_index";
      }
      {
        label = "SPSC write-index helper";
        needle = "pub fn producer_write_index";
      }
      {
        label = "facade idle test";
        needle = "shmem_ordering_facade_publishes_idle_state_and_observes_ceiling";
      }
      {
        label = "facade SPSC test";
        needle = "shmem_ordering_facade_enqueues_peeks_and_dequeues_spsc_frames";
      }
      {
        label = "facade shutdown test";
        needle = "shmem_ordering_facade_observes_shutdown_requested";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/boot_barrier.rs" pluginBootBarrier [
      {
        label = "boot barrier uses ordering facade";
        needle = "PluginShmemOrdering::publish_idle_wait";
      }
      {
        label = "boot barrier waits through ordering facade";
        needle = "PluginShmemOrdering::wait_on_wake_signal";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/device_io.rs" pluginDeviceIo [
      {
        label = "device I/O uses ordering facade";
        needle = "use crate::shmem_ordering::PluginShmemOrdering;";
      }
      {
        label = "relaxed local counter documented";
        needle = "This counter is plugin-local diagnostic state, not shared memory.";
      }
      {
        label = "relaxed owner id is local only";
        needle = "NEXT_FREEZE_OWNER_ID.fetch_add(1, Ordering::Relaxed)";
      }
      {
        label = "device I/O active flag via facade";
        needle = "PluginShmemOrdering::publish_device_io_active";
      }
      {
        label = "device I/O clear via facade";
        needle = "PluginShmemOrdering::clear_device_io_active";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop.rs" pluginIdleLoop [
      {
        label = "idle loop observes control through facade";
        needle = "PluginShmemOrdering::observe_control_action";
      }
      {
        label = "idle loop loads ceiling through facade";
        needle = "PluginShmemOrdering::load_scheduler_ceiling";
      }
      {
        label = "idle loop publishes reached through facade";
        needle = "PluginShmemOrdering::publish_reached_icount";
      }
      {
        label = "idle loop publishes idle through facade";
        needle = "PluginShmemOrdering::publish_idle_wait";
      }
      {
        label = "idle loop marks done through facade";
        needle = "PluginShmemOrdering::mark_done_after_shutdown";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/inbound.rs" pluginInbound [
      {
        label = "inbound peeks through facade";
        needle = "PluginShmemOrdering::peek_inbound_delivery_icount";
      }
      {
        label = "inbound dequeues through facade";
        needle = "PluginShmemOrdering::dequeue_inbound_frame";
      }
      {
        label = "inbound reads indices through facade";
        needle = "PluginShmemOrdering::producer_write_index";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/network_tx.rs" pluginNetworkTx [
      {
        label = "network TX enqueues through facade";
        needle = "PluginShmemOrdering::enqueue_outbound_frame";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/block_io.rs" pluginBlockIo [
      {
        label = "block outbound enqueue through facade";
        needle = "PluginShmemOrdering::enqueue_outbound_frame";
      }
      {
        label = "block inbound dequeue through facade";
        needle = "PluginShmemOrdering::dequeue_inbound_frame";
      }
      {
        label = "block inbound peek through facade";
        needle = "PluginShmemOrdering::peek_inbound_delivery_icount";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/ninep_io.rs" pluginNinePIo [
      {
        label = "9p outbound enqueue through facade";
        needle = "PluginShmemOrdering::enqueue_outbound_frame";
      }
      {
        label = "9p inbound dequeue through facade";
        needle = "PluginShmemOrdering::dequeue_inbound_frame";
      }
      {
        label = "9p inbound peek through facade";
        needle = "PluginShmemOrdering::peek_inbound_delivery_icount";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/setup.rs" pluginSetup [
      {
        label = "setup snapshots header through facade";
        needle = "PluginShmemOrdering::setup_header_snapshot";
      }
      {
        label = "setup validates header through facade";
        needle = "PluginShmemOrdering::validate_setup_header";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/teardown.rs" pluginTeardown [
      {
        label = "teardown observes shutdown through facade";
        needle = "PluginShmemOrdering::observe_shutdown_requested";
      }
      {
        label = "teardown marks done through facade";
        needle = "PluginShmemOrdering::mark_done_after_shutdown";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/lib.rs" shmemLib [
      {
        label = "producer own index relaxed";
        needle = "let tail = self.write_idx.load(Ordering::Relaxed);";
      }
      {
        label = "producer reads consumer index acquire";
        needle = "let head = self.read_idx.load(Ordering::Acquire);";
      }
      {
        label = "producer publishes write index release";
        needle = ".store(tail.wrapping_add(1), Ordering::Release);";
      }
      {
        label = "consumer reads producer index acquire";
        needle = "let tail = self.write_idx.load(Ordering::Acquire);";
      }
      {
        label = "consumer frees read index release";
        needle = "self.read_idx.store(head.wrapping_add(1), Ordering::Release);";
      }
      {
        label = "node ceiling acquire load";
        needle = "self.max_advance_icount.load(Ordering::Acquire)";
      }
      {
        label = "node current icount release publish";
        needle = "self.current_icount.store(current_icount, Ordering::Release);";
      }
      {
        label = "node seqlock acqrel generation";
        needle = "self.publish_gen.fetch_add(1, Ordering::AcqRel);";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin shmem ordering check";
        needle = "qemuPluginShmemOrdering = import ./phase2-plugin-shmem-ordering.nix";
      }
    ]
    ++ forbiddenRawShmemFailures
    ++ forbiddenRawOrderingFailures
    ++ deviceIoOrderingFailures;
in
  if failures != []
  then throw "crucible phase2 plugin shmem-ordering check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-shmem-ordering";
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
          name = "run-plugin-shmem-ordering";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-shmem-ordering-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              shmem_ordering \
              -- --test-threads=1
            mkdir -p "$out"
            printf '%s\n' \
              "attr=${attrPath}" \
              "tasks=${taskList}" \
              "ordering_facade=plugin-shmem-access-only-through-safe-abi-methods" \
              "relaxed_scope=plugin-local-diagnostics-only" \
              > "$out/result"
          '';
        }
      ];
    }
