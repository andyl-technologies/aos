{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuSpawnFdPassing",
  taskIds ? ["T-QEMU-7"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  qemuLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/lib.rs;
  };
  launchLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/launch.rs;
  };
  nodeLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/node.rs;
  };
  spawnLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/spawn.rs;
  };
  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "T-QEMU-7 completion note names Linux spawn adapter";
        needle = "Linux-only `crucible-qemu` spawn adapter";
      }
      {
        label = "T-QEMU-7 completion note names fixed child fds";
        needle = "fd 3/4/5";
      }
      {
        label = "T-QEMU-7 completion note names pdeathsig";
        needle = "PR_SET_PDEATHSIG=SIGKILL";
      }
      {
        label = "T-QEMU-7 completion note preserves later setup follow-up";
        needle = "setup-completion tasks";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "linux spawn module";
        needle = "#[cfg(target_os = \"linux\")]\nmod spawn;";
      }
      {
        label = "linux spawn exports";
        needle = "pub use spawn::{";
      }
      {
        label = "spawn function export";
        needle = "spawn_qemu_child_with_fds";
      }
      {
        label = "spawn run-directory function export";
        needle = "spawn_qemu_child_with_fds_in_directory";
      }
      {
        label = "spawn resources export";
        needle = "QemuSpawnHostResources";
      }
      {
        label = "spawn error export";
        needle = "QemuSpawnError";
      }
      {
        label = "fixed fd constants export";
        needle = "QEMU_PLUGIN_CONTROL_FD";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch.rs" launchLib [
      {
        label = "public control fd constant";
        needle = "pub const QEMU_PLUGIN_CONTROL_FD: i32 = FIXED_PLUGIN_SIM_FD;";
      }
      {
        label = "public shmem fd constant";
        needle = "pub const QEMU_PLUGIN_SHMEM_FD: i32 = FIXED_PLUGIN_SHMEM_FD;";
      }
      {
        label = "public wake fd constant";
        needle = "pub const QEMU_PLUGIN_WAKE_FD: i32 = FIXED_PLUGIN_WAKE_FD;";
      }
      {
        label = "plugin config uses shared control constant";
        needle = "pub const QEMU_PLUGIN_CONTROL_FD: i32 = FIXED_PLUGIN_SIM_FD;";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node.rs" nodeLib [
      {
        label = "node child drop implementation";
        needle = "impl Drop for QemuNodeChild";
      }
      {
        label = "drop-time kill";
        needle = "let _ = self.child.kill();";
      }
      {
        label = "bounded drop-time reap";
        needle = "wait_child(&mut self.child, DROP_REAP_DEADLINE)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/spawn.rs" spawnLib [
      {
        label = "spawn module docs";
        needle = "Linux QEMU process spawning with fixed inherited descriptors";
      }
      {
        label = "spawn host resources";
        needle = "pub struct QemuSpawnHostResources";
      }
      {
        label = "spawn result";
        needle = "pub struct QemuSpawnedChild";
      }
      {
        label = "spawn error";
        needle = "pub enum QemuSpawnError";
      }
      {
        label = "public spawn API";
        needle = "pub fn spawn_qemu_child_with_fds";
      }
      {
        label = "run-directory spawn API";
        needle = "pub fn spawn_qemu_child_with_fds_in_directory";
      }
      {
        label = "child current directory binding";
        needle = "command.current_dir(run_directory);";
      }
      {
        label = "validated launch command input";
        needle = "command: &QemuLaunchCommand";
      }
      {
        label = "control socketpair";
        needle = "libc::socketpair";
      }
      {
        label = "socket close-on-exec";
        needle = "libc::SOCK_CLOEXEC";
      }
      {
        label = "memfd creation";
        needle = "libc::memfd_create";
      }
      {
        label = "memfd close-on-exec";
        needle = "libc::MFD_CLOEXEC";
      }
      {
        label = "memfd sizing";
        needle = "libc::ftruncate";
      }
      {
        label = "eventfd creation";
        needle = "libc::eventfd";
      }
      {
        label = "eventfd close-on-exec";
        needle = "libc::EFD_CLOEXEC";
      }
      {
        label = "child duplicate close-on-exec";
        needle = "libc::F_DUPFD_CLOEXEC";
      }
      {
        label = "control socket child duplicate";
        needle = "duplicate_cloexec_fd(child_control.as_raw_fd(), \"duplicate plugin control fd\")";
      }
      {
        label = "pre-exec hook";
        needle = "command.pre_exec";
      }
      {
        label = "parent-death signal";
        needle = "libc::PR_SET_PDEATHSIG";
      }
      {
        label = "parent-death kill";
        needle = "libc::SIGKILL";
      }
      {
        label = "expected parent pid captured before fork";
        needle = "expected_parent_pid";
      }
      {
        label = "parent pid verified after pdeathsig";
        needle = "libc::getppid()";
      }
      {
        label = "parent change aborts child exec";
        needle = "parent changed before child exec";
      }
      {
        label = "fixed fd dup";
        needle = "libc::dup2";
      }
      {
        label = "control fd mapping";
        needle = "dup_to_fixed_child_fd(control_fd, QEMU_PLUGIN_CONTROL_FD)";
      }
      {
        label = "shmem fd mapping";
        needle = "dup_to_fixed_child_fd(shmem_fd, QEMU_PLUGIN_SHMEM_FD)";
      }
      {
        label = "wake fd mapping";
        needle = "dup_to_fixed_child_fd(wake_fd, QEMU_PLUGIN_WAKE_FD)";
      }
      {
        label = "source fd close";
        needle = "close_child_source_fd";
      }
      {
        label = "host resources retained";
        needle = "QemuSpawnHostResources {";
      }
      {
        label = "fixed child fd test";
        needle = "qemu_spawn_maps_fixed_child_fds_after_pre_exec";
      }
      {
        label = "source fd env handoff";
        needle = "CRUCIBLE_QEMU_SPAWN_SOURCE_FDS";
      }
      {
        label = "source fd closed assertion";
        needle = "assert_fd_closed(fd)";
      }
      {
        label = "spawn resources test";
        needle = "qemu_spawn_resources_create_socket_memfd_eventfd_and_host_copies";
      }
      {
        label = "spawn run-directory cwd test";
        needle = "qemu_spawn_run_directory_sets_child_cwd";
      }
      {
        label = "spawn cwd probe";
        needle = "child_probe_cwd";
      }
      {
        label = "drop kill test";
        needle = "qemu_node_child_drop_kills_and_reaps_unreaped_child";
      }
      {
        label = "parent death signal runtime test";
        needle = "qemu_spawn_kills_child_when_parent_exits";
      }
      {
        label = "empty region rejection test";
        needle = "qemu_spawn_rejects_empty_region";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/spawn.rs" spawnLib [
      {
        label = "shell invocation in spawn tests";
        needle = "sh -c";
      }
      {
        label = "hard-coded host shell";
        needle = "/bin/sh";
      }
      {
        label = "test unwrap";
        needle = ".unwrap()";
      }
      {
        label = "test expect";
        needle = ".expect(";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes qemu spawn fd passing check";
        needle = "qemuSpawnFdPassing = import ./phase2-qemu-spawn-fd-passing.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu spawn fd-passing check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-spawn-fd-passing";
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
          name = "run-qemu-spawn-fd-passing";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-spawn-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              spawn::tests \
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
            check_scope=task-level
            related_gates=gate:abi-conformance,gate:control-responsive
            rust_test=crucible-qemu::spawn::tests
            target=linux
            control_fd=3
            shmem_fd=4
            wake_fd=5
            spawn_resources=socketpair,memfd,eventfd
            child_contract=dup2-fixed-fds,PR_SET_PDEATHSIG-SIGKILL
            clean_exit_path=QemuNodeChild-drop-kill-reap
            RESULT
          '';
        }
      ];
    }
