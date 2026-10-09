//! Linux owner-loss containment exercised without the owning application's Drop.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

use std::{path::PathBuf, process::Stdio, time::Duration};

use dispatch_protocol::{
    framing::{read_frame_async, write_frame_async},
    wire::{self, worker_envelope::Body},
};
use dispatch_runtime::{ExecutionProvider, SubprocessProvider};

fn runner() -> PathBuf {
    let path = std::env::var_os("DISPATCH_TEST_WORKER")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .expect("test executable path")
                .parent()
                .expect("deps directory")
                .parent()
                .expect("profile directory")
                .join("dispatch-worker")
        });
    assert!(
        path.is_file(),
        "build the trusted worker or set DISPATCH_TEST_WORKER"
    );
    path
}

fn process_computes(pid: u32) -> bool {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    status
        .lines()
        .find(|line| line.starts_with("State:"))
        .is_some_and(|line| !line.contains("Z (zombie)") && !line.contains("X (dead)"))
}

#[tokio::test]
#[ignore = "requires a built trusted worker executable"]
async fn owner_control_pipe_eof_stops_native_grandchildren_without_owner_destructors() {
    assert!(
        SubprocessProvider::new().grant().owner_cleanup,
        "this test validates the advertised owner-loss guarantee"
    );
    let directory = tempfile::tempdir().expect("private descendant trace directory");
    let native_trace = directory.path().join("native-pid");
    let solves = directory.path().join("solves");
    let leaf_trace = directory.path().join("leaf-pid");
    let mut command = tokio::process::Command::new(runner());
    command
        .arg("--owner-group-cleanup")
        .arg("--backend")
        .arg(env!("CARGO_BIN_EXE_dispatch-test-backend"));
    for argument in [
        "tree_stall".to_owned(),
        native_trace.to_string_lossy().into_owned(),
        solves.to_string_lossy().into_owned(),
        leaf_trace.to_string_lossy().into_owned(),
    ] {
        command.arg("--backend-arg").arg(argument);
    }
    command
        .arg("--max-frame-bytes")
        .arg("16777216")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true);
    let mut child = command.spawn().expect("real runner in its dedicated group");
    let group = child.id().expect("live runner PID");
    let mut cleanup = ProcessTreeCleanup { group, armed: true };
    let mut input = child.stdin.take().expect("owner control writer");
    let mut output = child.stdout.take().expect("owner control reader");
    let hello = wire::WorkerEnvelope {
        protocol_version: Some(dispatch_protocol::WORKER_VERSION),
        session_generation: 1,
        worker_generation: 1,
        request_id: 1,
        body: Some(Body::Hello(wire::Hello {
            protocol_versions: vec![dispatch_protocol::WORKER_VERSION],
            model_versions: vec![dispatch_protocol::MODEL_VERSION],
            limits: Some(wire::WireLimits::standard()),
            required_capabilities: Vec::new(),
        })),
    };
    write_frame_async(&mut input, &hello, 65_536)
        .await
        .expect("native handshake request");
    let response = read_frame_async(&mut output, 65_536)
        .await
        .expect("real native handshake response");
    assert!(matches!(response.body, Some(Body::Capabilities(_))));
    let solve = wire::WorkerEnvelope {
        request_id: 2,
        body: Some(Body::Solve(wire::Solve {
            problem_json: serde_json::to_vec(&dispatch_model::Problem {
                model_version: 1,
                ..Default::default()
            })
            .expect("empty exact fixture"),
            options: Some(wire::SolveOptions {
                mode: wire::SearchMode::LocalSearch as i32,
                threads: 1,
                wall_time_millis: 30_000,
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..hello
    };
    write_frame_async(&mut input, &solve, 16 * 1024 * 1024)
        .await
        .expect("enter uncooperative native tree");
    let created = tokio::time::timeout(Duration::from_secs(3), async {
        while std::fs::read_to_string(&leaf_trace)
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok())
            .is_none()
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .is_ok();
    if !created {
        cleanup.terminate();
        let _ = child.wait().await;
    }
    assert!(
        created,
        "native grandchild must actually exist before testing EOF"
    );
    let native: u32 = std::fs::read_to_string(&native_trace)
        .expect("native PID trace")
        .trim()
        .parse()
        .expect("native PID");
    let leaf: u32 = std::fs::read_to_string(&leaf_trace)
        .expect("leaf PID trace")
        .trim()
        .parse()
        .expect("leaf PID");
    assert!(process_computes(native));
    assert!(process_computes(leaf));

    // Closing this writer models process loss: no ProcessControl::stop or Drop
    // runs. The surviving trusted runner alone must enforce the EOF guarantee.
    drop(input);
    let stopped = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !process_computes(native) && !process_computes(leaf) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok();
    if !stopped {
        cleanup.terminate();
    }
    let exited = tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .is_ok_and(|result| result.is_ok());
    if stopped && exited {
        cleanup.armed = false;
    }
    assert!(
        stopped,
        "owner loss must reclaim native descendants independently of owner destructors"
    );
    assert!(
        exited,
        "the trusted runner must also retire after owner loss"
    );
}

fn stop_group(group: u32) {
    if let Some(pid) = i32::try_from(group)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

struct ProcessTreeCleanup {
    group: u32,
    armed: bool,
}

impl ProcessTreeCleanup {
    fn terminate(&mut self) {
        if self.armed {
            self.armed = false;
            stop_group(self.group);
        }
    }
}

impl Drop for ProcessTreeCleanup {
    fn drop(&mut self) {
        self.terminate();
    }
}
