//! Portable application-owned subprocess execution and process-group cleanup.

use std::{
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use tokio::{
    process::{Child, Command},
    sync::Mutex,
};

use super::{ExecutionProvider, ResourceGrant, WorkerConnection, WorkerControl, WorkerLaunch};
use crate::RuntimeError;

/// Runs a trusted runner as an ordinary application-owned child process.
#[derive(Clone, Debug, Default)]
pub struct SubprocessProvider;

impl SubprocessProvider {
    /// Constructs a provider inheriting the application's resource accounting.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ExecutionProvider for SubprocessProvider {
    fn grant(&self) -> ResourceGrant {
        ResourceGrant {
            hard_cancellation: cfg!(unix),
            independent_memory: false,
            aggregate_accounting: false,
            owner_cleanup: cfg!(unix),
            enforced_memory_bytes: None,
            enforced_limits: None,
            description: "inherited application accounting; private process group on Unix; control-pipe EOF cleanup; no independent OOM boundary".into(),
        }
    }

    async fn launch(&self, launch: WorkerLaunch) -> Result<WorkerConnection, RuntimeError> {
        let mut command = Command::new(&launch.runner);
        command
            .arg("--owner-group-cleanup")
            .arg("--backend")
            .arg(&launch.native_backend)
            .arg("--max-frame-bytes")
            .arg(launch.max_frame_bytes.to_string());
        for argument in &launch.native_arguments {
            command.arg("--backend-arg").arg(argument);
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0);

        let mut child = command.spawn()?;
        let reader = child
            .stdout
            .take()
            .ok_or_else(|| RuntimeError::Unsupported("runner output pipe missing".into()))?;
        let writer = child
            .stdin
            .take()
            .ok_or_else(|| RuntimeError::Unsupported("runner input pipe missing".into()))?;
        let process_id = child.id();
        Ok(WorkerConnection {
            reader: Box::new(reader),
            writer: Box::new(writer),
            control: Arc::new(ProcessControl {
                child: Mutex::new(Some(child)),
                process_id,
                terminated: AtomicBool::new(false),
            }),
        })
    }
}

struct ProcessControl {
    child: Mutex<Option<Child>>,
    process_id: Option<u32>,
    terminated: AtomicBool,
}

impl ProcessControl {
    fn terminate_group(&self) {
        if self.terminated.swap(true, Ordering::AcqRel) {
            return;
        }
        #[cfg(unix)]
        if let Some(pid) = self
            .process_id
            .and_then(|pid| i32::try_from(pid).ok())
            .and_then(rustix::process::Pid::from_raw)
        {
            // The native process inherits the runner's dedicated group. Retiring
            // this control kills both even when startup or a handshake is dropped.
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
    }
}

impl Drop for ProcessControl {
    fn drop(&mut self) {
        self.terminate_group();
    }
}

#[async_trait]
impl WorkerControl for ProcessControl {
    async fn stop(&self) -> Result<(), RuntimeError> {
        let mut guard = self.child.lock().await;
        let Some(child) = guard.as_mut() else {
            return Ok(());
        };
        self.terminate_group();
        let _ = child.start_kill();
        child.wait().await?;
        *guard = None;
        Ok(())
    }
}
