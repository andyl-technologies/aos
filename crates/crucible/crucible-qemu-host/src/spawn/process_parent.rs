//! Process-lifetime launcher thread for children bound by a parent-death signal.
//!
//! Every guarded QEMU child installs `PR_SET_PDEATHSIG=SIGKILL` so that it
//! cannot outlive the supervisor. Linux delivers that signal when the *thread*
//! that created the child exits, not when the whole process does. Supervisor
//! work runs on executor and attempt threads that end long before the nodes
//! they launched are retired: a retained hot-fork source must survive the
//! attempt that produced it and remain answerable until daemon shutdown.
//!
//! Spawning on one thread that lives for the whole process restores the
//! intended contract. The child still dies with the supervisor process, and
//! no longer dies with the short-lived thread that asked for it.

use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::{Child, Command};
use std::sync::mpsc::{self, SendError};
use std::sync::{Mutex, PoisonError};
use std::thread;

/// One spawn the launcher performs on behalf of a supervisor thread.
struct LaunchRequest {
    command: Command,
    reply: mpsc::SyncSender<io::Result<Child>>,
}

/// Sender to the process-lifetime launcher, started on first use.
///
/// The static keeps one sender alive, so the launcher's receive loop never
/// observes a disconnected channel and the thread runs until process exit.
static LAUNCHER: Mutex<Option<mpsc::Sender<LaunchRequest>>> = Mutex::new(None);

/// Spawns `command` on the process-lifetime launcher thread.
///
/// The caller blocks until the launcher returns the spawned child, so error
/// handling and `pre_exec` behavior are those of [`Command::spawn`].
///
/// # Errors
///
/// Returns the spawn error, or an error when the launcher thread cannot be
/// started or stopped answering.
pub(super) fn spawn_from_process_parent(command: Command) -> io::Result<Child> {
    let (reply, response) = mpsc::sync_channel(1);
    let request = LaunchRequest { command, reply };

    {
        let mut launcher = LAUNCHER.lock().unwrap_or_else(PoisonError::into_inner);
        let sender = match launcher.as_ref() {
            Some(sender) => sender.clone(),
            None => {
                let sender = start_launcher()?;
                *launcher = Some(sender.clone());
                sender
            }
        };
        if sender.send(request).is_err() {
            // The loop catches spawn panics, so this only follows a failure
            // outside the spawn itself. Clear the sender so the next launch
            // starts a fresh thread instead of failing forever.
            *launcher = None;
            return Err(io::Error::other(
                "QEMU launcher thread is no longer running",
            ));
        }
    }

    response
        .recv()
        .map_err(|_disconnected| io::Error::other("QEMU launcher thread dropped a launch"))?
}

fn start_launcher() -> io::Result<mpsc::Sender<LaunchRequest>> {
    let (sender, requests) = mpsc::channel::<LaunchRequest>();
    thread::Builder::new()
        .name(String::from("crucible-qemu-launcher"))
        .spawn(move || {
            while let Ok(LaunchRequest { mut command, reply }) = requests.recv() {
                let result =
                    catch_unwind(AssertUnwindSafe(|| command.spawn())).unwrap_or_else(|_panic| {
                        Err(io::Error::other("QEMU launcher panicked while spawning"))
                    });
                // A requester that vanished can no longer own its child, so
                // the launcher reaps it rather than leave an orphan running.
                if let Err(SendError(Ok(mut child))) = reply.send(result) {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        })?;
    Ok(sender)
}
