//! Real subprocess regressions for bounded planner I/O and inherited pipes.

// crucible-lint: allow panic-shortcut -- fixtures fail at the violated subprocess invariant.
#![allow(clippy::expect_used)]

use super::*;

const CHILD_TEST: &str = "planner_process::pipes::tests::child";
const CHILD_MODE: &str = "CRUCIBLE_PLANNER_PIPE_TEST_MODE";

pub(in crate::planner_process) fn child_command(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
        .env(CHILD_MODE, mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[test]
#[ignore = "subprocess fixture invoked only by the bounded pipe regressions"]
fn child() {
    let mode = std::env::var(CHILD_MODE).expect("explicit subprocess mode");
    if mode == "blocked" {
        loop {
            thread::park();
        }
    }
    let mut request = Vec::new();
    io::stdin().read_to_end(&mut request).expect("read request");
    if mode == "inherited-pipe" {
        // The group owner must terminate this descendant when the direct
        // child exits without closing every inherited output descriptor.
        let mut descendant = child_command("blocked");
        descendant
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        // This subprocess deliberately exits while the pipe holder is alive.
        // The outer test's owned process group kills it; the system reaper
        // adopts it after this fixture exits. Waiting here would hide the bug.
        // crucible-lint: allow rust-allow -- this fixture models a child that exits without closing inherited pipes.
        #[allow(clippy::zombie_processes)]
        let _descendant = descendant.spawn().expect("spawn pipe holder");
    }
}

#[test]
fn unread_request_pipe_obeys_the_exchange_deadline() {
    let owner = owner::ProcessOwner::new().expect("process owner");
    let mut command = child_command("blocked");
    let result = owner.run(&mut command, |child| {
        exchange(
            child,
            &vec![0; 1024 * 1024],
            process_now() + Duration::from_millis(100),
            &AtomicBool::new(false),
        )
    });
    assert!(matches!(
        result,
        Err(CanonicalPlannerProcessError::TimedOut)
    ));
}

#[test]
fn inherited_output_pipe_does_not_outlive_deadline_or_block_next_evaluation() {
    let owner = owner::ProcessOwner::new().expect("process owner");
    let mut command = child_command("inherited-pipe");
    let result = owner.run(&mut command, |child| {
        exchange(
            child,
            b"request",
            process_now() + Duration::from_secs(1),
            &AtomicBool::new(false),
        )
    });
    assert!(matches!(
        result,
        Err(CanonicalPlannerProcessError::TimedOut)
    ));

    let mut command = child_command("exit");
    let (status, _, _) = owner
        .run(&mut command, |child| {
            exchange(
                child,
                b"next",
                process_now() + Duration::from_secs(5),
                &AtomicBool::new(false),
            )
        })
        .expect("previous cleanup leaves owner reusable");
    assert!(status.success());
}

#[test]
fn cancellation_interrupts_blocked_pipe_io() {
    let owner = owner::ProcessOwner::new().expect("process owner");
    let canceled = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&canceled);
    let canceler = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        signal.store(true, Ordering::Release);
    });
    let mut command = child_command("blocked");
    let result = owner.run(&mut command, |child| {
        exchange(
            child,
            b"request",
            process_now() + Duration::from_secs(5),
            &canceled,
        )
    });
    canceler.join().expect("canceler completes");
    assert!(matches!(
        result,
        Err(CanonicalPlannerProcessError::Canceled)
    ));
}
