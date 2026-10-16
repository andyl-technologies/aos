//! Tests control-return ordering with real descriptors and one actual worker.
//!
//! These are component mechanisms, not Main/Source issuance fixtures. Ordinary
//! files model cgroup observations; no authenticated Target admission is minted.

use super::*;
use std::fs;
use std::os::unix::fs::MetadataExt;

fn mechanism_state(path: &Path) -> Result<Arc<DispatcherState>, LinuxQemuCgroupError> {
    Ok(Arc::new(DispatcherState {
        slot: Mutex::new(JobSlot {
            epoch: 0,
            phase: JobPhase::Idle,
            control: None,
            original: None,
        }),
        shutdown: AtomicBool::new(false),
        wake: create_cancellation_eventfd(path)?,
        _namespace: open_directory(path, "retain dispatcher mechanism namespace")?,
        path: path.to_owned(),
    }))
}

#[test]
fn returned_job_reuses_its_slot_only_after_actual_descriptor_close()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let state = mechanism_state(directory.path())?;
    let (control, cancellation) =
        super::super::tests::watcher_control_fixture(directory.path(), false)?;
    let descriptor = control.cgroup_events.as_raw_fd();
    let expected = control.cgroup_events.metadata()?;
    {
        let mut slot = state.slot.lock().unwrap();
        slot.epoch = 1;
        slot.phase = JobPhase::Returned;
        slot.control = Some(control);
    }
    let job = TargetWatchJob {
        state: Arc::clone(&state),
        epoch: 1,
        released: false,
    };

    let returned = job.retire().unwrap();
    assert_eq!(state.slot.lock().unwrap().phase, JobPhase::Retiring);
    let observed = fs::metadata(format!("/proc/self/fd/{descriptor}"))?;
    assert_eq!(
        (observed.dev(), observed.ino()),
        (expected.dev(), expected.ino())
    );
    drop(returned);

    assert_eq!(state.slot.lock().unwrap().phase, JobPhase::Idle);
    // Another parallel test may reuse the numeric descriptor. It cannot reopen
    // this private fixture's same inode between these two observations.
    assert!(
        fs::metadata(format!("/proc/self/fd/{descriptor}")).map_or(true, |observed| {
            (observed.dev(), observed.ino()) != (expected.dev(), expected.ino())
        })
    );
    assert_eq!(Arc::strong_count(&state), 1);
    drop(cancellation);
    Ok(())
}

#[test]
// crucible-lint: allow clippy-disallowed-method -- the real worker containment test retains one fixed wall-clock bound.
#[allow(clippy::disallowed_methods)]
fn one_worker_returns_actual_controls_for_sequential_jobs() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let state = mechanism_state(directory.path())?;
    let worker_state = Arc::clone(&state);
    let worker = thread::spawn(move || run(worker_state));
    let worker_id = worker.thread().id();
    let end = std::time::Instant::now() + Duration::from_secs(5);

    for epoch in 1..=4 {
        let child = directory.path().join(format!("job-{epoch}"));
        fs::create_dir(&child)?;
        let (control, cancellation) = super::super::tests::watcher_control_fixture(&child, false)?;
        signal_terminal(&control.watcher_state, cancellation.as_raw_fd())?;
        {
            let mut slot = state.slot.lock().unwrap();
            assert_eq!(slot.phase, JobPhase::Idle);
            slot.epoch = epoch;
            slot.phase = JobPhase::Queued;
            slot.control = Some(control);
        }
        let job = TargetWatchJob {
            state: Arc::clone(&state),
            epoch,
            released: false,
        };
        wake(&state.wake)?;
        while !job.is_finished() && std::time::Instant::now() < end {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(
            job.is_finished(),
            "same worker did not return actual job controls"
        );
        assert_eq!(worker.thread().id(), worker_id);
        assert!(!worker.is_finished());
        drop(job.retire().unwrap());
        assert_eq!(state.slot.lock().unwrap().phase, JobPhase::Idle);
    }

    state.shutdown.store(true, Ordering::Release);
    wake(&state.wake)?;
    while !worker.is_finished() && std::time::Instant::now() < end {
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        worker.is_finished(),
        "fixed Main worker did not physically stop"
    );
    worker.join().unwrap();
    assert_eq!(Arc::strong_count(&state), 1);
    Ok(())
}
