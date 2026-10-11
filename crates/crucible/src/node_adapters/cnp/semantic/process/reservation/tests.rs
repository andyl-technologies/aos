//! Checks pre-Child callback ordering and one original failed launch reservation.

#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Test assertions deliberately use panic-shortcut checks for the exact refusal.
#![allow(clippy::unwrap_used)]

use std::{
    cell::{Cell, RefCell},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Command,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

use crucible_node_contract::{ContentRef, U64, canonical};

use super::{CnpSemanticLaunchReservation, CnpSemanticProcessCustody, CnpSemanticProcessSlot};

/// Owns only the exclusively created private fixture directory.
struct Directory(PathBuf);

impl Directory {
    fn new() -> std::io::Result<Self> {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

        for _ in 0..64 {
            let ordinal = NEXT_DIRECTORY
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| {
                    std::io::Error::other("packet fixture directory identities exhausted")
                })?;
            let path = std::env::temp_dir().join(format!(
                "aos-packet-reservation-{}-{ordinal}",
                std::process::id()
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "packet fixture directory collision allowance exhausted",
        ))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        // Exclusive creation makes this cleanup responsible only for this fixture.
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}

struct Slot {
    identities: Rc<Cell<usize>>,
    panic_first: bool,
    retained: Rc<RefCell<Option<CnpSemanticProcessCustody>>>,
}

impl CnpSemanticProcessSlot for Slot {
    fn identity(&self) -> U64 {
        let calls = self.identities.get();
        self.identities.set(calls + 1);
        assert!(
            !self.panic_first && calls == 0,
            "identity callback is pre-Child only"
        );
        U64::new(73)
    }

    fn retain(&mut self, custody: CnpSemanticProcessCustody) {
        assert!(self.retained.borrow().is_none());
        *self.retained.borrow_mut() = Some(custody);
    }
}

fn reference() -> ContentRef {
    ContentRef {
        hash: canonical::hash("cnp.blob.v1", b"model-only executable identity").unwrap(),
        length: U64::new(30),
        media_type: "application/octet-stream".into(),
    }
}

#[test]
fn slot_identity_unwind_precedes_any_child_or_native_retention() {
    let identities = Rc::new(Cell::new(0));
    let retained = Rc::new(RefCell::new(None));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CnpSemanticLaunchReservation::reserve(
            "unlaunched-model-directory".into(),
            reference(),
            Box::new(Slot {
                identities: identities.clone(),
                panic_first: true,
                retained: retained.clone(),
            }),
        )
    }));

    assert!(result.is_err());
    assert_eq!(identities.get(), 1);
    assert!(retained.borrow().is_none());
}

#[test]
fn cached_identity_does_not_repeat_callback_or_expose_unlaunched_custody() {
    let identities = Rc::new(Cell::new(0));
    let retained = Rc::new(RefCell::new(None));
    let reservation = CnpSemanticLaunchReservation::reserve(
        "unlaunched-model-directory".into(),
        reference(),
        Box::new(Slot {
            identities: identities.clone(),
            panic_first: false,
            retained: retained.clone(),
        }),
    );
    let failure = match reservation.into_guard() {
        Ok(_) => panic!("unlaunched reservation cannot become an actual guard"),
        Err(failure) => failure,
    };

    assert_eq!(failure.original.guard.supervision_id(), U64::new(73));
    assert!(failure.original.guard.custody().is_err());
    assert_eq!(identities.get(), 1);
    drop(failure);
    assert!(retained.borrow().is_none());
}

#[test]
fn failed_spawn_keeps_same_reservation_and_refuses_second_spawn() {
    let identities = Rc::new(Cell::new(0));
    let retained = Rc::new(RefCell::new(None));
    let mut reservation = CnpSemanticLaunchReservation::reserve(
        "unlaunched-model-directory".into(),
        reference(),
        Box::new(Slot {
            identities: identities.clone(),
            panic_first: false,
            retained: retained.clone(),
        }),
    );
    let directory = Directory::new().unwrap();
    let missing = directory.path().join("absent-peer");
    let first = reservation.launch(&mut Command::new(&missing));
    let second = reservation.launch(&mut Command::new(&missing));

    assert!(first.is_err());
    assert!(matches!(
        second,
        Err(crucible_node_provider::ProviderError::Correlation(
            "generic launch already attempted"
        ))
    ));
    assert_eq!(reservation.guard.supervision_id(), U64::new(73));
    assert_eq!(identities.get(), 1);
    assert!(retained.borrow().is_none());
}

// Cleanup remains independent of assertions and the simulated callback unwind.
struct NativeCleanup(Rc<RefCell<Option<CnpSemanticProcessCustody>>>);

impl Drop for NativeCleanup {
    fn drop(&mut self) {
        if let Some(mut custody) = self.0.borrow_mut().take()
            && let Some(child) = custody.child.as_mut()
        {
            if matches!(child.try_wait(), Ok(None)) {
                let _signal = child.kill();
            }
            let _reaped = child.wait();
        }
    }
}

#[test]
#[ignore = "requires the source-built native test executable; not a model or class gate"]
fn post_spawn_unwind_retains_the_same_child_in_the_original_supervisor() {
    use std::os::unix::process::CommandExt;

    let executable = std::env::current_exe().unwrap();
    let measured = crucible_node_provider::conformance::measure_executable(&executable).unwrap();
    let directory = Directory::new().unwrap();
    let identities = Rc::new(Cell::new(0));
    let retained = Rc::new(RefCell::new(None));
    let _cleanup = NativeCleanup(retained.clone());
    let mut reservation = CnpSemanticLaunchReservation::reserve(
        directory.path().to_path_buf(),
        measured.clone(),
        Box::new(Slot {
            identities: identities.clone(),
            panic_first: false,
            retained: retained.clone(),
        }),
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Even a fast-exiting child or failed kernel authentication remains owned.
        let _original = reservation.launch(
            Command::new(&executable)
                .arg("--list")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .process_group(0),
        );
        assert!(reservation.guard.custody().unwrap().provider_pid() > 0);
        assert_eq!(reservation.guard.supervision_id(), U64::new(73));
        panic!("modeled post-spawn authority unwind");
    }));
    let pid = reservation.guard.custody().unwrap().provider_pid();

    assert!(result.is_err());
    assert_eq!(identities.get(), 1);
    drop(reservation);
    let mut custody = retained.borrow_mut().take().unwrap();
    assert_eq!(custody.provider_pid(), pid);
    assert_eq!(custody.expected_executable, measured);
    assert_eq!(custody.private_directory(), directory.path());
    custody.child.as_mut().unwrap().wait().unwrap();
    assert!(custody.poll_reclamation().unwrap());
}
