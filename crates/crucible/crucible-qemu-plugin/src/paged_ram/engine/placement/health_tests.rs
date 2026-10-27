//! Checks known worker failures at placement's local supervision cuts.
//!
//! These controls issue no native certificate and prove no release-race closure.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use crate::paged_ram::source::ObservationOperationError;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

#[derive(Clone, Copy)]
enum HealthChange {
    None,
    OwnerFailed,
    WorkerFailed,
    Stopping,
}

struct PlacementOperation<'a> {
    owner_failed: &'a AtomicBool,
    service_failed: &'a AtomicBool,
    stopping: &'a AtomicBool,
    change: HealthChange,
    refuse: bool,
    checked: AtomicUsize,
}

impl PlacementOperation<'_> {
    fn change_health(&self) {
        let flag = match self.change {
            HealthChange::None => return,
            HealthChange::OwnerFailed => self.owner_failed,
            HealthChange::WorkerFailed => self.service_failed,
            HealthChange::Stopping => self.stopping,
        };
        flag.store(true, Ordering::Release);
    }

    fn check(&self) -> Result<(), RamError> {
        check_placement_operation(self, self.owner_failed, self.service_failed, self.stopping)
    }
}

impl SourceOperation for PlacementOperation<'_> {
    fn wait_slice(&self) -> io::Result<Duration> {
        self.checked.fetch_add(1, Ordering::SeqCst);
        self.change_health();
        if self.refuse {
            return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        Ok(Duration::from_millis(1))
    }

    fn complete(&self) -> io::Result<()> {
        panic!("checking placement cannot commit completion");
    }

    fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
        self.wait_slice().map_err(Into::into)
    }

    fn complete_observation(&self) -> Result<(), ObservationOperationError> {
        panic!("placement checks cannot complete an observation");
    }
}

#[test]
fn known_failure_refuses_before_supervision_and_failure_during_it_refuses_afterward() {
    for change in [
        HealthChange::OwnerFailed,
        HealthChange::WorkerFailed,
        HealthChange::Stopping,
    ] {
        for known_before in [false, true] {
            let owner_failed = AtomicBool::new(false);
            let service_failed = AtomicBool::new(false);
            let stopping = AtomicBool::new(false);
            let operation = PlacementOperation {
                owner_failed: &owner_failed,
                service_failed: &service_failed,
                stopping: &stopping,
                change,
                refuse: false,
                checked: AtomicUsize::new(0),
            };
            if known_before {
                operation.change_health();
            }

            let result = operation.check();

            let expected = match change {
                HealthChange::Stopping => "physical placement worker is stopping",
                _ => "physical placement authority failed",
            };
            assert_eq!(result, Err(RamError::Invariant(expected)));
            assert_eq!(
                operation.checked.load(Ordering::SeqCst),
                usize::from(!known_before)
            );
        }
    }
}

#[test]
fn healthy_placement_preserves_the_original_supervision_refusal() {
    for refuse in [false, true] {
        let owner_failed = AtomicBool::new(false);
        let service_failed = AtomicBool::new(false);
        let stopping = AtomicBool::new(false);
        let operation = PlacementOperation {
            owner_failed: &owner_failed,
            service_failed: &service_failed,
            stopping: &stopping,
            change: HealthChange::None,
            refuse,
            checked: AtomicUsize::new(0),
        };

        let result = operation.check();

        if refuse {
            assert!(matches!(
                result,
                Err(RamError::Io(error)) if error.raw_os_error() == Some(libc::ETIMEDOUT)
            ));
        } else {
            assert_eq!(result, Ok(()));
        }
        assert_eq!(operation.checked.load(Ordering::SeqCst), 1);
    }
}
