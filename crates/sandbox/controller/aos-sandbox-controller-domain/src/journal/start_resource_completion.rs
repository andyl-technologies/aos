//! Retains the actual C and Source native samples for one final Start proof.
//!
//! Both names-first observations run once, including after the other refuses.
//! The samples yield comparison DATA only. The actual Start loan pays before
//! entry and retains these owners through its independent C and Root posts.

use std::{error::Error, mem::size_of};

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1;

use super::{Journal, JournalError, ProtectedJournalCurrentnessOriginalsV1};

type Witness = WriterWitnessOriginalsV1<JournalError>;

struct PositionOriginalV2 {
    names: ProtectedJournalCurrentnessOriginalsV1,
    witness: Witness,
    result: Option<Result<[u8; 64], JournalError>>,
    retired: bool,
}

impl PositionOriginalV2 {
    const fn new() -> Self {
        Self {
            names: ProtectedJournalCurrentnessOriginalsV1::new(),
            witness: Witness::new(),
            result: None,
            retired: false,
        }
    }

    fn observe_once(&mut self, journal: &Journal) {
        if self.result.is_some() {
            return;
        }
        self.result = Some((|| {
            let names = journal
                .observe_held_physical_names_retaining_v1(&mut self.names, &mut self.witness)?;
            let (_, _, end) = self
                .names
                .completed_held_file_boundary_data_v1()
                .ok_or(JournalError::ProtectedBoundary)?;
            let next = journal.snapshot_sequence();
            if next == 0 || end == 0 {
                return Err(JournalError::ProtectedBoundary);
            }

            let mut bytes = [0; 64];
            bytes[..48].copy_from_slice(&names.to_bytes());
            bytes[48..56].copy_from_slice(&next.to_be_bytes());
            bytes[56..].copy_from_slice(&end.to_be_bytes());
            Ok(bytes)
        })());
    }

    fn data(&self) -> Result<&[u8; 64], JournalError> {
        match &self.result {
            Some(Ok(bytes)) => Ok(bytes),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.names
            .failure()
            .or_else(|| self.witness.failure())
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    fn retire_positive_once(&mut self) -> Result<(), JournalError> {
        self.data()?;
        if self.retired {
            return Err(JournalError::ProtectedBoundary);
        }
        self.names.settle_positive_once_v1();
        if !self.witness.retire_positive_metadata_once_v1() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.retired = true;
        Ok(())
    }
}

/// Owns both reached samples until the actual final resource posts complete.
pub(crate) struct StartResourceNativePositionsOriginalV2 {
    controller: PositionOriginalV2,
    source: PositionOriginalV2,
    entered: bool,
    reentered: bool,
}

impl StartResourceNativePositionsOriginalV2 {
    pub(crate) const fn new() -> Self {
        Self {
            controller: PositionOriginalV2::new(),
            source: PositionOriginalV2::new(),
            entered: false,
            reentered: false,
        }
    }

    pub(crate) fn receiving_demand_v2(
        controller: &Journal,
        source: &Journal,
    ) -> Result<ResourceVector, JournalError> {
        let witness = Witness::receiving_footprint_v1().ok_or(JournalError::JournalTooLarge)?;
        let memory = witness
            .memory_bytes
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(size_of::<Self>().checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(JournalError::JournalTooLarge)?;
        controller
            .held_names_receiving_demand_v2()?
            .checked_add(source.held_names_receiving_demand_v2()?)
            .and_then(|demand| {
                demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, memory))
            })
            .map_err(|_| JournalError::JournalTooLarge)
    }

    pub(crate) fn observe_once_v2(
        &mut self,
        controller: &Journal,
        source: &Journal,
    ) -> Result<(), JournalError> {
        if self.entered {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.entered = true;
        self.controller.observe_once(controller);
        // The second actual journal is independent of the first one's result.
        self.source.observe_once(source);
        self.data_v2().map(|_| ())
    }

    pub(crate) fn data_v2(&self) -> Result<(&[u8; 64], &[u8; 64]), JournalError> {
        if !self.entered || self.reentered {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok((self.controller.data()?, self.source.data()?))
    }

    pub(crate) fn retire_positive_once_v2(&mut self) -> Result<(), JournalError> {
        self.data_v2()?;
        self.controller.retire_positive_once()?;
        self.source.retire_positive_once()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.controller
            .failure()
            .or_else(|| self.source.failure())
            .or_else(|| {
                self.reentered
                    .then_some(&JournalError::ProtectedBoundary as _)
            })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    fn writer(root: &std::path::Path) -> Journal {
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = root.metadata().unwrap().uid();
        Journal::open_protected_at_uid(
            root,
            "history.journal",
            super::super::JournalLimits::default(),
            uid,
        )
        .unwrap()
        .0
    }

    #[test]
    fn both_failed_names_keep_their_native_prefix_and_first_cause() {
        let c = tempfile::tempdir().unwrap();
        let s = tempfile::tempdir().unwrap();
        let controller = writer(c.path());
        let source = writer(s.path());
        std::fs::remove_file(c.path().join("history.journal")).unwrap();
        std::fs::remove_file(s.path().join("history.journal")).unwrap();

        let mut original = StartResourceNativePositionsOriginalV2::new();
        assert!(original.observe_once_v2(&controller, &source).is_err());
        assert_eq!(original.controller.names.retained_file_count(), 1);
        assert_eq!(original.source.names.retained_file_count(), 1);
        let cause = original.failure().unwrap() as *const (dyn Error + 'static);

        assert!(original.retire_positive_once_v2().is_err());
        assert!(original.observe_once_v2(&controller, &source).is_err());
        assert!(std::ptr::addr_eq(
            cause,
            original.failure().unwrap() as *const _
        ));
        assert_eq!(original.controller.names.retained_file_count(), 1);
        assert_eq!(original.source.names.retained_file_count(), 1);
    }

    #[test]
    fn held_observation_geometry_prices_two_actual_names_per_writer() {
        let c = tempfile::tempdir().unwrap();
        let s = tempfile::tempdir().unwrap();
        let controller = writer(c.path());
        let source = writer(s.path());

        let demand =
            StartResourceNativePositionsOriginalV2::receiving_demand_v2(&controller, &source)
                .unwrap();
        assert_eq!(demand.get(D::OpenFiles), 4);
        assert_eq!(demand.get(D::MetadataEntries), 4);
        assert!(
            demand.get(D::MemoryBytes)
                > 2 * size_of::<StartResourceNativePositionsOriginalV2>() as u64
        );
    }
}
