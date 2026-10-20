//! Retains Storage's original once-paid PID1 service receiving envelope.
//!
//! The image policy and sealed delivery are DATA until rejoined with the
//! existing fixed Storage invocation and the live original PID1 producer.
//! This owner never creates a Project/Sandbox or native-effect reservation.
//! The aggregate was paid once by PID1 before jobs, socket activation and
//! startup capture; opening Storage does not charge the node again.

use std::fs::File;
use std::os::fd::OwnedFd;

use super::ResourceReservationErrorV1;
use aos_sandbox_broker::receiving::{OriginalEnrollment, OriginalEnrollmentPairAttemptV1};
use super::service_interval::ObserverLifetime;
use aos_sandbox_core::ResourceVector;
/// Retains the same original pair assigned to the fixed Storage invocation.
///
/// Construction is restricted to Core's first complete inherited-table
/// capture. No caller file, resource vector, capsule or receipt creates it.
/// Failed admission retains its whole observations and both original files.
/// Loans borrow this owner, so its files cannot be disposed during a loan.
/// Ordinary descriptor disposal never refunds the shared bootstrap envelope
/// or reconstructs the once-only original PID1 recipient.
#[must_use]
pub struct StorageComponentEnvelopeOriginalV1 {
    policy: File,
    enrollment: File,
    process: u32,
    closed: bool,
    receiving: StorageReceivingPreparationV1,
}

impl StorageComponentEnvelopeOriginalV1 {
    pub(crate) fn from_original_table(policy: OwnedFd, enrollment: OwnedFd) -> Self {
        Self {
            policy: policy.into(),
            enrollment: enrollment.into(),
            process: std::process::id(),
            closed: false,
            receiving: StorageReceivingPreparationV1::new(),
        }
    }

    // This bounded negative-prefix read belongs only to the genuine fixed
    // inherited-table owner. The envelope remains DATA until the actual native
    // startup rejoins current PID1, cgroup, recipient and producer observations.
    pub(crate) fn prepare_storage_receiving_once(
        &mut self,
    ) -> Result<ResourceVector, &(dyn std::error::Error + 'static)> {
        if self.closed || self.process != std::process::id() {
            self.closed = true;
            return Err(&CLOSED);
        }
        self.receiving.prepare(&self.policy, &self.enrollment)
    }

    // This fence belongs to the same original. It supplies no payment and
    // cannot reconstruct that original from an envelope or a decoded record.
    pub(crate) fn storage_receiving_lifetime(
        &self,
    ) -> Result<ObserverLifetime, &(dyn std::error::Error + 'static)> {
        self.receiving.require_storage()?;
        self.receiving.lifetime.as_ref().cloned().ok_or(&CLOSED as &dyn std::error::Error)
    }

    pub(crate) fn require_storage_receiving_binding(
        &self,
        before: ([u8; 16], [u8; 16]),
        after: ([u8; 16], [u8; 16]),
    ) -> Result<(), ResourceReservationErrorV1> {
        self.receiving.require_storage()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let original = self.receiving.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        if self.closed || self.process != std::process::id() || before != after
            || original.recipient_invocation != before.0
            || original.identity.native_fields().invocation != before.1
        {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        Ok(())
    }

    pub(crate) fn storage_receiving_pair_post(&self) -> StorageComponentPairPostV1 {
        let mut post = StorageComponentPairPostV1 {
            pair: OriginalEnrollmentPairAttemptV1::new_controller(crate::controller_resource_reservation::q04_intake::native_layout()),
            original: None,
            binding: None,
        };
        post.original = Some(post.pair.observe_once(&self.policy, &self.enrollment)
            .copied().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable));
        post.binding = Some((|| {
            self.receiving.require_storage()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let initial = self.receiving.original.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let current = post.original.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            if self.closed || self.process != std::process::id() || initial != current {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        post
    }

    pub(crate) fn storage_receiving_failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.receiving.failure()
    }

}

impl Drop for StorageComponentEnvelopeOriginalV1 {
    fn drop(&mut self) {
        self.closed = true;
        if let Some(lifetime) = &self.receiving.lifetime {
            lifetime.close();
        }
    }
}

static CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::EnrollmentUnavailable;

// The wrapper retains every native/canonical result of the same original pair.
// Its fields and sole factory stay private to the actual component owner.
pub(crate) struct StorageComponentPairPostV1 {
    pair: OriginalEnrollmentPairAttemptV1,
    original: Option<Result<OriginalEnrollment, ResourceReservationErrorV1>>,
    binding: Option<Result<(), ResourceReservationErrorV1>>,
}

impl StorageComponentPairPostV1 {
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.pair.failure()
            .or_else(|| self.original.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.binding.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
    }

    pub(crate) fn require_current(&self) -> Result<(), &(dyn std::error::Error + 'static)> {
        if let Some(error) = self.failure() {
            return Err(error);
        }
        if !matches!(self.binding, Some(Ok(()))) {
            return Err(&CLOSED);
        }
        Ok(())
    }
}

// Historical V1..V6 remain readable DATA. They lack this whole-service
// subdivision and cannot open contacted receiving from their historical rows.
struct StorageReceivingPreparationV1 {
    pair: OriginalEnrollmentPairAttemptV1,
    original: Option<Result<OriginalEnrollment, ResourceReservationErrorV1>>,
    shape: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    lifetime: Option<ObserverLifetime>,
    closed: bool,
}

impl StorageReceivingPreparationV1 {
    fn new() -> Self {
        Self {
            pair: OriginalEnrollmentPairAttemptV1::new_controller(crate::controller_resource_reservation::q04_intake::native_layout()),
            original: None,
            shape: None,
            lifetime: None,
            closed: false,
        }
    }

    fn prepare(
        &mut self,
        policy: &File,
        delivery: &File,
    ) -> Result<ResourceVector, &(dyn std::error::Error + 'static)> {
        if self.original.is_some() || self.closed {
            self.closed = true;
            if let Some(lifetime) = &self.lifetime {
                lifetime.close();
            }
            return Err(&CLOSED);
        }
        self.original = Some(self.pair.observe_once(policy, delivery)
            .copied().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable));
        self.shape = Some(match self.original.as_ref() {
            Some(Ok(original)) => original.policy.bootstrap_provisions().storage_receiving
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)
                .and_then(|envelope| {
                    super::bank::require_storage_service_envelope(envelope)
                        .map(|()| envelope).map_err(ResourceReservationErrorV1::from)
                }),
            _ => Err(ResourceReservationErrorV1::EnrollmentUnavailable),
        });
        let envelope = self.shape.as_ref().and_then(|result| result.as_ref().ok()).copied();
        if envelope.is_some() && self.pair.failure().is_none() {
            self.lifetime = Some(ObserverLifetime::begin());
        }
        if let Some(error) = self.failure() {
            return Err(error);
        }
        envelope.ok_or(&CLOSED as &dyn std::error::Error)
    }

    fn require_storage(&self) -> Result<ResourceVector, &(dyn std::error::Error + 'static)> {
        if let Some(error) = self.failure() {
            return Err(error);
        }
        self.shape.as_ref().and_then(|result| result.as_ref().ok()).copied()
            .ok_or(&CLOSED as &dyn std::error::Error)
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.pair.failure()
            .or_else(|| self.original.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.shape.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.closed.then_some(&CLOSED as &(dyn std::error::Error + 'static)))
    }
}
