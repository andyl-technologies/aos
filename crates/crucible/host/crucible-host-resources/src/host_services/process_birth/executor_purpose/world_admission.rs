//! Bounds the concrete World descriptor/ledger joins beneath the same Main.
//!
//! These observations preserve real Main, family and Preparation checks. They
//! refuse a busy control borrow without entering a new operation or replacing
//! its clock. Supervisor publication and later node setup retain their own
//! independent synchronization and custody requirements.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::sync::{Mutex, MutexGuard};

impl AuthenticatedNativeSlotPurpose {
    // Guard issuance reserves no descriptor window. The saved Original
    // governs actual World effect admission after this genuine Main check.
    fn check_world_origin(&self) -> Result<(), ServiceBirthError> {
        self.original
            .verify_retained_phase()
            .map_err(ServiceBirthError::from)?;
        if !self.owner.is_live() {
            return Err(ServiceBirthError::policy("normal executor main expired"));
        }
        self.family.check()
    }

    fn check_world_admission(&self) -> Result<(), ServiceBirthError> {
        self.check_world_origin()?;
        if let Some(partition) = borrow_world_control(
            &self.host_descriptors,
            "World descriptor custody is busy or uncertain",
        )?
        .as_ref()
        {
            partition.check()?;
        }
        self.original
            .verify_retained_phase()
            .map_err(ServiceBirthError::from)
    }
}

impl AuthenticatedNativeSubdivision {
    fn require_world_root(&self) -> Result<(), ServiceBirthError> {
        if self.node.is_some() {
            return Err(ServiceBirthError::policy(
                "World admission requires the containing Main pool root",
            ));
        }
        Ok(())
    }

    fn check_world_admission(&self) -> Result<(), ServiceBirthError> {
        self.require_world_root()?;
        self.owner.check_world_admission()
    }

    pub(super) fn begin_world_preparation(&self) -> Result<HostOperationGuard, ServiceBirthError> {
        self.require_world_root()?;
        self.owner.check_world_origin()?;
        self.owner
            .supervisor
            .begin(HostOperationClass::Preparation)
            .map_err(ServiceBirthError::from)
    }

    pub(super) fn verify_world_preparation(
        &self,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        self.check_world_admission()?;
        verify_preparation(&self.owner.supervisor, original)?;
        self.check_world_admission()
    }
}

pub(super) fn borrow_world_control<'a, T>(
    control: &'a Mutex<T>,
    refusal: &'static str,
) -> Result<MutexGuard<'a, T>, ServiceBirthError> {
    control
        .try_lock()
        .map_err(|_| ServiceBirthError::policy(refusal))
}

/// Observes the same actual Preparation after every attempted pre/work cut.
///
/// The caller releases its control borrows inside the attempted work, before
/// post. Any real claim is retained before work can fail; this helper creates no
/// holder, readiness observation, no-birth proof or successful native provider.
pub(super) fn observe_world_attempt(
    mut check: impl FnMut() -> Result<(), ServiceBirthError>,
    attempt: impl FnOnce() -> Result<(), ServiceBirthError>,
) -> (Result<(), ServiceBirthError>, Option<ServiceBirthError>) {
    let result = check().and_then(|()| attempt());
    let after = check().err();
    (result, after)
}

#[cfg(test)]
mod tests;
