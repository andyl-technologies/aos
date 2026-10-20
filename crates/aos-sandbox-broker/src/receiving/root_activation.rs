//! Owns the original fixed Root activation table before role authentication.
//!
//! The four inherited descriptors and the actual names observation remain in
//! one owner. Its borrowed files and slots provide physical custody only: the
//! Root recipient still authenticates the original enrollment pair, pays its
//! fixed prefix and joins its actual process, profile and PID1 observations.
//! This module cannot construct an account, purpose grant or semantic writer.

use std::error::Error;
use std::fs::File;
use std::os::fd::OwnedFd;

use aos_sandbox_linux::inherited_fd::RootInitialActivationTableV1;

use super::{ActivationNamesErrorV1, original_activation_names_v1};

/// Describes an unavailable or repeated original Root activation capture.
#[derive(Debug, thiserror::Error)]
pub enum RootInitialActivationErrorV1 {
    /// The fixed table or its four unique role names are unavailable.
    #[error("original Root activation table is unavailable")]
    Unavailable,
    /// The original destination was entered again or inherited across a fork.
    #[error("original Root activation table was already entered")]
    Conflict,
}

/// Retains the original four-role Root activation and its native failures.
///
/// Construction is inert and accepts no descriptors, paths, accounts or
/// observations. Capture observes only the current process's initial table.
/// A successful physical capture carries no role or resource authority.
pub struct RootInitialActivationOriginalsV1 {
    table: RootInitialActivationTableV1,
    entries: [Option<OwnedFd>; 4],
    names: Option<Result<Vec<String>, ActivationNamesErrorV1>>,
    role_error: Option<RootInitialActivationErrorV1>,
    policy: Option<File>,
    delivery: Option<File>,
    pid1: Option<OwnedFd>,
    profile: Option<OwnedFd>,
    process: u32,
}

impl Default for RootInitialActivationOriginalsV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl RootInitialActivationOriginalsV1 {
    /// Creates inert destinations for the current process's fixed Root table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: RootInitialActivationTableV1::new(),
            entries: [const { None }; 4],
            names: None,
            role_error: None,
            policy: None,
            delivery: None,
            pid1: None,
            profile: None,
            process: std::process::id(),
        }
    }

    /// Captures the actual fixed table before parsing its unique role names.
    ///
    /// # Errors
    ///
    /// Retains the actual table or names failure and refuses missing, unknown
    /// or repeated roles. Reentry and use in another process are refused.
    pub fn capture_once(&mut self) -> Result<(), RootInitialActivationErrorV1> {
        if self.names.is_some() || self.role_error.is_some()
            || self.process != std::process::id()
        {
            return Err(RootInitialActivationErrorV1::Conflict);
        }
        if self.table.observe_once().is_err() {
            self.role_error = Some(RootInitialActivationErrorV1::Unavailable);
            return Err(RootInitialActivationErrorV1::Unavailable);
        }
        self.entries = self.table.take_completed_entries()
            .ok_or(RootInitialActivationErrorV1::Unavailable)?;
        self.names = Some(original_activation_names_v1(4));
        let names = self.names.as_ref().and_then(|result| result.as_ref().ok());
        let Some(names) = names else {
            self.role_error = Some(RootInitialActivationErrorV1::Unavailable);
            return Err(RootInitialActivationErrorV1::Unavailable);
        };
        if require_roles(names).is_err() {
            self.role_error = Some(RootInitialActivationErrorV1::Unavailable);
            return Err(RootInitialActivationErrorV1::Unavailable);
        }
        for (name, entry) in names.iter().zip(&mut self.entries) {
            match name.as_str() {
                "aos-normal-root-pid1-image" => self.pid1 = entry.take(),
                "aos-normal-root-profile" => self.profile = entry.take(),
                "aos-resource-image-policy-v1" => self.policy = entry.take().map(File::from),
                "aos-resource-pid1-enrollment-v1" => self.delivery = entry.take().map(File::from),
                _ => return Err(RootInitialActivationErrorV1::Unavailable),
            }
        }
        Ok(())
    }

    /// Borrows the process identity captured by the original inert owner.
    #[must_use]
    pub const fn process_id_v1(&self) -> u32 {
        self.process
    }

    /// Prices the added wrapper construction and its two borrowed carriers.
    ///
    /// This is nonauthorizing arithmetic. The genuine Root owner must add it
    /// to its cumulative fixed prefix before using the profile/kernel slots.
    /// It supplies no account, credit or admission by itself.
    #[must_use]
    pub fn additional_receiving_demand_v1() -> Option<aos_sandbox_core::ResourceVector> {
        use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<(&File, &File)>())?
            .checked_add(std::mem::size_of::<(&mut Option<OwnedFd>, &mut Option<OwnedFd>)>())?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            // Parent destination, construction temporary, native role-error
            // destination and the two borrowed carriers. The upper adapter
            // separately pays its preserved names-error projection slot.
            .with(D::MetadataEntries, 5))
    }

    /// Reports completion of the physical capture in this same process.
    #[must_use]
    pub fn is_captured_v1(&self) -> bool {
        self.process == std::process::id() && self.role_error.is_none()
            && self.names.as_ref().is_some_and(Result::is_ok)
    }

    /// Borrows the two original files for the existing enrollment-pair engine.
    ///
    /// The files are not cloned, replaced, reopened or decoded here. Their
    /// observations remain owned by the caller's actual pair destination.
    #[must_use]
    pub fn enrollment_originals_v1(&self) -> Option<(&File, &File)> {
        if !self.is_captured_v1() {
            return None;
        }
        Some((self.policy.as_ref()?, self.delivery.as_ref()?))
    }

    /// Borrows the actual PID1 and profile move slots from the same table.
    ///
    /// The genuine Root owner keeps this reservoir private and borrows these
    /// slots only after paying its fixed profile/kernel prefix. The slots
    /// provide no authority and cannot install a reservoir into a Root owner.
    pub fn profile_originals_v1(
        &mut self,
    ) -> Option<(&mut Option<OwnedFd>, &mut Option<OwnedFd>)> {
        if !self.is_captured_v1() {
            return None;
        }
        Some((&mut self.pid1, &mut self.profile))
    }

    /// Borrows an actual table failure for the existing role error adapter.
    #[must_use]
    pub fn table_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.table.failure().map(|cause| cause as &(dyn Error + 'static))
    }

    /// Borrows a failed names observation for the existing role error adapter.
    #[must_use]
    pub fn names_failure_v1(&self) -> Option<&ActivationNamesErrorV1> {
        self.names.as_ref()?.as_ref().err()
    }

    /// Borrows the fixed role refusal without changing the actual cause.
    #[must_use]
    pub fn role_failure_v1(&self) -> Option<&RootInitialActivationErrorV1> {
        self.role_error.as_ref()
    }

    /// Borrows the earliest actual capture failure without releasing custody.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.table.failure().map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| self.names.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| self.role_error.as_ref()
                .map(|cause| cause as &(dyn Error + 'static)))
    }
}

fn require_roles(names: &[String]) -> Result<(), RootInitialActivationErrorV1> {
    let roles = [
        "aos-normal-root-pid1-image",
        "aos-normal-root-profile",
        "aos-resource-image-policy-v1",
        "aos-resource-pid1-enrollment-v1",
    ];
    if names.len() != roles.len()
        || roles.iter().any(|role| names.iter().filter(|name| name.as_str() == *role).count() != 1)
    {
        return Err(RootInitialActivationErrorV1::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Vec<String> {
        ["aos-normal-root-pid1-image", "aos-normal-root-profile",
         "aos-resource-image-policy-v1", "aos-resource-pid1-enrollment-v1"]
            .into_iter().map(String::from).collect()
    }

    #[test]
    fn duplicate_or_late_unknown_role_cannot_select_originals() {
        let mut duplicate = names();
        duplicate[3] = duplicate[1].clone();
        assert!(require_roles(&duplicate).is_err());

        let mut unknown = names();
        unknown[3] = String::from("aos-resource-pid1-enrollment-v2");
        assert!(require_roles(&unknown).is_err());
        assert!(require_roles(&names()).is_ok());
    }

    #[test]
    fn inert_owner_has_no_positive_borrow_or_observation() {
        // The production initial-table fence remains armed even before IO.
        // Keep this inert fixture resident until the test process terminates.
        let mut original = std::mem::ManuallyDrop::new(RootInitialActivationOriginalsV1::new());
        assert!(!original.is_captured_v1());
        assert!(original.enrollment_originals_v1().is_none());
        assert!(original.profile_originals_v1().is_none());
        assert!(original.failure().is_none());
    }
}
