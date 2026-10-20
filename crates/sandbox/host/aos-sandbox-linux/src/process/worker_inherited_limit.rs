//! Retains actual inherited worker limits and privilege observations.
//!
//! This read-only native destination supplies no financial or process role.
//! A genuine fixed worker owns it beside the same delivered aggregate before
//! READY; the parent independently authenticates that actual worker and pays
//! its complete shape before launch. Ordinary workers never enter this gate.

use crate::{Error, Result};
use rustix::thread::{Capability, CapabilitySet, CapabilitySets};

#[derive(Clone, Copy, Debug)]
enum First { Limits, Privileges, Capabilities, Bounding, Ambient, Policy, Closed }

/// Reports that the actual native recipe remains refused in its owning sink.
#[derive(Debug, thiserror::Error)]
#[error("fixed worker inherited limit recipe is incomplete or refused")]
pub struct StorageWorkerInheritedLimitRefusalV1;

/// Owns actual limits and all capability/exec privilege results before policy.
///
/// No setter, raw descriptor, caller identity or budget can create a positive
/// observation. This owner is passive native evidence, not funding authority.
#[derive(Debug)]
pub struct StorageWorkerInheritedLimitOriginalV1 {
    limits: Option<Result<rustix::process::Rlimit>>,
    privileges: Option<rustix::io::Result<bool>>,
    capabilities: Option<rustix::io::Result<CapabilitySets>>,
    bounding: Option<rustix::io::Result<bool>>,
    ambient: Option<rustix::io::Result<bool>>,
    policy: Option<Result<()>>,
    first: Option<First>,
    entered: bool,
}

impl StorageWorkerInheritedLimitOriginalV1 {
    /// Creates empty storage without native work, allocation or authority.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: None, privileges: None, capabilities: None,
            bounding: None, ambient: None, policy: None, first: None, entered: false,
        }
    }

    /// Observes the actual calling worker once without changing its state.
    ///
    /// All five original native calls remain parked before classification.
    /// Positive policy requires hard/soft128, no-new-privileges, and absence of
    /// SYS_RESOURCE in current, inherited, bounding and ambient capability
    /// sets. Descendants therefore inherit the existing hard ceiling without
    /// an exec-file capability or setid escape. This is not a process-count or
    /// simultaneous-parent/child/descriptor-phase proof.
    ///
    /// # Errors
    ///
    /// Refuses repeat entry, any native syscall error or a differing actual
    /// recipe. Every reached result and the original first cause remain held.
    pub fn capture_once(&mut self) -> std::result::Result<(), StorageWorkerInheritedLimitRefusalV1> {
        if self.entered {
            self.first.get_or_insert(First::Closed);
            return Err(StorageWorkerInheritedLimitRefusalV1);
        }
        self.entered = true;
        self.limits = Some(super::observe_nofile_limit_v1());
        self.privileges = Some(rustix::thread::no_new_privs());
        self.capabilities = Some(rustix::thread::capabilities(None));
        self.bounding = Some(rustix::thread::capability_is_in_bounding_set(Capability::SystemResource));
        self.ambient = Some(rustix::thread::capability_is_in_ambient_set(Capability::SystemResource));

        for (failed, first) in [
            (matches!(self.limits, Some(Err(_))), First::Limits),
            (matches!(self.privileges, Some(Err(_))), First::Privileges),
            (matches!(self.capabilities, Some(Err(_))), First::Capabilities),
            (matches!(self.bounding, Some(Err(_))), First::Bounding),
            (matches!(self.ambient, Some(Err(_))), First::Ambient),
        ] {
            if failed { self.first.get_or_insert(first); }
        }
        if self.first.is_some() { return Err(StorageWorkerInheritedLimitRefusalV1); }
        let no_resource = self.capabilities.as_ref().is_some_and(|result| match result {
            Ok(sets) => !sets.effective.contains(CapabilitySet::SYS_RESOURCE)
                && !sets.permitted.contains(CapabilitySet::SYS_RESOURCE)
                && !sets.inheritable.contains(CapabilitySet::SYS_RESOURCE),
            Err(_) => false,
        });
        let exact = self.limits.as_ref().is_some_and(|result| match result {
            Ok(limits) => limits.current == Some(128) && limits.maximum == Some(128),
            Err(_) => false,
        }) && matches!(self.privileges, Some(Ok(true))) && no_resource
            && matches!(self.bounding, Some(Ok(false)))
            && matches!(self.ambient, Some(Ok(false)));
        self.policy = Some(if exact { Ok(()) } else { Err(Error::InvalidInput {
            field: "fixed worker inherited limit", message: "actual hard128 or privilege recipe differs".into(),
        }) });
        if matches!(self.policy, Some(Ok(()))) { Ok(()) } else {
            self.first = Some(First::Policy);
            Err(StorageWorkerInheritedLimitRefusalV1)
        }
    }

    /// Borrows the actual chronological native or recipe failure.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Limits => self.limits.as_ref()?.as_ref().err().map(|error| error as _),
            First::Privileges => self.privileges.as_ref()?.as_ref().err().map(|error| error as _),
            First::Capabilities => self.capabilities.as_ref()?.as_ref().err().map(|error| error as _),
            First::Bounding => self.bounding.as_ref()?.as_ref().err().map(|error| error as _),
            First::Ambient => self.ambient.as_ref()?.as_ref().err().map(|error| error as _),
            First::Policy => self.policy.as_ref()?.as_ref().err().map(|error| error as _),
            First::Closed => Some(&StorageWorkerInheritedLimitRefusalV1),
        }
    }

    /// Prices actual resident/construction frames and bounded native errors.
    #[must_use]
    pub fn requested_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(2)?.checked_add(6 * 256)
    }

    /// Counts fields, actual Rlimit/capability results and construction controls.
    pub const METADATA_ENTRIES_V1: usize = 8 + 2 + 3 + 5 + 2;
}

impl Default for StorageWorkerInheritedLimitOriginalV1 {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolated_wrong_hard_limit_keeps_every_actual_native_result_and_first_cause() {
        const SELECTOR: &str = "AOS_TEST_FIXED_WORKER_INHERITED_LIMIT";
        if std::env::var_os(SELECTOR).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "process::worker_inherited_limit::tests::isolated_wrong_hard_limit_keeps_every_actual_native_result_and_first_cause"])
                .env(SELECTOR, "1").status().unwrap();
            assert!(status.success());
            return;
        }
        let inherited = super::super::observe_nofile_limit_v1().unwrap();
        let wrong_limit = inherited.maximum.unwrap_or(127).min(127);
        rustix::process::setrlimit(rustix::process::Resource::Nofile,
            rustix::process::Rlimit { current: Some(wrong_limit), maximum: Some(wrong_limit) }).unwrap();
        let mut original = StorageWorkerInheritedLimitOriginalV1::new();

        assert!(original.capture_once().is_err());
        assert_eq!(original.limits.as_ref().unwrap().as_ref().unwrap().maximum, Some(wrong_limit));
        assert!(original.privileges.is_some());
        assert!(original.capabilities.is_some());
        assert!(original.bounding.is_some());
        assert!(original.ambient.is_some());
        let first = original.failure().unwrap() as *const dyn std::error::Error as *const ();

        assert!(original.capture_once().is_err());
        assert_eq!(first, original.failure().unwrap() as *const dyn std::error::Error as *const ());
        assert_eq!(original.limits.as_ref().unwrap().as_ref().unwrap().maximum, Some(wrong_limit));
    }
}
