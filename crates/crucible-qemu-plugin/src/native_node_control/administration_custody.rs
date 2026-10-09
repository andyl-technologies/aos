//! Original self-registration custody, distinct from modeled worker admission.
//!
//! This component retains the exact original source record across reply loss.
//! It never releases a modeled gate, excludes worker bit 3 or supplies readiness.
//! Native self-registration is invoked by the installed sole reader; every retry
//! still calls the source's TLS check, even when historical facts are cached.

use std::sync::{Mutex, TryLockError};

use crucible_protocol::node_control::{
    NativeAdministrativeFacts, NativeAdministrativePreparation, NativeCommandError,
};

use super::administration_abi::{
    NativeAdministrationFacts, NativeAdministrationPolicy, QueryAdministration,
    RegisterAdministration,
};

#[derive(Default)]
struct OriginalRegistration {
    raw: Option<NativeAdministrationFacts>,
    facts: Option<NativeAdministrativeFacts>,
    divergent_raw: Option<NativeAdministrationFacts>,
    failed: bool,
}

#[cfg(test)]
#[path = "administration_custody_tests.rs"]
mod tests;

/// Retains one installed role's original native registration and diagnostic bytes.
pub(crate) struct AdministrationCustody {
    preparation: NativeAdministrativePreparation,
    policy: NativeAdministrationPolicy,
    register: RegisterAdministration,
    query: QueryAdministration,
    original: Mutex<OriginalRegistration>,
}

impl AdministrationCustody {
    /// Copies the already validated original record without another source query.
    ///
    /// This historical view carries no current thread-life or readiness proof.
    pub(crate) fn retained_original(&self) -> Option<NativeAdministrativeFacts> {
        let original = self.original.try_lock().ok()?;
        if original.failed {
            return None;
        }
        original.facts.clone()
    }
    /// Retains complete original policy before the reader invokes native enrollment.
    ///
    /// # Errors
    /// Refuses invalid preparation. No native registration or modeled effect occurs.
    pub(crate) fn new(
        preparation: NativeAdministrativePreparation,
        register: RegisterAdministration,
        query: QueryAdministration,
    ) -> Result<Self, NativeCommandError> {
        let policy = NativeAdministrationPolicy::from_preparation(&preparation)?;
        Ok(Self {
            preparation,
            policy,
            register,
            query,
            original: Mutex::new(OriginalRegistration::default()),
        })
    }

    /// Invokes actual self-registration from the installed administrative reader.
    ///
    /// An original retry checks native TLS rather than promoting a cached thread
    /// identifier to authority. The source observes its own OS PID/TID and fd.
    /// These historical facts do not attest complete native roots or liveness.
    ///
    /// # Errors
    /// Refuses busy custody, native refusal, differing original source records,
    /// malformed facts, or a source record for a different process/thread.
    pub(crate) fn register_current_reader(
        &self,
    ) -> Result<NativeAdministrativeFacts, NativeCommandError> {
        let mut original = self.try_original()?;
        if original.failed {
            return Err(NativeCommandError::Conflict);
        }
        let mut raw = NativeAdministrationFacts::default();
        let status = (self.register)(&self.policy, &mut raw);
        if status != 0 {
            original.retain_failed_output(raw);
            return Err(NativeCommandError::Conflict);
        }
        let facts = original.retain_successful_output(raw, &self.preparation)?;
        // SAFETY: SYS_gettid takes no pointers and observes this actual Linux
        // calling thread. It grants no native effect or scheduling permission.
        let thread = unsafe { libc::syscall(libc::SYS_gettid) };
        if facts.process_id.get() != u64::from(std::process::id())
            || thread <= 0
            || facts.thread_id.get() != thread as u64
        {
            original.failed = true;
            return Err(NativeCommandError::Conflict);
        }
        Ok(facts)
    }

    /// Recovers the original historical record without another registration.
    ///
    /// Querying an exited reader does not rehabilitate it or prove thread life.
    /// An inherited fork cannot adopt this source's original process record.
    ///
    /// # Errors
    /// Refuses absent registration, busy or divergent custody, native refusal,
    /// differing source bytes, or a record belonging to a different process.
    pub(crate) fn query_original(&self) -> Result<NativeAdministrativeFacts, NativeCommandError> {
        let mut original = self.try_original()?;
        if original.failed || original.facts.is_none() {
            return Err(NativeCommandError::Conflict);
        }
        let mut raw = NativeAdministrationFacts::default();
        let scope = self
            .preparation
            .phase
            .initialization
            .preparation
            .scope
            .identity_digest()?;
        let commitment = self.preparation.identity_digest()?;
        let status = (self.query)(scope.as_ptr(), commitment.as_ptr(), &mut raw);
        if status != 0 {
            original.retain_failed_output(raw);
            return Err(NativeCommandError::Conflict);
        }
        let facts = original.retain_successful_output(raw, &self.preparation)?;
        if facts.process_id.get() != u64::from(std::process::id()) {
            original.failed = true;
            return Err(NativeCommandError::Conflict);
        }
        Ok(facts)
    }

    fn try_original(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, OriginalRegistration>, NativeCommandError> {
        match self.original.try_lock() {
            Ok(original) => Ok(original),
            Err(TryLockError::WouldBlock | TryLockError::Poisoned(_)) => {
                Err(NativeCommandError::Conflict)
            }
        }
    }
}

impl OriginalRegistration {
    fn retain_failed_output(&mut self, raw: NativeAdministrationFacts) {
        // A nonzero failure output cannot be interpreted as no registration.
        // Keep the first diagnostic alongside the genuine original observation.
        if raw != NativeAdministrationFacts::default() {
            if self.divergent_raw.is_none() {
                self.divergent_raw = Some(raw);
            }
            self.failed = true;
        }
    }

    fn retain_successful_output(
        &mut self,
        raw: NativeAdministrationFacts,
        preparation: &NativeAdministrativePreparation,
    ) -> Result<NativeAdministrativeFacts, NativeCommandError> {
        if self.raw.is_some_and(|original| original != raw) {
            if self.divergent_raw.is_none() {
                self.divergent_raw = Some(raw);
            }
            self.failed = true;
            return Err(NativeCommandError::Conflict);
        }
        // Preserve source bytes before validation or allocating any reply.
        self.raw = Some(raw);
        let facts = match raw.decode().and_then(|facts| {
            facts.validate_against(preparation)?;
            Ok(facts)
        }) {
            Ok(facts) => facts,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        self.facts = Some(facts.clone());
        Ok(facts)
    }
}
