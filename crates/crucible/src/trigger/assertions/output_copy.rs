//! Fallible copies of assertion diagnostics under their retained origin.
//!
//! Owning diagnostics deliberately have no unchecked `Clone` implementation.
//! Each copy uses a separate child of the original authority and retains that
//! child's credits until all of the copied fields have closed.

use super::*;

fn copy_under_origin<T>(
    custody: &crate::owned_decode::DecodeCustody,
    copy: impl FnOnce() -> Result<T, EngineError>,
) -> Result<T, EngineError> {
    let _original = custody.enter();
    let budget =
        crate::owned_decode::require_current_child_budget().map_err(owned_storage::admission)?;
    let _scope = budget.enter();
    let result = copy()?;
    owned_storage::check()?;
    Ok(result)
}

impl HostAssertionLifecycle {
    /// Copies this lifecycle under a separately retained original resource account.
    ///
    /// # Errors
    /// Refuses missing or exhausted original metadata before copying the identifier.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        copy_under_origin(&self._decode_custody, || {
            Ok(Self {
                assertion: owned_storage::copy_assertion_id(&self.assertion)?,
                state: self.state,
                _decode_custody: crate::owned_decode::require_current_custody()
                    .map_err(owned_storage::admission)?,
            })
        })
    }
}

impl HostAssertionOutcome {
    fn copy_fields(&self) -> Result<Self, EngineError> {
        Ok(Self {
            assertion: owned_storage::copy_assertion_id(&self.assertion)?,
            quantifier: self.quantifier,
            at: self.at,
            kind: self.kind,
            lifecycle: self.lifecycle,
            message: owned_storage::copy_string(&self.message)?,
            reason: owned_storage::copy_string(&self.reason)?,
            evidence: owned_storage::copy_json(&self.evidence)?,
            _decode_custody: crate::owned_decode::require_current_custody()
                .map_err(owned_storage::admission)?,
        })
    }

    /// Copies this outcome under a separately retained original resource account.
    ///
    /// # Errors
    /// Refuses missing or exhausted original metadata before copying owned evidence.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        copy_under_origin(&self._decode_custody, || self.copy_fields())
    }
}

impl HostAssertionViolation {
    fn copy_fields(&self) -> Result<Self, EngineError> {
        Ok(Self {
            assertion: owned_storage::copy_assertion_id(&self.assertion)?,
            message: owned_storage::copy_string(&self.message)?,
            quantifier: self.quantifier,
            event_kind: owned_storage::copy_string(&self.event_kind)?,
            at_icount: self.at_icount,
            at_virtual_time: self.at_virtual_time,
            node: self
                .node
                .as_ref()
                .map(owned_storage::copy_node)
                .transpose()?,
            detail: owned_storage::copy_string(&self.detail)?,
            reproduction_artifact: self.reproduction_artifact,
            _decode_custody: crate::owned_decode::require_current_custody()
                .map_err(owned_storage::admission)?,
        })
    }

    /// Copies this violation under a separately retained original resource account.
    ///
    /// # Errors
    /// Refuses missing or exhausted original metadata before copying owned fields.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        copy_under_origin(&self._decode_custody, || self.copy_fields())
    }
}

impl HostAssertionProximity {
    fn copy_fields(&self) -> Result<Self, EngineError> {
        Ok(Self {
            assertion: owned_storage::copy_assertion_id(&self.assertion)?,
            quantifier: self.quantifier,
            distance: self.distance,
            at: self.at,
            event_log_offset: self.event_log_offset,
            _decode_custody: crate::owned_decode::require_current_custody()
                .map_err(owned_storage::admission)?,
        })
    }

    /// Copies this proximity under a separately retained original resource account.
    ///
    /// # Errors
    /// Refuses missing or exhausted original metadata before copying its identifier.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        copy_under_origin(&self._decode_custody, || self.copy_fields())
    }
}

impl HostAssertionReport {
    /// Copies the complete report under one separately retained original account.
    ///
    /// # Errors
    /// Refuses missing or exhausted original metadata before publishing a partial copy.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        copy_under_origin(&self._decode_custody, || {
            let mut outcomes = Vec::new();
            for outcome in &self.outcomes {
                owned_storage::reserve_slot(&mut outcomes)?;
                outcomes.push(outcome.copy_fields()?);
            }
            let mut violations = Vec::new();
            for violation in &self.violations {
                owned_storage::reserve_slot(&mut violations)?;
                violations.push(violation.copy_fields()?);
            }
            let mut proximities = Vec::new();
            for proximity in &self.proximities {
                owned_storage::reserve_slot(&mut proximities)?;
                proximities.push(proximity.copy_fields()?);
            }
            let mut failures = Vec::new();
            for failure in self.verdict.failures() {
                owned_storage::reserve_slot(&mut failures)?;
                failures.push(AssertionVerdictFailure::new(
                    owned_storage::copy_assertion_id(&failure.assertion)?,
                    failure.at,
                    owned_storage::copy_string(&failure.reason)?,
                ));
            }
            let verdict = match self.verdict {
                AssertionRunVerdict::Passed => AssertionRunVerdict::Passed,
                AssertionRunVerdict::Failed { .. } => AssertionRunVerdict::Failed { failures },
            };
            Ok(Self {
                outcomes,
                violations,
                proximities,
                verdict,
                _decode_custody: crate::owned_decode::require_current_custody()
                    .map_err(owned_storage::admission)?,
            })
        })
    }
}

impl ExternalFormalTraceExport {
    /// Copies exported bytes under a separately retained original account.
    ///
    /// # Errors
    /// Refuses missing or exhausted original metadata before allocating output.
    pub fn try_clone_admitted(&self) -> Result<Self, EngineError> {
        copy_under_origin(&self._decode_custody, || {
            let mut bytes = Vec::new();
            crate::owned_decode::reserve_vec(&mut bytes, self.bytes.len())
                .map_err(owned_storage::admission)?;
            bytes.extend_from_slice(&self.bytes);
            Ok(Self {
                bytes,
                content_hash: self.content_hash,
                entry_count: self.entry_count,
                _decode_custody: crate::owned_decode::require_current_custody()
                    .map_err(owned_storage::admission)?,
            })
        })
    }
}

macro_rules! shared_output {
    ($kind:ty) => {
        impl $kind {
            /// Moves this admitted diagnostic into a shared immutable owner.
            ///
            /// # Errors
            /// Refuses exhausted original metadata before allocating the Arc body.
            pub fn into_shared(self) -> Result<std::sync::Arc<Self>, EngineError> {
                let _original = self._decode_custody.enter();
                owned_storage::reserve_arc::<Self>()?;
                owned_storage::check()?;
                Ok(std::sync::Arc::new(self))
            }
        }
    };
}
shared_output!(HostAssertionReport);
shared_output!(HostAssertionViolation);
