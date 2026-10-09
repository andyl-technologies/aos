//! Retains optional source-authorized hostile bodies beside adopted originals.
//!
//! A changed-body probe is distinct from an unchanged duplicate. Its policy,
//! original scope, proposed body and uncertainty stay inside peer custody. A
//! refusal does not replace the native original or grant replacement progress.

use std::rc::Rc;

use crucible_node_contract::canonical;
use crucible_node_provider::{ProviderError, bodies::ResponseBody};
use serde_json::{Map, Value};

use crate::node_contract::{EffectKnowledge, OperationFailure};

use super::{CnpCompletedLifecycleScope, CnpLaunchGuard};

/// Authenticates a fixed changed-body population against genuine adopted facts.
///
/// Installed source implementations retain their complete fixture before native
/// preparation and authenticate the original envelope, typed evidence closure,
/// current native enrollment and exact hostile body before every transmission.
/// Returning `None` definitively excludes an original from that fixed population.
/// This interface exposes no controller, progress token or acceptance authority.
pub trait CnpOriginalConflictQualification {
    /// Selects one exact hostile body for this original or excludes it.
    ///
    /// # Errors
    /// Refuses changed source, original scope/body, evidence or actual native
    /// enrollment. Error or unwind fences normal completion under original custody.
    fn authenticate(
        &self,
        guard: &CnpLaunchGuard,
        scope: &CnpCompletedLifecycleScope,
    ) -> Result<Option<Map<String, Value>>, OperationFailure>;
}

pub(super) struct ConflictAttempt {
    pub(super) scope: CnpCompletedLifecycleScope,
    pub(super) proposed_body: Option<Map<String, Value>>,
    pub(super) response: Option<ResponseBody>,
}

pub(super) struct ConflictProbeCustody {
    policy: Rc<dyn CnpOriginalConflictQualification>,
    pub(super) attempts: Vec<ConflictAttempt>,
    pub(super) current: Option<ConflictAttempt>,
    pub(super) unresolved: bool,
    maximum_probes: usize,
    maximum_body_bytes: usize,
    body_bytes: Vec<u8>,
    maximum_lifetime_bytes: usize,
    failure: Option<OperationFailure>,
}

impl ConflictProbeCustody {
    fn reserve(
        policy: Rc<dyn CnpOriginalConflictQualification>,
        maximum_probes: usize,
        maximum_body_bytes: usize,
    ) -> Result<Self, OperationFailure> {
        if maximum_probes == 0
            || maximum_probes > 16
            || maximum_body_bytes == 0
            || maximum_body_bytes > 1024 * 1024
        {
            return Err(refused(
                "original conflict ceilings are outside the installed bounds",
            ));
        }
        let maximum_lifetime_bytes = maximum_probes
            .checked_mul(maximum_body_bytes)
            .ok_or_else(|| refused("original conflict lifetime credits overflow"))?;
        let mut attempts = Vec::new();
        attempts
            .try_reserve_exact(maximum_probes)
            .map_err(|_| refused("original conflict attempt reservation failed"))?;
        let mut body_bytes = Vec::new();
        body_bytes
            .try_reserve_exact(maximum_lifetime_bytes)
            .map_err(|_| refused("original conflict body reservation failed"))?;
        Ok(Self {
            policy,
            attempts,
            current: None,
            unresolved: false,
            maximum_probes,
            maximum_body_bytes,
            body_bytes,
            maximum_lifetime_bytes,
            failure: None,
        })
    }
}

impl CnpLaunchGuard {
    /// Retains a distinct finite conflict policy before original preparation.
    ///
    /// Its lifetime journal and body arena are reserved before realization. The
    /// controller's separate conflict recorder must precede all original controls.
    /// Ordinary launches omit this policy and preserve their existing behavior.
    ///
    /// # Errors
    /// Refuses late/repeated installation, transferred custody, invalid ceilings
    /// or failed reservations. Neither installation nor policy grants readiness.
    pub fn install_original_conflict_qualification(
        &mut self,
        policy: Rc<dyn CnpOriginalConflictQualification>,
        maximum_probes: usize,
        maximum_body_bytes: usize,
    ) -> Result<(), OperationFailure> {
        let custody = self
            .custody
            .as_mut()
            .ok_or_else(|| refused("original guarded custody unavailable"))?;
        if custody.preparation_started
            || custody.companion.is_some()
            || custody.runtime.is_some()
            || custody.conflict_probes.is_some()
        {
            return Err(refused("original conflict policy must precede preparation"));
        }
        custody.conflict_probes = Some(ConflictProbeCustody::reserve(
            policy,
            maximum_probes,
            maximum_body_bytes,
        )?);
        Ok(())
    }

    pub(super) fn require_resolved_conflict_probes(&self) -> Result<(), ProviderError> {
        if self
            .custody
            .as_ref()
            .and_then(|custody| custody.conflict_probes.as_ref())
            .is_some_and(|probes| probes.unresolved)
        {
            return Err(ProviderError::Correlation(
                "original conflict probe remains unresolved",
            ));
        }
        Ok(())
    }

    pub(super) fn probe_completed_conflict(
        &mut self,
        scope: CnpCompletedLifecycleScope,
    ) -> Result<(), ProviderError> {
        let Some(probes) = self
            .custody
            .as_mut()
            .and_then(|custody| custody.conflict_probes.as_mut())
        else {
            return Ok(());
        };
        if !probes.unresolved || probes.current.is_some() {
            return Err(ProviderError::Correlation(
                "original conflict attempt was not reserved",
            ));
        }
        let policy = Rc::clone(&probes.policy);
        probes.current = Some(ConflictAttempt {
            scope,
            proposed_body: None,
            response: None,
        });
        let scope = &self
            .conflicts()?
            .current
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "original conflict scope unavailable",
            ))?
            .scope;
        let proposed_body = match policy.authenticate(self, scope) {
            Ok(body) => body,
            Err(error) => {
                self.conflicts_mut()?.failure = Some(error);
                return Err(ProviderError::Correlation(
                    "original conflict source policy refused",
                ));
            }
        };
        let Some(body) = proposed_body else {
            let probes = self.conflicts_mut()?;
            probes.current = None;
            probes.unresolved = false;
            return Ok(());
        };
        // Retain the source proposal before any fallible encoding or SDK call.
        self.conflicts_mut()?
            .current
            .as_mut()
            .ok_or(ProviderError::Correlation(
                "original conflict proposal custody unavailable",
            ))?
            .proposed_body = Some(body);
        let probes = self.conflicts_mut()?;
        if probes.attempts.len() >= probes.maximum_probes {
            return Err(ProviderError::ResourceExhausted(
                "original conflict attempt journal full",
            ));
        }
        let current = probes
            .current
            .as_ref()
            .ok_or(ProviderError::Correlation("original conflict scope lost"))?;
        let body = current
            .proposed_body
            .as_ref()
            .ok_or(ProviderError::Correlation("original conflict body lost"))?;
        let bytes = canonical::canonical_json(&Value::Object(body.clone()))?;
        if bytes.len() > probes.maximum_body_bytes
            || probes
                .body_bytes
                .len()
                .checked_add(bytes.len())
                .is_none_or(|length| length > probes.maximum_lifetime_bytes)
        {
            return Err(ProviderError::ResourceExhausted(
                "original conflict body credits exhausted",
            ));
        }
        probes.body_bytes.extend_from_slice(&bytes);
        let request_id = current.scope.request_id.clone();
        let body = body.clone();
        let returned = self
            .custody
            .as_mut()
            .and_then(|custody| custody.controller.as_mut())
            .ok_or(ProviderError::Correlation(
                "original conflict controller unavailable",
            ))?
            .probe_completed_lifecycle_body_conflict(&request_id, &body)?;
        let probes = self.conflicts_mut()?;
        let mut original = probes
            .current
            .take()
            .ok_or(ProviderError::Correlation("original conflict attempt lost"))?;
        original.response = Some(returned);
        probes.attempts.push(original);
        probes.unresolved = false;
        Ok(())
    }

    fn conflicts(&self) -> Result<&ConflictProbeCustody, ProviderError> {
        self.custody
            .as_ref()
            .and_then(|custody| custody.conflict_probes.as_ref())
            .ok_or(ProviderError::Correlation(
                "original conflict custody unavailable",
            ))
    }

    fn conflicts_mut(&mut self) -> Result<&mut ConflictProbeCustody, ProviderError> {
        self.custody
            .as_mut()
            .and_then(|custody| custody.conflict_probes.as_mut())
            .ok_or(ProviderError::Correlation(
                "original conflict custody unavailable",
            ))
    }
}

fn refused(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}
