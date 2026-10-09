//! Source-authorized duplicates beneath the original public runtime custody.
//!
//! The optional installation policy selects only its predeclared original
//! controls. A failed probe fences ordinary cached completion while preserving
//! the already adopted native outcome and its complete guarded custody.

use std::rc::Rc;

use crucible_node_contract::{ContentRef, HashRef, Id};
use crucible_node_provider::{
    ProviderError,
    bodies::{MethodResult, ResponseBody},
    envelope::Method,
    reference_device::{DeviceGrant, DeviceStatus},
};

use crate::node_contract::{ActivationRecord, EffectKnowledge, OperationFailure};

use super::control::CnpControlledReference;
use super::process::CnpLaunchGuard;

/// Identifies the original codec-validated adoption preceding a probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CnpCompletedLifecyclePhase {
    /// Records the genuine staged owner-ready receipt.
    Prepared,
    /// Records the complete durable world manifest consumed by this provider.
    WorldActivated,
    /// Records the exact accepted input and authenticated custody closure.
    InputAccepted,
    /// Records the genuine stopped native window and original staged output.
    WindowCompleted,
    /// Records the original committed output and unchanged stop boundary.
    PublicationClosed,
    /// Records the original publication consumption acknowledgement.
    PublicationConsumed,
}

/// Contains immutable original facts for an installed duplicate-control policy.
///
/// This read-only data does not expose a controller or authorize effects. The
/// source policy also authenticates the retained original envelopes, complete
/// codec-declared evidence and actual native process enrollment before each
/// selected transmission.
#[derive(Clone, Debug)]
pub struct CnpCompletedLifecycleScope {
    /// Names the exact validated original adoption.
    pub phase: CnpCompletedLifecyclePhase,
    /// Names the unchanged original controller request.
    pub request_id: Id,
    /// Names the original native operation when the control has one.
    pub operation_id: Option<Id>,
    /// Identifies the original control method without interpreting its authority.
    pub method: Method,
    /// Binds the complete actual node binding, including its original live scope.
    pub binding_hash: HashRef,
    /// Binds the actual complete execution-owner binding.
    pub owner_binding_hash: HashRef,
    /// Retains the original complete proposed or committed world scope.
    pub activation: ActivationRecord,
    /// Retains the original native grant for window-scoped controls.
    pub grant: Option<DeviceGrant>,
    /// Records the actual adapter state after adoption of the original outcome.
    pub native_status: DeviceStatus,
    /// Selects original codec roots whose complete bytes the policy authenticates.
    pub evidence_roots: Vec<ContentRef>,
    /// Retains the genuine original typed result independently of duplicate RPCs.
    pub original_result: MethodResult,
}

/// Authenticates a fixed installed original-control population before resend.
///
/// Implementations belong to the trusted source installation. They retain their
/// immutable fixture and inert observation handle before realization, measure
/// the actual original native enrollment on each selected invocation, and
/// authenticate exact original identities, bodies and codec evidence. Returning
/// `false` excludes an original from that fixed population; it grants no effect
/// or readiness authority.
pub trait CnpCompletedLifecycleQualification {
    /// Selects and authenticates this exact original under its current custody.
    ///
    /// # Errors
    /// Rejects changed source, owner, phase, original identity, body, evidence or
    /// actual native enrollment. Such refusal preserves the original outcome and
    /// fences ordinary completion because that outcome has already occurred.
    fn authenticate(
        &self,
        guard: &CnpLaunchGuard,
        scope: &CnpCompletedLifecycleScope,
    ) -> Result<bool, OperationFailure>;
}

pub(super) struct LifecycleProbeCustody {
    policy: Rc<dyn CnpCompletedLifecycleQualification>,
    pub(super) attempts: Vec<CnpCompletedLifecycleScope>,
    maximum_probes: usize,
    pub(super) current: Option<CnpCompletedLifecycleScope>,
    pub(super) unresolved: bool,
    failure: Option<OperationFailure>,
}

impl LifecycleProbeCustody {
    fn reserve(
        policy: Rc<dyn CnpCompletedLifecycleQualification>,
        maximum_probes: usize,
    ) -> Result<Self, OperationFailure> {
        if maximum_probes == 0 || maximum_probes > 16 {
            return Err(refused(
                "completed lifecycle probe count exceeds the installed ceiling",
            ));
        }
        let mut attempts = Vec::new();
        attempts
            .try_reserve_exact(maximum_probes)
            .map_err(|_| refused("completed lifecycle probe journal could not be reserved"))?;
        Ok(Self {
            policy,
            attempts,
            maximum_probes,
            current: None,
            unresolved: false,
            failure: None,
        })
    }
}

impl CnpLaunchGuard {
    /// Retains a bounded optional source duplicate policy before preparation.
    ///
    /// The same guarded capsule retains its policy and attempted scopes through
    /// runtime transfer, transport uncertainty and supervision. The controller's
    /// separate transmission archive must also be reserved before its controls.
    /// Ordinary launches omit this policy and retain their existing behavior.
    ///
    /// # Errors
    /// Refuses duplicate installation, preparation already begun, transferred
    /// custody, invalid finite limits or failed journal reservation.
    pub fn install_completed_lifecycle_qualification(
        &mut self,
        policy: Rc<dyn CnpCompletedLifecycleQualification>,
        maximum_probes: usize,
    ) -> Result<(), OperationFailure> {
        let custody = self
            .custody
            .as_mut()
            .ok_or_else(|| refused("original guarded native custody is unavailable"))?;
        if custody.preparation_started
            || custody.companion.is_some()
            || custody.runtime.is_some()
            || custody.lifecycle_probes.is_some()
        {
            return Err(refused(
                "completed lifecycle policy must precede original preparation",
            ));
        }
        custody.lifecycle_probes = Some(LifecycleProbeCustody::reserve(policy, maximum_probes)?);
        Ok(())
    }

    pub(super) fn require_resolved_lifecycle_probes(&self) -> Result<(), ProviderError> {
        if self
            .custody
            .as_ref()
            .and_then(|custody| custody.lifecycle_probes.as_ref())
            .is_some_and(|probes| probes.unresolved)
        {
            return Err(ProviderError::Correlation(
                "original lifecycle probe remains unresolved",
            ));
        }
        Ok(())
    }

    pub(super) fn probe_completed_lifecycle(
        &mut self,
        scope: CnpCompletedLifecycleScope,
    ) -> Result<(), ProviderError> {
        let Some(probes) = self
            .custody
            .as_mut()
            .and_then(|custody| custody.lifecycle_probes.as_mut())
        else {
            return Ok(());
        };
        if !probes.unresolved || probes.current.is_some() {
            return Err(ProviderError::Correlation(
                "original lifecycle attempt was not reserved",
            ));
        }
        let policy = Rc::clone(&probes.policy);
        // Set uncertainty before entering user-owned policy or native transport.
        // An unwind cannot turn the adopted original into a fresh cached success.
        probes.current = Some(scope);
        probes.unresolved = true;
        let scope = self
            .custody
            .as_ref()
            .and_then(|custody| custody.lifecycle_probes.as_ref())
            .and_then(|probes| probes.current.as_ref())
            .ok_or(ProviderError::Correlation(
                "original lifecycle scope was lost",
            ))?;
        let selected = match policy.authenticate(self, scope) {
            Ok(selected) => selected,
            Err(error) => {
                self.probes_mut()?.failure = Some(error);
                return Err(ProviderError::Correlation(
                    "original lifecycle source policy refused",
                ));
            }
        };
        if !selected {
            let probes = self.probes_mut()?;
            probes.current = None;
            probes.unresolved = false;
            return Ok(());
        }
        if self.probes()?.attempts.len() >= self.probes()?.maximum_probes {
            return Err(ProviderError::ResourceExhausted(
                "original lifecycle probe journal is full",
            ));
        }
        let request_id = self
            .probes()?
            .current
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "original lifecycle request was lost",
            ))?
            .request_id
            .clone();
        let response: ResponseBody = self
            .custody
            .as_mut()
            .and_then(|custody| custody.controller.as_mut())
            .ok_or(ProviderError::Correlation(
                "original lifecycle controller was lost",
            ))?
            .resend_completed_lifecycle_original(&request_id)?;
        let probes = self.probes_mut()?;
        let original = probes.current.as_ref().ok_or(ProviderError::Correlation(
            "original lifecycle outcome was lost",
        ))?;
        if response.result.as_ref() != Some(&original.original_result) {
            return Err(ProviderError::Correlation(
                "duplicate lifecycle result changed original",
            ));
        }
        let original = probes.current.take().ok_or(ProviderError::Correlation(
            "original lifecycle journal was lost",
        ))?;
        probes.attempts.push(original);
        probes.unresolved = false;
        Ok(())
    }

    fn probes(&self) -> Result<&LifecycleProbeCustody, ProviderError> {
        self.custody
            .as_ref()
            .and_then(|custody| custody.lifecycle_probes.as_ref())
            .ok_or(ProviderError::Correlation(
                "original lifecycle policy custody was lost",
            ))
    }

    fn probes_mut(&mut self) -> Result<&mut LifecycleProbeCustody, ProviderError> {
        self.custody
            .as_mut()
            .and_then(|custody| custody.lifecycle_probes.as_mut())
            .ok_or(ProviderError::Correlation(
                "original lifecycle policy custody was lost",
            ))
    }
}

fn refused(reason: &str) -> OperationFailure {
    OperationFailure {
        effects: EffectKnowledge::None,
        reason: reason.into(),
    }
}

impl CnpControlledReference {
    pub(super) fn probe_adopted_lifecycle(
        &mut self,
        phase: CnpCompletedLifecyclePhase,
        request_id: Id,
        operation_id: Option<Id>,
        grant: Option<DeviceGrant>,
        evidence_roots: Vec<ContentRef>,
        original_result: MethodResult,
    ) -> Result<(), ProviderError> {
        if self
            .guard
            .custody
            .as_ref()
            .is_none_or(|custody| custody.lifecycle_probes.is_none())
        {
            return Ok(());
        }
        self.guard.require_resolved_lifecycle_probes()?;
        // Even a local encoding refusal after native adoption must prevent the
        // ordinary cached path from replacing this unfinished selected probe.
        self.guard.probes_mut()?.unresolved = true;
        let activation = self
            .prepared
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "original lifecycle world preparation is unavailable",
            ))?
            .record
            .clone();
        let method = match phase {
            CnpCompletedLifecyclePhase::Prepared => Method::Activate,
            CnpCompletedLifecyclePhase::WorldActivated => Method::WorldActivate,
            CnpCompletedLifecyclePhase::InputAccepted => Method::Input,
            CnpCompletedLifecyclePhase::WindowCompleted => Method::Begin,
            CnpCompletedLifecyclePhase::PublicationClosed => Method::QuantumClose,
            CnpCompletedLifecyclePhase::PublicationConsumed => Method::Retire,
        };
        self.guard
            .probe_completed_lifecycle(CnpCompletedLifecycleScope {
                phase,
                request_id,
                operation_id,
                method,
                binding_hash: self.binding.identity()?,
                owner_binding_hash: self.owner_binding.identity()?,
                activation,
                grant,
                native_status: self.status,
                evidence_roots,
                original_result,
            })
    }
}
