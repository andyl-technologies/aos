//! Retains the existing signed Stop authority selected under the paid B turn.
//!
//! Protected publication recovery is structural. Host independently verifies
//! its signed request; selection never creates a new plan, lease or window.

use super::*;
use aos_sandbox_model::RawPairedClockSample;
use crate::publication::CurrentAuthorityPublicationV1;
use crate::runtime_authority::{RuntimeAuthorityBindingV1, RuntimeAuthorityError};

pub(crate) struct RuntimeStopAuthorityOriginalV4 {
    entered: bool,
    repeated: bool,
    binding: Option<Result<Option<RuntimeAuthorityBindingV1>, RuntimeAuthorityError>>,
    publication: Option<Result<Option<CurrentAuthorityPublicationV1>, AuthorityPublicationError>>,
    prepared: Option<Result<PreparedAuthorityEffectV1, ReconcilerError>>,
    refused: ReconcilerError,
}

impl RuntimeStopAuthorityOriginalV4 {
    pub(crate) fn new() -> Self {
        Self {
            entered: false,
            repeated: false,
            binding: None,
            publication: None,
            prepared: None,
            refused: ReconcilerError::InvalidPlan("retained Stop authority is incomplete"),
        }
    }

    // Caller has already admitted the complete shared runtime/publication model
    // quote on this same B/native interval before either protected getter.
    pub(crate) fn prepare_once_v4(
        &mut self,
        journal: &Journal,
        node: NodeId,
        fence: LiveRuntimeFenceV1,
        clock: RawPairedClockSample,
        transport_bound: u64,
    ) -> Result<(), ReconcilerError> {
        if self.entered {
            self.repeated = true;
            return Err(ReconcilerError::InvalidPlan("retained Stop authority was reentered"));
        }
        self.entered = true;
        self.prepared = Some((|| {
            self.binding = Some(crate::runtime_authority::current_readonly_v2(
                journal, RuntimeAuthorityLimits::default(), fence.sandbox()));
            let binding = self.binding.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(Option::as_ref).ok_or(ReconcilerError::InvalidPlan(
                    "retained Stop runtime authority is absent or failed"))?;
            let manifest = binding.manifest().manifest();
            let desired = fence.desired();
            if binding.state() != RuntimeAuthorityStateV1::Bound
                || manifest.node() != node
                || manifest.sandbox() != fence.sandbox()
                || manifest.incarnation() != fence.incarnation()
                || manifest.epoch() != fence.assignment_epoch()
                || manifest.namespace_generation() != fence.namespace_generation()
                || manifest.desired_generation() != desired.expected_generation()
                || binding.assignment_digest().as_bytes() != desired.resource_state().digest().as_bytes()
            {
                return Err(ReconcilerError::InvalidPlan("retained Stop runtime fence changed"));
            }

            self.publication = Some(crate::publication::current_readonly_v2(journal, fence.sandbox()));
            let current = self.publication.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(Option::as_ref).ok_or(ReconcilerError::InvalidPlan(
                    "retained Stop authority publication is absent or failed"))?;
            if current.digest() != binding.publication_digest()
                || current.lease_generation() != binding.lease_generation()
                || current.lease_digest() != binding.lease_digest()
            {
                return Err(ReconcilerError::InvalidPlan("retained Stop authority publication changed"));
            }

            let mut matching = current.templates().iter().filter(|template|
                runtime_template_matches_v4(template, fence, RuntimeAction::RUNTIME_ACTION_STOP));
            let template = matching.next().ok_or(ReconcilerError::InvalidPlan(
                "current publication has no exact signed Stop template"))?;
            if matching.next().is_some() {
                return Err(ReconcilerError::InvalidPlan("current publication has ambiguous Stop templates"));
            }
            if transport_bound <= clock.boottime_nanoseconds() {
                return Err(ReconcilerError::InvalidPlan("retained Stop transport bound expired"));
            }
            let deadline = crate::dispatch::current_host_stop_deadline_data_v4(
                template, current.lease(), clock).map_err(AuthorityPublicationError::DispatchAttempt)?
                .min(transport_bound);
            let (publication, attempt) = crate::publication::select_bound_current_models_v4(
                current.history_data_v2(), current, binding.source_draft_digest(),
                BrokerAudience::Host, template.digest(), None, deadline, clock)?;
            Ok(PreparedAuthorityEffectV1::new(binding.digest(), publication, clock, attempt))
        })());
        if self.completed_v4().is_some() { Ok(()) }
        else { Err(ReconcilerError::InvalidPlan("retained Stop authority selection failed")) }
    }

    pub(crate) fn completed_v4(&self) -> Option<&PreparedAuthorityEffectV1> {
        if self.repeated { return None; }
        self.prepared.as_ref()?.as_ref().ok()
    }

    pub(crate) fn failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = self.binding.as_ref() { return Some(cause); }
        if let Some(Err(cause)) = self.publication.as_ref() { return Some(cause); }
        if let Some(Err(cause)) = self.prepared.as_ref() { return Some(cause); }
        self.repeated.then_some(&self.refused as &(dyn std::error::Error + 'static))
    }
}
