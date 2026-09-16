//! Checksummed atomic host fences and request replay state.
//!
//! The on-disk format is a bounded JSON body inside a fixed binary envelope:
//!
//! ```text
//! magic[8] | version:u32-le | body-length:u64-le | sha256[32] | body
//! ```
//!
//! Version 1 records authenticated Guardian-launch, composite-Stop, and direct
//! lifecycle executions.
//! JSON is an internal node-local format, not a portable or wire contract.
//! Unknown fields, checksum failures, overlong bodies, duplicate identities,
//! and invalid pending/completed records fail closed during startup.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::PathBuf;

use aos_sandbox_broker::VerifiedBrokerAdmission;
use aos_sandbox_broker::{BrokerAuthorizationFenceV1, BrokerEffectIntentV1};
use aos_sandbox_core::model::KeyUsage;
use aos_sandbox_core::{BrokerGrantTarget, BrokerVerb};
use aos_sandbox_protocol::ValidatedAssignmentFence;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::authorization::HostAuthorityV1;
use crate::recovery::{
    RetainedEffectDurability, RetainedRuntimeEffect, RetainedRuntimeIntent,
    RetainedRuntimeInventory,
};
use crate::worker::HostRuntimeIdentity;
use crate::{HostError, Result};

pub(crate) mod transition;

pub(crate) use transition::HostAction;
use transition::{DurableExecution, ExecutionContext};

const MAGIC: &[u8; 8] = b"AOSHOST\0";
const VERSION: u32 = 1;
const HEADER_BYTES: usize = 8 + 4 + 8 + 32;
const MAXIMUM_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_REQUESTS: usize = 16_384;
const MAXIMUM_RECEIPT_BYTES: usize = 1024 * 1024;
const MAXIMUM_EXECUTION_AUTHENTICATION_BYTES: usize = 1024;
const STABLE_AUTHORITY_DOMAIN: &[u8] = b"aos.host.execution-stable-authority.v1\0";
const STABLE_AUTHORITY_VERSION: u16 = 1;

/// Reports whether an exact request is new, pending after a crash, or complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Admission {
    /// The fence and pending intent were newly persisted.
    New,
    /// The same request was already durably pending and must be reconciled.
    Pending,
    /// The exact completed request replayed its persisted response bytes.
    Complete(Vec<u8>),
}

/// Reports the immutable status of one exact request identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeEffectQuery {
    /// No durable request uses this request ID.
    Absent,
    /// The exact request is durably pending.
    Pending,
    /// The exact request completed with these byte-exact response bytes.
    Complete(Vec<u8>),
}

/// Identifies the authenticated completed Guardian launch that still owns a live incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CompletedGuardianLineage {
    pub(crate) source_request_id: [u8; 16],
    pub(crate) incarnation_id: [u8; 16],
    pub(crate) binding: [u8; 32],
    pub(crate) guardian_invocation: [u8; 16],
    pub(crate) payload_invocation: [u8; 16],
    pub(crate) worker_proof: transition::RuntimeProofSnapshot,
}

/// Classifies whether durable history authorizes Guardian-backed runtime adoption.
#[allow(
    clippy::large_enum_variant,
    reason = "lineage proof remains stack-owned and copyable across closed broker decisions"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuardianLineage {
    /// No Guardian launch exists for this sandbox incarnation.
    Absent,
    /// Guardian history exists, but a transition or ownership boundary hides it.
    Shadowed,
    /// Exactly one completed Guardian launch owns the current runtime.
    Complete(CompletedGuardianLineage),
}

/// In-memory form of a structurally validated durable host snapshot.
///
/// Broker construction performs a second authenticated validation before it
/// can use any authority-bearing record. An incarnation remains reserved to
/// its sandbox while any current or historical authority record retains it;
/// reuse requires a future explicit authoritative retirement operation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HostState {
    fences: BTreeMap<[u8; 16], DurableFence>,
    requests: BTreeMap<[u8; 16], RequestRecord>,
    observation_sequences: BTreeMap<[u8; 16], u64>,
    scope_replays: BTreeMap<[u8; 32], DurableScopeReplay>,
}

/// Exact Host-authenticated identity of one descriptor-bearing scope replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostScopeReplayBindingV1 {
    pub(crate) method: i32,
    pub(crate) request_id: [u8; 16],
    pub(crate) request_body_digest: [u8; 32],
    pub(crate) signed_request_digest: [u8; 32],
    pub(crate) session_binding: [u8; 32],
    pub(crate) response_body_digest: [u8; 32],
    pub(crate) terminal_verifier_commitment: [u8; 32],
    pub(crate) terminal_reservation_locator: [u8; 32],
    pub(crate) signed_outcome_digest: [u8; 32],
    pub(crate) protected_generation: u64,
    pub(crate) protected_head: [u8; 32],
    pub(crate) artifact_commitment: [u8; 32],
    pub(crate) peer_uid: u32,
    pub(crate) peer_gid: u32,
    pub(crate) peer_pid: u32,
    pub(crate) policy_uid: u32,
    pub(crate) policy_gid: u32,
    pub(crate) policy_audience: i32,
    pub(crate) protocol_major: u16,
    pub(crate) protocol_minor: u16,
    pub(crate) protected_boot_id: [u8; 16],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableScopeReplay {
    locator: [u8; 32],
    method: i32,
    request_id: [u8; 16],
    request_body_digest: [u8; 32],
    signed_request_digest: [u8; 32],
    session_binding: [u8; 32],
    response_body_digest: [u8; 32],
    terminal_verifier_commitment: [u8; 32],
    terminal_reservation_locator: [u8; 32],
    signed_outcome_digest: [u8; 32],
    protected_generation: u64,
    protected_head: [u8; 32],
    artifact_commitment: [u8; 32],
    peer_uid: u32,
    peer_gid: u32,
    peer_pid: u32,
    policy_uid: u32,
    policy_gid: u32,
    policy_audience: i32,
    protocol_major: u16,
    protocol_minor: u16,
    protected_boot_id: [u8; 16],
    authentication: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableFence {
    witness_request_id: [u8; 16],
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
    authorization: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestRecord {
    request_id: [u8; 16],
    request_digest: [u8; 32],
    fence: DurableFence,
    action: u8,
    execution: DurableExecution,
    execution_authentication: Vec<u8>,
    effect: Vec<u8>,
    receipt: Option<Vec<u8>>,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StateWire {
    fences: Vec<DurableFence>,
    requests: Vec<RequestRecord>,
    observation_sequences: Vec<ObservationSequence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scope_replays: Vec<DurableScopeReplay>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservationSequence {
    incarnation_id: [u8; 16],
    sequence: u64,
}

impl HostState {
    /// Authenticates every authority-bearing record and its structural links.
    ///
    /// Every current fence must be retained byte-exactly by at least one
    /// authenticated request. Deleting an arbitrary older request cannot be
    /// detected without a separately authenticated set root, but after a
    /// newer fence exists replay of that older Apply is stale and rejected.
    pub(crate) fn validate_authenticated(&self, authority: &HostAuthorityV1) -> Result<()> {
        self.validate_unique_retained_incarnations()?;
        self.validate_execution_links()?;

        for (sandbox_id, durable) in &self.fences {
            let opened = authority.open_fence(sandbox_id, &durable.authorization)?;
            validate_opened_fence(durable, &opened)?;
        }

        let mut pending_sandboxes = BTreeSet::new();
        for (request_id, request) in &self.requests {
            if request.request_id != *request_id || request.fence.witness_request_id != *request_id
            {
                return Err(HostError::State(
                    "request index and fence witness disagree".to_owned(),
                ));
            }
            let effect = authority.open_effect(request_id, &request.effect)?;
            if effect.request_id() != request_id
                || effect.transport_request_digest().as_bytes() != &request.request_digest
                || action_verb(request.action) != Some(effect.verb())
            {
                return Err(HostError::State(
                    "authenticated host effect contradicts its request record".to_owned(),
                ));
            }
            match (effect.status(), request.receipt.as_deref()) {
                (aos_sandbox_broker::BrokerEffectStatusV1::Pending, None) => {}
                (aos_sandbox_broker::BrokerEffectStatusV1::Complete, Some(receipt))
                    if receipt == effect.receipt() => {}
                _ => {
                    return Err(HostError::State(
                        "authenticated host effect status contradicts its receipt".to_owned(),
                    ));
                }
            }

            let embedded =
                authority.open_fence(&request.fence.sandbox_id, &request.fence.authorization)?;
            validate_opened_fence(&request.fence, &embedded)?;
            if embedded.plan_digest() != effect.plan_digest()
                || embedded.plan_expires_seconds() != effect.plan_expires_seconds()
                || embedded.local_lease_record() != effect.local_lease_record()
                || effect.local_lease_record().lease_digest() != effect.lease_digest()
            {
                return Err(HostError::State(
                    "request fence and effect name different authorization state".to_owned(),
                ));
            }
            let stable_authority_digest = stable_authority_digest(&effect, &embedded)?;
            validate_execution_authentication(authority, request, stable_authority_digest)?;
            let current = self.fences.get(&request.fence.sandbox_id).ok_or_else(|| {
                HostError::State("request has no current sandbox fence".to_owned())
            })?;
            request.fence.validate_successor(current)?;

            if effect.status() == aos_sandbox_broker::BrokerEffectStatusV1::Pending
                && (!pending_sandboxes.insert(request.fence.sandbox_id)
                    || request.fence != *current)
            {
                return Err(HostError::State(
                    "pending request is not the unique current sandbox transition".to_owned(),
                ));
            }
        }
        if self.fences.values().any(|current| {
            self.requests
                .get(&current.witness_request_id)
                .is_none_or(|request| request.fence != *current)
        }) {
            return Err(HostError::State(
                "current sandbox fence has no retaining request".to_owned(),
            ));
        }
        for request in self.requests.values() {
            ensure_live_execution_enabled(&request.execution)?;
        }
        for (locator, replay) in &self.scope_replays {
            if replay.locator != *locator {
                return Err(HostError::State(
                    "Host scope replay index contradicts its record".to_owned(),
                ));
            }
            let binding = replay.binding();
            let payload = encode_scope_replay_binding(&binding);
            if scope_replay_locator(&payload) != *locator
                || authority
                    .terminal_verifier_commitment()
                    .map_err(|error| HostError::State(error.to_string()))?
                    != binding.terminal_verifier_commitment
                || authority.open_execution_record(&binding.request_id, &replay.authentication)?
                    != payload
            {
                return Err(HostError::State(
                    "Host scope replay authentication is invalid".to_owned(),
                ));
            }
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "direct lifecycle admission commits one authenticated request atomically"
    )]
    pub(crate) fn admit(
        &mut self,
        fence: &ValidatedAssignmentFence,
        request_id: [u8; 16],
        request_digest: [u8; 32],
        action: u8,
        sealed_fence: Vec<u8>,
        admitted: &VerifiedBrokerAdmission,
        sealed_effect: Vec<u8>,
        authority: &HostAuthorityV1,
    ) -> Result<Admission> {
        if sealed_fence.is_empty()
            || sealed_effect.is_empty()
            || sealed_fence.len() > MAXIMUM_STATE_BYTES
            || sealed_effect.len() > MAXIMUM_STATE_BYTES
        {
            return Err(HostError::State(
                "sealed host authorization record is empty or oversized".to_owned(),
            ));
        }
        self.ensure_incarnation_available(fence.sandbox_id(), fence.incarnation_id())?;
        if let Some(record) = self.requests.get_mut(&request_id) {
            if record.request_digest != request_digest || record.action != action {
                return Err(HostError::Fence(
                    "request ID was reused with different bytes",
                ));
            }
            let result = match &record.receipt {
                Some(receipt) => Admission::Complete(receipt.clone()),
                None => Admission::Pending,
            };
            if matches!(result, Admission::Pending) {
                record.effect = sealed_effect;
                record.fence.authorization = sealed_fence.clone();
                let durable_fence = self.fences.get_mut(fence.sandbox_id()).ok_or_else(|| {
                    HostError::State("request fence disappeared from host state".to_owned())
                })?;
                durable_fence.authorization = sealed_fence;
            }
            return Ok(result);
        }

        let host_action = HostAction::from_code(action)
            .ok_or_else(|| HostError::State("durable host action is invalid".to_owned()))?;
        let execution = DurableExecution::direct_lifecycle(host_action).ok_or_else(|| {
            HostError::State("direct lifecycle execution has an invalid action".to_owned())
        })?;
        if self.requests.len() >= MAXIMUM_REQUESTS {
            return Err(HostError::State(
                "durable host request table reached its fixed bound".to_owned(),
            ));
        }
        if self.requests.values().any(|request| {
            request.receipt.is_none() && request.fence.sandbox_id == *fence.sandbox_id()
        }) {
            return Err(HostError::Fence(
                "sandbox already has a different pending host transition",
            ));
        }

        let proposed = DurableFence::from_validated(fence, request_id, sealed_fence);
        if let Some(current) = self.fences.get(fence.sandbox_id()) {
            current.validate_successor(&proposed)?;
        }
        let context = execution_context_from_parts(
            host_action,
            request_id,
            request_digest,
            *fence.sandbox_id(),
            *fence.incarnation_id(),
            fence.assignment_epoch(),
            fence.desired_generation(),
            *fence.assignment_digest(),
            false,
        );
        let stable = stable_authority_digest(&admitted.effect, &admitted.fence)?;
        let digest = execution
            .authentication_digest(context, stable)
            .ok_or_else(|| {
                HostError::State("lifecycle authentication input is too large".to_owned())
            })?;
        let execution_authentication = authority.seal_execution_record(&request_id, &digest)?;
        self.fences.insert(*fence.sandbox_id(), proposed.clone());
        self.requests.insert(
            request_id,
            RequestRecord {
                request_id,
                request_digest,
                fence: proposed,
                action,
                execution,
                execution_authentication,
                effect: sealed_effect,
                receipt: None,
            },
        );
        Ok(Admission::New)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Guardian admission commits one complete authenticated request atomically"
    )]
    pub(crate) fn admit_guardian(
        &mut self,
        fence: &ValidatedAssignmentFence,
        request_id: [u8; 16],
        request_digest: [u8; 32],
        execution: DurableExecution,
        sealed_fence: Vec<u8>,
        admitted: &VerifiedBrokerAdmission,
        sealed_effect: Vec<u8>,
        authority: &HostAuthorityV1,
    ) -> Result<Admission> {
        if self.requests.contains_key(&request_id) {
            return self.admit(
                fence,
                request_id,
                request_digest,
                HostAction::Launch.code(),
                sealed_fence,
                admitted,
                sealed_effect,
                authority,
            );
        }
        if sealed_fence.is_empty()
            || sealed_effect.is_empty()
            || sealed_fence.len() > MAXIMUM_STATE_BYTES
            || sealed_effect.len() > MAXIMUM_STATE_BYTES
        {
            return Err(HostError::State(
                "sealed host authorization record is empty or oversized".to_owned(),
            ));
        }
        self.ensure_incarnation_available(fence.sandbox_id(), fence.incarnation_id())?;
        if self.requests.len() >= MAXIMUM_REQUESTS {
            return Err(HostError::State(
                "durable host request table reached its fixed bound".to_owned(),
            ));
        }
        if self.requests.values().any(|request| {
            request.receipt.is_none() && request.fence.sandbox_id == *fence.sandbox_id()
        }) {
            return Err(HostError::Fence(
                "sandbox already has a different pending host transition",
            ));
        }

        let context = execution_context_from_parts(
            HostAction::Launch,
            request_id,
            request_digest,
            *fence.sandbox_id(),
            *fence.incarnation_id(),
            fence.assignment_epoch(),
            fence.desired_generation(),
            *fence.assignment_digest(),
            false,
        );
        if !execution.validate(context) {
            return Err(HostError::State(
                "Guardian execution contradicts its request".to_owned(),
            ));
        }
        let stable = stable_authority_digest(&admitted.effect, &admitted.fence)?;
        let digest = execution
            .authentication_digest(context, stable)
            .ok_or_else(|| {
                HostError::State("Guardian authentication input is too large".to_owned())
            })?;
        let execution_authentication = authority.seal_execution_record(&request_id, &digest)?;

        let proposed = DurableFence::from_validated(fence, request_id, sealed_fence);
        if let Some(current) = self.fences.get(fence.sandbox_id()) {
            current.validate_successor(&proposed)?;
        }
        self.fences.insert(*fence.sandbox_id(), proposed.clone());
        self.requests.insert(
            request_id,
            RequestRecord {
                request_id,
                request_digest,
                fence: proposed,
                action: HostAction::Launch.code(),
                execution,
                execution_authentication,
                effect: sealed_effect,
                receipt: None,
            },
        );
        Ok(Admission::New)
    }

    pub(crate) fn guardian_attempt(
        &self,
        request_id: &[u8; 16],
    ) -> Option<transition::GuardianAttempt<'_>> {
        self.requests.get(request_id)?.execution.guardian_attempt()
    }

    pub(crate) fn guardian_execution(&self, request_id: &[u8; 16]) -> Option<DurableExecution> {
        let execution = &self.requests.get(request_id)?.execution;
        execution.guardian_attempt()?;
        Some(execution.clone())
    }

    pub(crate) fn current_execution(
        &self,
        sandbox_id: &[u8; 16],
    ) -> Option<([u8; 16], HostAction, [u8; 16], DurableExecution)> {
        let fence = self.fences.get(sandbox_id)?;
        let request = self.requests.get(&fence.witness_request_id)?;
        Some((
            request.request_id,
            HostAction::from_code(request.action)?,
            request.fence.incarnation_id,
            request.execution.clone(),
        ))
    }

    /// Classifies the Guardian launch lineage underlying the current live runtime.
    ///
    /// Completed Freeze and Thaw requests may replace the current fence witness
    /// without replacing the live runtime when they remain in the launch's
    /// assignment epoch. Pending transitions, terminal Stop or Kill history, an
    /// ownership-epoch or incarnation replacement, and incomplete launches all
    /// shadow historical launch authority. The full snapshot is authenticated
    /// before any historical execution is classified.
    pub(crate) fn completed_guardian_lineage(
        &self,
        sandbox_id: &[u8; 16],
        incarnation_id: &[u8; 16],
        authority: &HostAuthorityV1,
    ) -> Result<GuardianLineage> {
        self.validate_authenticated(authority)?;

        let same_incarnation = |request: &&RequestRecord| {
            request.fence.sandbox_id == *sandbox_id
                && request.fence.incarnation_id == *incarnation_id
        };
        let guardian_history = self
            .requests
            .values()
            .filter(same_incarnation)
            .filter(|request| request.execution.guardian_attempt().is_some())
            .collect::<Vec<_>>();
        if guardian_history.is_empty() {
            return Ok(GuardianLineage::Absent);
        }

        let Some(current_fence) = self.fences.get(sandbox_id) else {
            return Ok(GuardianLineage::Shadowed);
        };
        if current_fence.incarnation_id != *incarnation_id {
            return Ok(GuardianLineage::Shadowed);
        }
        let current = self
            .requests
            .get(&current_fence.witness_request_id)
            .ok_or_else(|| {
                HostError::State("current lineage lost its witness request".to_owned())
            })?;
        let current_action = HostAction::from_code(current.action)
            .ok_or_else(|| HostError::State("current lineage has an invalid action".to_owned()))?;
        if current.receipt.is_none() {
            return Ok(GuardianLineage::Shadowed);
        }
        match current_action {
            HostAction::Launch if current.execution.guardian_completed_invocations().is_none() => {
                return Ok(GuardianLineage::Shadowed);
            }
            HostAction::Stop | HostAction::Kill => return Ok(GuardianLineage::Shadowed),
            HostAction::Launch | HostAction::Freeze | HostAction::Thaw => {}
        }

        if self
            .requests
            .values()
            .filter(same_incarnation)
            .any(|request| {
                request.receipt.is_some()
                    && matches!(
                        HostAction::from_code(request.action),
                        Some(HostAction::Stop | HostAction::Kill)
                    )
            })
        {
            return Ok(GuardianLineage::Shadowed);
        }

        let mut lineage = None;
        for request in guardian_history {
            if request.fence.assignment_epoch != current_fence.assignment_epoch {
                continue;
            }
            let attempt = request.execution.guardian_attempt().ok_or_else(|| {
                HostError::State("Guardian lineage classification lost its attempt".to_owned())
            })?;
            let transition::GuardianLaunchPhase::Complete {
                guardian_invocation,
                payload_invocation,
                worker_proof,
                ..
            } = attempt.phase
            else {
                return Ok(GuardianLineage::Shadowed);
            };
            let candidate = CompletedGuardianLineage {
                source_request_id: request.request_id,
                incarnation_id: request.fence.incarnation_id,
                binding: attempt.binding,
                guardian_invocation: *guardian_invocation,
                payload_invocation: *payload_invocation,
                worker_proof: *worker_proof,
            };
            if lineage.replace(candidate).is_some() {
                return Err(HostError::State(
                    "current runtime has ambiguous completed Guardian launch lineage".to_owned(),
                ));
            }
        }
        Ok(lineage.map_or(GuardianLineage::Shadowed, GuardianLineage::Complete))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "composite Stop admission commits one complete authenticated request atomically"
    )]
    pub(crate) fn admit_composite_stop(
        &mut self,
        fence: &ValidatedAssignmentFence,
        request_id: [u8; 16],
        request_digest: [u8; 32],
        execution: DurableExecution,
        sealed_fence: Vec<u8>,
        admitted: &VerifiedBrokerAdmission,
        sealed_effect: Vec<u8>,
        authority: &HostAuthorityV1,
    ) -> Result<Admission> {
        if self.requests.contains_key(&request_id) {
            return self.admit(
                fence,
                request_id,
                request_digest,
                HostAction::Stop.code(),
                sealed_fence,
                admitted,
                sealed_effect,
                authority,
            );
        }
        if sealed_fence.is_empty()
            || sealed_effect.is_empty()
            || sealed_fence.len() > MAXIMUM_STATE_BYTES
            || sealed_effect.len() > MAXIMUM_STATE_BYTES
        {
            return Err(HostError::State(
                "sealed host authorization record is empty or oversized".to_owned(),
            ));
        }
        self.ensure_incarnation_available(fence.sandbox_id(), fence.incarnation_id())?;
        if self.requests.len() >= MAXIMUM_REQUESTS {
            return Err(HostError::State(
                "durable host request table reached its fixed bound".to_owned(),
            ));
        }
        if self.requests.values().any(|request| {
            request.receipt.is_none() && request.fence.sandbox_id == *fence.sandbox_id()
        }) {
            return Err(HostError::Fence(
                "sandbox already has a different pending host transition",
            ));
        }

        let context = execution_context_from_parts(
            HostAction::Stop,
            request_id,
            request_digest,
            *fence.sandbox_id(),
            *fence.incarnation_id(),
            fence.assignment_epoch(),
            fence.desired_generation(),
            *fence.assignment_digest(),
            false,
        );
        if !execution.validate(context) {
            return Err(HostError::State(
                "composite Stop execution contradicts its request".to_owned(),
            ));
        }
        let stable = stable_authority_digest(&admitted.effect, &admitted.fence)?;
        let digest = execution
            .authentication_digest(context, stable)
            .ok_or_else(|| {
                HostError::State("composite Stop authentication input is too large".to_owned())
            })?;
        let execution_authentication = authority.seal_execution_record(&request_id, &digest)?;

        let proposed = DurableFence::from_validated(fence, request_id, sealed_fence);
        if let Some(current) = self.fences.get(fence.sandbox_id()) {
            current.validate_successor(&proposed)?;
        }
        self.fences.insert(*fence.sandbox_id(), proposed.clone());
        self.requests.insert(
            request_id,
            RequestRecord {
                request_id,
                request_digest,
                fence: proposed,
                action: HostAction::Stop.code(),
                execution,
                execution_authentication,
                effect: sealed_effect,
                receipt: None,
            },
        );
        Ok(Admission::New)
    }

    pub(crate) fn set_guardian_phase(
        &mut self,
        request_id: &[u8; 16],
        phase: transition::GuardianLaunchPhase,
        authority: &HostAuthorityV1,
    ) -> Result<()> {
        let request = self
            .requests
            .get(request_id)
            .ok_or_else(|| HostError::State("Guardian phase update lost its request".to_owned()))?;
        let effect = authority.open_effect(request_id, &request.effect)?;
        let fence =
            authority.open_fence(&request.fence.sandbox_id, &request.fence.authorization)?;
        let stable = stable_authority_digest(&effect, &fence)?;

        let mut execution = request.execution.clone();
        if !execution.set_guardian_phase(phase) {
            return Err(HostError::State("invalid Guardian phase update".to_owned()));
        }
        let digest = execution
            .authentication_digest(execution_context(request)?, stable)
            .ok_or_else(|| {
                HostError::State("Guardian authentication input is too large".to_owned())
            })?;
        let authentication = authority.seal_execution_record(request_id, &digest)?;

        let request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| HostError::State("Guardian phase update lost its request".to_owned()))?;
        request.execution = execution;
        request.execution_authentication = authentication;
        Ok(())
    }

    pub(crate) fn set_composite_stop_phase(
        &mut self,
        request_id: &[u8; 16],
        phase: transition::CompositeStopPhase,
        authority: &HostAuthorityV1,
    ) -> Result<()> {
        let request = self.requests.get(request_id).ok_or_else(|| {
            HostError::State("composite Stop phase update lost its request".to_owned())
        })?;
        let effect = authority.open_effect(request_id, &request.effect)?;
        let fence =
            authority.open_fence(&request.fence.sandbox_id, &request.fence.authorization)?;
        let stable = stable_authority_digest(&effect, &fence)?;

        let mut execution = request.execution.clone();
        if !execution.set_composite_stop_phase(phase) {
            return Err(HostError::State(
                "invalid composite Stop phase update".to_owned(),
            ));
        }
        let digest = execution
            .authentication_digest(execution_context(request)?, stable)
            .ok_or_else(|| {
                HostError::State("composite Stop authentication input is too large".to_owned())
            })?;
        let authentication = authority.seal_execution_record(request_id, &digest)?;

        let request = self.requests.get_mut(request_id).ok_or_else(|| {
            HostError::State("composite Stop phase update lost its request".to_owned())
        })?;
        request.execution = execution;
        request.execution_authentication = authentication;
        Ok(())
    }

    pub(crate) fn composite_stop_execution(
        &self,
        request_id: &[u8; 16],
    ) -> Option<transition::CompositeStopRecord> {
        self.requests
            .get(request_id)?
            .execution
            .composite_stop_record()
            .cloned()
    }

    fn ensure_incarnation_available(
        &self,
        sandbox_id: &[u8; 16],
        incarnation_id: &[u8; 16],
    ) -> Result<()> {
        // A superseded incarnation can still name a residual systemd unit.
        // Historical authority therefore reserves the flat unit namespace
        // until an explicit retirement mechanism removes that authority.
        let current_collision = self.fences.values().any(|retained| {
            &retained.sandbox_id != sandbox_id && &retained.incarnation_id == incarnation_id
        });
        let historical_collision = self.requests.values().any(|retained| {
            &retained.fence.sandbox_id != sandbox_id
                && &retained.fence.incarnation_id == incarnation_id
        });
        if current_collision || historical_collision {
            return Err(HostError::Fence(
                "runtime incarnation is already retained by another sandbox",
            ));
        }
        Ok(())
    }

    fn validate_unique_retained_incarnations(&self) -> Result<()> {
        let mut incarnations = BTreeMap::new();
        for fence in self
            .fences
            .values()
            .chain(self.requests.values().map(|request| &request.fence))
        {
            if incarnations
                .insert(fence.incarnation_id, fence.sandbox_id)
                .is_some_and(|sandbox_id| sandbox_id != fence.sandbox_id)
            {
                return Err(HostError::State(
                    "distinct sandboxes retain the same current or historical runtime incarnation"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn validate_execution_links(&self) -> Result<()> {
        for request in self.requests.values() {
            let Some(source) = request.execution.stop_source() else {
                continue;
            };
            let launch = self.requests.get(&source.request_id).ok_or_else(|| {
                HostError::State("composite Stop lost its retained launch source".to_owned())
            })?;
            if launch.action != 1
                || launch.fence.sandbox_id != request.fence.sandbox_id
                || launch.fence.incarnation_id != source.incarnation_id
                || request.fence.incarnation_id != source.incarnation_id
                || launch.fence.assignment_epoch != request.fence.assignment_epoch
            {
                return Err(HostError::State(
                    "composite Stop source contradicts its retained assignment".to_owned(),
                ));
            }
            match source.guardian_binding {
                Some(binding) if launch.execution.guardian_binding() == Some(binding) => {
                    let Some((guardian_invocation, payload_invocation)) =
                        launch.execution.guardian_completed_invocations()
                    else {
                        return Err(HostError::State(
                            "composite Stop source Guardian launch is not complete".to_owned(),
                        ));
                    };
                    let Some(stop) = request.execution.composite_stop_record() else {
                        return Err(HostError::State(
                            "composite Stop lost its durable execution record".to_owned(),
                        ));
                    };
                    let transition::CompositeStopTarget::GuardianComposite {
                        payload,
                        guardian,
                        ..
                    } = &stop.target
                    else {
                        return Err(HostError::State(
                            "composite Stop source has the wrong Guardian target".to_owned(),
                        ));
                    };
                    if payload.exact_identity() != Some((Some(binding), payload_invocation))
                        || guardian.exact_identity() != Some((Some(binding), guardian_invocation))
                    {
                        return Err(HostError::State(
                            "composite Stop target contradicts its completed Guardian launch"
                                .to_owned(),
                        ));
                    }
                }
                Some(_) | None => {
                    return Err(HostError::State(
                        "composite Stop source has the wrong launch execution kind".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn complete(
        &mut self,
        request_id: [u8; 16],
        request_digest: [u8; 32],
        sealed_effect: Vec<u8>,
        receipt: Vec<u8>,
    ) -> Result<()> {
        if receipt.is_empty() || receipt.len() > MAXIMUM_RECEIPT_BYTES {
            return Err(HostError::State(
                "host replay receipt is empty or exceeds one MiB".to_owned(),
            ));
        }
        let record = self.requests.get_mut(&request_id).ok_or(HostError::State(
            "pending host request disappeared".to_owned(),
        ))?;
        if record.request_digest != request_digest {
            return Err(HostError::Fence(
                "completion digest differs from pending request",
            ));
        }
        if sealed_effect.is_empty() || sealed_effect.len() > MAXIMUM_STATE_BYTES {
            return Err(HostError::State(
                "sealed completed host effect is empty or oversized".to_owned(),
            ));
        }
        if let Some(existing) = &record.receipt {
            return if existing == &receipt {
                Ok(())
            } else {
                Err(HostError::Fence(
                    "completed request produced conflicting response bytes",
                ))
            };
        }
        record.effect = sealed_effect;
        record.receipt = Some(receipt);
        Ok(())
    }

    pub(crate) fn prior_authorization(&self, sandbox_id: &[u8; 16]) -> Option<&[u8]> {
        self.fences
            .get(sandbox_id)
            .map(|fence| fence.authorization.as_slice())
    }

    pub(crate) fn request_authorization(&self, request_id: &[u8; 16]) -> Option<&[u8]> {
        self.requests
            .get(request_id)
            .map(|request| request.fence.authorization.as_slice())
    }

    pub(crate) fn effect(&self, request_id: &[u8; 16]) -> Option<&[u8]> {
        self.requests
            .get(request_id)
            .map(|request| request.effect.as_slice())
    }

    pub(crate) fn query_effect(
        &self,
        request_id: &[u8; 16],
        request_digest: [u8; 32],
    ) -> Result<RuntimeEffectQuery> {
        let Some(record) = self.requests.get(request_id) else {
            return Ok(RuntimeEffectQuery::Absent);
        };
        if record.request_digest != request_digest {
            return Err(HostError::Fence(
                "request ID was reused with different bytes",
            ));
        }
        Ok(match &record.receipt {
            Some(receipt) => RuntimeEffectQuery::Complete(receipt.clone()),
            None => RuntimeEffectQuery::Pending,
        })
    }

    pub(crate) fn contains_runtime(&self, identity: &HostRuntimeIdentity) -> bool {
        self.fences
            .get(identity.sandbox_id())
            .is_some_and(|fence| fence.runtime_identity() == *identity)
    }

    pub(crate) fn runtime_inventory(&self) -> Vec<HostRuntimeIdentity> {
        self.fences
            .values()
            .map(DurableFence::runtime_identity)
            .collect()
    }

    pub(crate) fn runtime_recovery_inventory(&self) -> Result<RetainedRuntimeInventory> {
        let mut current = Vec::new();
        let mut historical = Vec::new();
        current
            .try_reserve_exact(self.fences.len())
            .map_err(|_| HostError::State("cannot reserve current runtime inventory".to_owned()))?;
        historical
            .try_reserve_exact(self.requests.len())
            .map_err(|_| HostError::State("cannot reserve runtime history".to_owned()))?;

        for fence in self.fences.values() {
            let request = self
                .requests
                .get(&fence.witness_request_id)
                .ok_or_else(|| {
                    HostError::State("current sandbox fence lost its witness request".to_owned())
                })?;
            current.push(retained_effect(request)?);
        }
        for request in self.requests.values() {
            let current_fence = self.fences.get(&request.fence.sandbox_id).ok_or_else(|| {
                HostError::State("historical request lost its current sandbox fence".to_owned())
            })?;
            if request.fence.incarnation_id != current_fence.incarnation_id {
                historical.push(retained_effect(request)?);
            }
        }
        current.sort_unstable_by_key(|effect| *effect.identity.incarnation_id());
        historical.sort_unstable();
        Ok(RetainedRuntimeInventory {
            current,
            historical,
        })
    }

    #[cfg(test)]
    pub(crate) fn corrupt_effect(&mut self, request_id: &[u8; 16]) {
        if let Some(byte) = self
            .requests
            .get_mut(request_id)
            .and_then(|request| request.effect.first_mut())
        {
            *byte ^= 1;
        }
    }

    #[cfg(test)]
    pub(crate) fn swap_effects(&mut self, left: &[u8; 16], right: &[u8; 16]) {
        let Some(mut left_record) = self.requests.remove(left) else {
            return;
        };
        let Some(right_record) = self.requests.get_mut(right) else {
            self.requests.insert(*left, left_record);
            return;
        };
        std::mem::swap(&mut left_record.effect, &mut right_record.effect);
        self.requests.insert(*left, left_record);
    }

    #[cfg(test)]
    pub(crate) fn remove_request(&mut self, request_id: &[u8; 16]) {
        self.requests.remove(request_id);
    }

    #[cfg(test)]
    pub(crate) fn tamper_execution_to_guardian(&mut self, request_id: &[u8; 16]) {
        if let Some(request) = self.requests.get_mut(request_id) {
            request.execution = DurableExecution::guardian_fixture(ExecutionContext {
                action: HostAction::Launch,
                request_id: request.request_id,
                request_digest: request.request_digest,
                sandbox_id: request.fence.sandbox_id,
                incarnation_id: request.fence.incarnation_id,
                assignment_epoch: request.fence.assignment_epoch,
                desired_generation: request.fence.desired_generation,
                assignment_digest: request.fence.assignment_digest,
                receipt_present: request.receipt.is_some(),
            });
        }
    }

    #[cfg(test)]
    pub(crate) fn corrupt_receipt(&mut self, request_id: &[u8; 16]) {
        if let Some(byte) = self
            .requests
            .get_mut(request_id)
            .and_then(|request| request.receipt.as_mut())
            .and_then(|receipt| receipt.first_mut())
        {
            *byte ^= 1;
        }
    }

    #[cfg(test)]
    pub(crate) fn swap_receipts(&mut self, left: &[u8; 16], right: &[u8; 16]) {
        let Some(mut left_record) = self.requests.remove(left) else {
            return;
        };
        let Some(right_record) = self.requests.get_mut(right) else {
            self.requests.insert(*left, left_record);
            return;
        };
        std::mem::swap(&mut left_record.receipt, &mut right_record.receipt);
        self.requests.insert(*left, left_record);
    }

    #[cfg(test)]
    pub(crate) fn corrupt_fence(&mut self, sandbox_id: &[u8; 16]) {
        if let Some(byte) = self
            .fences
            .get_mut(sandbox_id)
            .and_then(|fence| fence.authorization.first_mut())
        {
            *byte ^= 1;
        }
    }

    #[cfg(test)]
    pub(crate) fn remove_fence(&mut self, sandbox_id: &[u8; 16]) {
        self.fences.remove(sandbox_id);
    }

    #[cfg(test)]
    pub(crate) fn merge_retained_authority_for_test(&mut self, other: &Self) {
        self.fences.extend(
            other
                .fences
                .iter()
                .map(|(key, value)| (*key, value.clone())),
        );
        self.requests.extend(
            other
                .requests
                .iter()
                .map(|(key, value)| (*key, value.clone())),
        );
    }

    #[cfg(test)]
    pub(crate) fn swap_fences(&mut self, left: &[u8; 16], right: &[u8; 16]) {
        let Some(mut left_fence) = self.fences.remove(left) else {
            return;
        };
        let Some(right_fence) = self.fences.get_mut(right) else {
            self.fences.insert(*left, left_fence);
            return;
        };
        std::mem::swap(
            &mut left_fence.authorization,
            &mut right_fence.authorization,
        );
        self.fences.insert(*left, left_fence);
    }

    pub(crate) fn next_observation_sequence(&mut self, incarnation: [u8; 16]) -> Result<u64> {
        let sequence = self.observation_sequences.entry(incarnation).or_default();
        *sequence = sequence
            .checked_add(1)
            .ok_or_else(|| HostError::State("observation sequence overflow".to_owned()))?;
        Ok(*sequence)
    }

    pub(crate) fn retain_scope_replay(
        &mut self,
        binding: HostScopeReplayBindingV1,
        authority: &HostAuthorityV1,
    ) -> Result<[u8; 32]> {
        if authority
            .terminal_verifier_commitment()
            .map_err(|error| HostError::State(error.to_string()))?
            != binding.terminal_verifier_commitment
        {
            return Err(HostError::State(
                "Host scope replay verifier does not match fixed authority".to_owned(),
            ));
        }
        let payload = encode_scope_replay_binding(&binding);
        let locator = scope_replay_locator(&payload);
        let authentication = authority.seal_execution_record(&binding.request_id, &payload)?;
        let replay = DurableScopeReplay::new(locator, binding, authentication);

        if let Some(current) = self.scope_replays.get(&locator) {
            if current != &replay {
                return Err(HostError::State(
                    "Host scope replay locator was reused".to_owned(),
                ));
            }
            return Ok(locator);
        }
        if self.scope_replays.len() >= MAXIMUM_REQUESTS {
            return Err(HostError::State(
                "durable Host scope replay table exceeds its fixed bound".to_owned(),
            ));
        }
        self.scope_replays.insert(locator, replay);
        Ok(locator)
    }

    pub(crate) fn revalidate_scope_replay(
        &self,
        retained_locator: Option<[u8; 32]>,
        expected: &HostScopeReplayBindingV1,
        authority: &HostAuthorityV1,
    ) -> Result<[u8; 32]> {
        let payload = encode_scope_replay_binding(expected);
        let locator = scope_replay_locator(&payload);
        if retained_locator.is_some_and(|retained| retained != locator) {
            return Err(HostError::State(
                "Host scope replay locator does not match protected custody".to_owned(),
            ));
        }
        let replay = self.scope_replays.get(&locator).ok_or_else(|| {
            HostError::State("Host scope replay authority is not retained".to_owned())
        })?;
        if scope_replay_locator(&payload) != locator
            || replay.binding() != *expected
            || authority
                .terminal_verifier_commitment()
                .map_err(|error| HostError::State(error.to_string()))?
                != expected.terminal_verifier_commitment
            || authority.open_execution_record(&expected.request_id, &replay.authentication)?
                != payload
        {
            return Err(HostError::State(
                "Host scope replay authority does not match the protected request".to_owned(),
            ));
        }
        Ok(locator)
    }

    pub(crate) fn finalize_scope_replay(
        &mut self,
        receipt: &aos_sandbox_protocol::BrokerTerminalCommitReceiptV1,
        authority: &HostAuthorityV1,
    ) -> Result<[u8; 32]> {
        let receipt_binding = receipt.binding();
        let retained_locator = receipt_binding.reservation_locator();
        let Some(retained) = self.scope_replays.get(&retained_locator) else {
            let mut exact_finalized = None;
            for (locator, retained) in &self.scope_replays {
                let finalized = retained.binding();
                if finalized.terminal_reservation_locator != retained_locator {
                    continue;
                }
                self.revalidate_scope_replay(Some(*locator), &finalized, authority)?;
                if !scope_replay_receipt_matches(receipt, retained_locator, &finalized) {
                    return Err(HostError::State(
                        "Host finalized scope replay contradicts its receipt".to_owned(),
                    ));
                }
                if exact_finalized.replace(*locator).is_some() {
                    return Err(HostError::State(
                        "Host scope replay has multiple finalized successors".to_owned(),
                    ));
                }
            }
            return exact_finalized.ok_or_else(|| {
                HostError::State("Host scope replay reservation is not retained".to_owned())
            });
        };
        let reservation = retained.binding();
        self.revalidate_scope_replay(Some(retained_locator), &reservation, authority)?;
        if reservation.terminal_reservation_locator != [0; 32]
            || !scope_replay_receipt_matches(receipt, retained_locator, &reservation)
        {
            return Err(HostError::State(
                "Host scope terminal replay receipt is invalid".to_owned(),
            ));
        }

        let mut terminal = reservation;
        terminal.terminal_reservation_locator = retained_locator;
        terminal.signed_outcome_digest = receipt_binding.signed_outcome_digest();
        terminal.protected_generation = receipt_binding.protected_generation();
        terminal.protected_head = receipt_binding.protected_head();
        let payload = encode_scope_replay_binding(&terminal);
        let locator = scope_replay_locator(&payload);
        let authentication = authority.seal_execution_record(&terminal.request_id, &payload)?;
        let finalized = DurableScopeReplay::new(locator, terminal, authentication);
        if self
            .scope_replays
            .get(&locator)
            .is_some_and(|current| current != &finalized)
        {
            return Err(HostError::State(
                "Host scope terminal replay locator was reused".to_owned(),
            ));
        }
        self.scope_replays.remove(&retained_locator);
        self.scope_replays.insert(locator, finalized);
        Ok(locator)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let wire = StateWire {
            fences: self.fences.values().cloned().collect(),
            requests: self.requests.values().cloned().collect(),
            observation_sequences: self
                .observation_sequences
                .iter()
                .map(|(incarnation_id, sequence)| ObservationSequence {
                    incarnation_id: *incarnation_id,
                    sequence: *sequence,
                })
                .collect(),
            scope_replays: self.scope_replays.values().cloned().collect(),
        };
        serde_json::to_vec(&wire).map_err(|error| HostError::State(error.to_string()))
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let wire: StateWire =
            serde_json::from_slice(bytes).map_err(|error| HostError::State(error.to_string()))?;
        if wire.requests.len() > MAXIMUM_REQUESTS {
            return Err(HostError::State(
                "durable host request table exceeds its fixed bound".to_owned(),
            ));
        }
        if wire.scope_replays.len() > MAXIMUM_REQUESTS {
            return Err(HostError::State(
                "durable Host scope replay table exceeds its fixed bound".to_owned(),
            ));
        }
        let mut state = Self::default();
        for fence in wire.fences {
            validate_fence(&fence)?;
            if state.fences.insert(fence.sandbox_id, fence).is_some() {
                return Err(HostError::State(
                    "duplicate durable sandbox fence".to_owned(),
                ));
            }
        }
        for request in wire.requests {
            validate_request(&request)?;
            if state.requests.insert(request.request_id, request).is_some() {
                return Err(HostError::State("duplicate durable request ID".to_owned()));
            }
        }
        for observation in wire.observation_sequences {
            if observation.incarnation_id == [0; 16]
                || observation.sequence == 0
                || state
                    .observation_sequences
                    .insert(observation.incarnation_id, observation.sequence)
                    .is_some()
            {
                return Err(HostError::State(
                    "invalid durable observation sequence".to_owned(),
                ));
            }
        }
        for replay in wire.scope_replays {
            validate_scope_replay(&replay)?;
            if state.scope_replays.insert(replay.locator, replay).is_some() {
                return Err(HostError::State(
                    "duplicate durable Host scope replay locator".to_owned(),
                ));
            }
        }
        state.validate_execution_links()?;
        Ok(state)
    }
}

impl DurableScopeReplay {
    fn new(locator: [u8; 32], binding: HostScopeReplayBindingV1, authentication: Vec<u8>) -> Self {
        Self {
            locator,
            method: binding.method,
            request_id: binding.request_id,
            request_body_digest: binding.request_body_digest,
            signed_request_digest: binding.signed_request_digest,
            session_binding: binding.session_binding,
            response_body_digest: binding.response_body_digest,
            terminal_verifier_commitment: binding.terminal_verifier_commitment,
            terminal_reservation_locator: binding.terminal_reservation_locator,
            signed_outcome_digest: binding.signed_outcome_digest,
            protected_generation: binding.protected_generation,
            protected_head: binding.protected_head,
            artifact_commitment: binding.artifact_commitment,
            peer_uid: binding.peer_uid,
            peer_gid: binding.peer_gid,
            peer_pid: binding.peer_pid,
            policy_uid: binding.policy_uid,
            policy_gid: binding.policy_gid,
            policy_audience: binding.policy_audience,
            protocol_major: binding.protocol_major,
            protocol_minor: binding.protocol_minor,
            protected_boot_id: binding.protected_boot_id,
            authentication,
        }
    }

    fn binding(&self) -> HostScopeReplayBindingV1 {
        HostScopeReplayBindingV1 {
            method: self.method,
            request_id: self.request_id,
            request_body_digest: self.request_body_digest,
            signed_request_digest: self.signed_request_digest,
            session_binding: self.session_binding,
            response_body_digest: self.response_body_digest,
            terminal_verifier_commitment: self.terminal_verifier_commitment,
            terminal_reservation_locator: self.terminal_reservation_locator,
            signed_outcome_digest: self.signed_outcome_digest,
            protected_generation: self.protected_generation,
            protected_head: self.protected_head,
            artifact_commitment: self.artifact_commitment,
            peer_uid: self.peer_uid,
            peer_gid: self.peer_gid,
            peer_pid: self.peer_pid,
            policy_uid: self.policy_uid,
            policy_gid: self.policy_gid,
            policy_audience: self.policy_audience,
            protocol_major: self.protocol_major,
            protocol_minor: self.protocol_minor,
            protected_boot_id: self.protected_boot_id,
        }
    }
}

fn encode_scope_replay_binding(binding: &HostScopeReplayBindingV1) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(298);
    encoded.extend_from_slice(b"aos.sandbox.host.scope-replay.v1\0");
    encoded.extend_from_slice(&binding.method.to_be_bytes());
    encoded.extend_from_slice(&binding.request_id);
    encoded.extend_from_slice(&binding.request_body_digest);
    encoded.extend_from_slice(&binding.signed_request_digest);
    encoded.extend_from_slice(&binding.session_binding);
    encoded.extend_from_slice(&binding.response_body_digest);
    encoded.extend_from_slice(&binding.terminal_verifier_commitment);
    encoded.extend_from_slice(&binding.terminal_reservation_locator);
    encoded.extend_from_slice(&binding.signed_outcome_digest);
    encoded.extend_from_slice(&binding.protected_generation.to_be_bytes());
    encoded.extend_from_slice(&binding.protected_head);
    encoded.extend_from_slice(&binding.artifact_commitment);
    encoded.extend_from_slice(&binding.peer_uid.to_be_bytes());
    encoded.extend_from_slice(&binding.peer_gid.to_be_bytes());
    encoded.extend_from_slice(&binding.peer_pid.to_be_bytes());
    encoded.extend_from_slice(&binding.policy_uid.to_be_bytes());
    encoded.extend_from_slice(&binding.policy_gid.to_be_bytes());
    encoded.extend_from_slice(&binding.policy_audience.to_be_bytes());
    encoded.extend_from_slice(&binding.protocol_major.to_be_bytes());
    encoded.extend_from_slice(&binding.protocol_minor.to_be_bytes());
    encoded.extend_from_slice(&binding.protected_boot_id);
    encoded
}

fn scope_replay_locator(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

pub(crate) fn scope_replay_reservation_locator(binding: &HostScopeReplayBindingV1) -> [u8; 32] {
    scope_replay_locator(&encode_scope_replay_binding(binding))
}

fn scope_replay_receipt_matches(
    receipt: &aos_sandbox_protocol::BrokerTerminalCommitReceiptV1,
    reservation_locator: [u8; 32],
    binding: &HostScopeReplayBindingV1,
) -> bool {
    let receipt_binding = receipt.binding();
    let terminal_matches = if binding.terminal_reservation_locator == [0; 32] {
        binding.signed_outcome_digest == [0; 32]
            && binding.protected_generation == 0
            && binding.protected_head == [0; 32]
    } else {
        binding.terminal_reservation_locator == reservation_locator
            && binding.signed_outcome_digest == receipt_binding.signed_outcome_digest()
            && binding.protected_generation == receipt_binding.protected_generation()
            && binding.protected_head == receipt_binding.protected_head()
    };
    let expected = aos_proto::aos::sandbox::local::v1::BrokerMethod::try_from(binding.method)
        .ok()
        .and_then(|method| {
            aos_sandbox_protocol::BrokerTerminalCommitBindingV1::new(
                reservation_locator,
                method,
                binding.request_id,
                binding.signed_request_digest,
                binding.session_binding,
                receipt_binding.signed_outcome_digest(),
                receipt_binding.protected_generation(),
                receipt_binding.protected_head(),
            )
        });
    terminal_matches
        && scope_replay_terminal_lineage_is_valid(binding)
        && expected.as_ref().is_some_and(|expected| {
            receipt.verify_pinned_commitment(expected, binding.terminal_verifier_commitment)
        })
}

fn scope_replay_terminal_lineage_is_valid(binding: &HostScopeReplayBindingV1) -> bool {
    if binding.terminal_reservation_locator == [0; 32] {
        return true;
    }
    let mut reservation = binding.clone();
    reservation.terminal_reservation_locator = [0; 32];
    reservation.signed_outcome_digest = [0; 32];
    reservation.protected_generation = 0;
    reservation.protected_head = [0; 32];
    scope_replay_reservation_locator(&reservation) == binding.terminal_reservation_locator
}

fn validate_scope_replay(replay: &DurableScopeReplay) -> Result<()> {
    let binding = replay.binding();
    let payload = encode_scope_replay_binding(&binding);
    if replay.locator == [0; 32]
        || replay.request_id == [0; 16]
        || replay.request_body_digest == [0; 32]
        || replay.signed_request_digest == [0; 32]
        || replay.session_binding == [0; 32]
        || replay.response_body_digest == [0; 32]
        || replay.terminal_verifier_commitment == [0; 32]
        || replay.artifact_commitment == [0; 32]
        || replay.protected_boot_id == [0; 16]
        || replay.authentication.is_empty()
        || replay.authentication.len() > MAXIMUM_EXECUTION_AUTHENTICATION_BYTES
        || scope_replay_locator(&payload) != replay.locator
        || !scope_replay_terminal_lineage_is_valid(&binding)
        || ((replay.terminal_reservation_locator == [0; 32]
            || replay.signed_outcome_digest == [0; 32]
            || replay.protected_generation == 0
            || replay.protected_head == [0; 32])
            && (replay.terminal_reservation_locator != [0; 32]
                || replay.signed_outcome_digest != [0; 32]
                || replay.protected_generation != 0
                || replay.protected_head != [0; 32]))
    {
        return Err(HostError::State(
            "durable Host scope replay record is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_opened_fence(
    durable: &DurableFence,
    opened: &aos_sandbox_broker::BrokerAuthorizationFenceV1,
) -> Result<()> {
    let assignment = opened.assignment();
    if assignment.sandbox().as_bytes() != &durable.sandbox_id
        || assignment.incarnation().as_bytes() != &durable.incarnation_id
        || assignment.epoch().get() != durable.assignment_epoch
        || assignment.desired_generation().get() != durable.desired_generation
        || assignment.digest().as_bytes() != &durable.assignment_digest
    {
        return Err(HostError::State(
            "authenticated fence contradicts its durable index".to_owned(),
        ));
    }
    Ok(())
}

fn action_verb(action: u8) -> Option<aos_sandbox_core::BrokerVerb> {
    match action {
        1 => Some(aos_sandbox_core::BrokerVerb::HostLaunch),
        2 => Some(aos_sandbox_core::BrokerVerb::HostStop),
        3 => Some(aos_sandbox_core::BrokerVerb::HostFreeze),
        4 => Some(aos_sandbox_core::BrokerVerb::HostThaw),
        5 => Some(aos_sandbox_core::BrokerVerb::HostKill),
        _ => None,
    }
}

fn stable_authority_digest(
    effect: &BrokerEffectIntentV1,
    fence: &BrokerAuthorizationFenceV1,
) -> Result<[u8; 32]> {
    let assignment = fence.assignment();
    let ownership = fence.ownership_authority();
    let verb = host_verb_code(effect.verb()).ok_or_else(|| {
        HostError::State("authenticated Host effect has a non-Host verb".to_owned())
    })?;
    let usage = match ownership.usage() {
        KeyUsage::OwnershipLease => 2,
        _ => {
            return Err(HostError::State(
                "authenticated Host fence has a non-ownership authority".to_owned(),
            ));
        }
    };

    StableAuthorityFields {
        transport_request_digest: *effect.transport_request_digest().as_bytes(),
        semantic_request_digest: *effect.request_digest().as_bytes(),
        verb,
        target: stable_target_bytes(effect.target()),
        sandbox_id: *assignment.sandbox().as_bytes(),
        incarnation_id: *assignment.incarnation().as_bytes(),
        assignment_epoch: assignment.epoch().get(),
        desired_generation: assignment.desired_generation().get(),
        assignment_digest: *assignment.digest().as_bytes(),
        node_id: *fence.node().as_bytes(),
        plan_digest: *fence.plan_digest().as_bytes(),
        ownership_stable_key_id: ownership.stable_key_id().as_str().as_bytes().to_vec(),
        ownership_generation: ownership.generation(),
        ownership_public_key_sha256: *ownership.public_key_sha256().as_bytes(),
        ownership_usage: usage,
    }
    .digest()
}

#[derive(Clone)]
struct StableAuthorityFields {
    transport_request_digest: [u8; 32],
    semantic_request_digest: [u8; 32],
    verb: u8,
    target: Vec<u8>,
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
    node_id: [u8; 16],
    plan_digest: [u8; 32],
    ownership_stable_key_id: Vec<u8>,
    ownership_generation: u64,
    ownership_public_key_sha256: [u8; 32],
    ownership_usage: u8,
}

impl StableAuthorityFields {
    fn digest(&self) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(STABLE_AUTHORITY_DOMAIN);
        update_stable_authority_field(&mut hash, 1, &STABLE_AUTHORITY_VERSION.to_be_bytes())?;
        update_stable_authority_field(&mut hash, 2, &self.transport_request_digest)?;
        update_stable_authority_field(&mut hash, 3, &self.semantic_request_digest)?;
        update_stable_authority_field(&mut hash, 4, &[self.verb])?;
        update_stable_authority_field(&mut hash, 5, &self.target)?;
        update_stable_authority_field(&mut hash, 6, &self.sandbox_id)?;
        update_stable_authority_field(&mut hash, 7, &self.incarnation_id)?;
        update_stable_authority_field(&mut hash, 8, &self.assignment_epoch.to_be_bytes())?;
        update_stable_authority_field(&mut hash, 9, &self.desired_generation.to_be_bytes())?;
        update_stable_authority_field(&mut hash, 10, &self.assignment_digest)?;
        update_stable_authority_field(&mut hash, 11, &self.node_id)?;
        update_stable_authority_field(&mut hash, 12, &self.plan_digest)?;
        update_stable_authority_field(&mut hash, 13, &self.ownership_stable_key_id)?;
        update_stable_authority_field(&mut hash, 14, &self.ownership_generation.to_be_bytes())?;
        update_stable_authority_field(&mut hash, 15, &self.ownership_public_key_sha256)?;
        update_stable_authority_field(&mut hash, 16, &[self.ownership_usage])?;
        Ok(hash.finalize().into())
    }
}

fn update_stable_authority_field(hash: &mut Sha256, tag: u16, value: &[u8]) -> Result<()> {
    let length = u64::try_from(value.len())
        .map_err(|_| HostError::State("stable Host authority field is too large".to_owned()))?;
    hash.update(tag.to_be_bytes());
    hash.update(length.to_be_bytes());
    hash.update(value);
    Ok(())
}

fn host_verb_code(verb: BrokerVerb) -> Option<u8> {
    match verb {
        BrokerVerb::HostLaunch => Some(1),
        BrokerVerb::HostStop => Some(2),
        BrokerVerb::HostFreeze => Some(3),
        BrokerVerb::HostThaw => Some(4),
        BrokerVerb::HostKill => Some(5),
        _ => None,
    }
}

fn stable_target_bytes(target: BrokerGrantTarget) -> Vec<u8> {
    match target {
        BrokerGrantTarget::Assignment => vec![1],
        BrokerGrantTarget::Resource(resource) => {
            let mut bytes = Vec::with_capacity(33);
            bytes.push(2);
            bytes.extend_from_slice(resource.as_bytes());
            bytes
        }
        BrokerGrantTarget::ResourcePair {
            previous,
            successor,
        } => {
            let mut bytes = Vec::with_capacity(65);
            bytes.push(3);
            bytes.extend_from_slice(previous.as_bytes());
            bytes.extend_from_slice(successor.as_bytes());
            bytes
        }
    }
}

fn validate_execution_authentication(
    authority: &HostAuthorityV1,
    request: &RequestRecord,
    stable_authority_digest: [u8; 32],
) -> Result<()> {
    let expected = request
        .execution
        .authentication_digest(execution_context(request)?, stable_authority_digest)
        .ok_or_else(|| {
            HostError::State("Host execution authentication input is too large".to_owned())
        })?;
    let opened =
        authority.open_execution_record(&request.request_id, &request.execution_authentication)?;
    if !fixed_digest_matches(opened, &expected) {
        return Err(HostError::State(
            "Host execution authentication contradicts its record".to_owned(),
        ));
    }
    Ok(())
}

fn fixed_digest_matches(opened: &[u8], expected: &[u8; 32]) -> bool {
    opened.len() == expected.len()
        && opened
            .iter()
            .zip(expected)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn ensure_live_execution_enabled(execution: &DurableExecution) -> Result<()> {
    match execution {
        DurableExecution::DirectLifecycle
        | DurableExecution::GuardianLaunch(_)
        | DurableExecution::CompositeStop(_) => Ok(()),
    }
}

fn execution_context(request: &RequestRecord) -> Result<ExecutionContext> {
    let action = HostAction::from_code(request.action)
        .ok_or_else(|| HostError::State("durable host action is invalid".to_owned()))?;
    Ok(execution_context_from_parts(
        action,
        request.request_id,
        request.request_digest,
        request.fence.sandbox_id,
        request.fence.incarnation_id,
        request.fence.assignment_epoch,
        request.fence.desired_generation,
        request.fence.assignment_digest,
        request.receipt.is_some(),
    ))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the final durable execution context authenticates one closed fixed field set"
)]
fn execution_context_from_parts(
    action: HostAction,
    request_id: [u8; 16],
    request_digest: [u8; 32],
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
    receipt_present: bool,
) -> ExecutionContext {
    ExecutionContext {
        action,
        request_id,
        request_digest,
        sandbox_id,
        incarnation_id,
        assignment_epoch,
        desired_generation,
        assignment_digest,
        receipt_present,
    }
}

fn retained_effect(request: &RequestRecord) -> Result<RetainedRuntimeEffect> {
    let intent = match request.action {
        1 => RetainedRuntimeIntent::Launch,
        2 => RetainedRuntimeIntent::Stop,
        3 => RetainedRuntimeIntent::Freeze,
        4 => RetainedRuntimeIntent::Thaw,
        5 => RetainedRuntimeIntent::Kill,
        _ => {
            return Err(HostError::State(
                "retained runtime request has an unknown action".to_owned(),
            ));
        }
    };
    Ok(RetainedRuntimeEffect {
        identity: request.fence.runtime_identity(),
        request_id: request.request_id,
        intent,
        durability: if request.receipt.is_some() {
            RetainedEffectDurability::Complete
        } else {
            RetainedEffectDurability::Pending
        },
    })
}

impl DurableFence {
    fn runtime_identity(&self) -> HostRuntimeIdentity {
        HostRuntimeIdentity::new(
            self.sandbox_id,
            self.incarnation_id,
            self.assignment_epoch,
            self.desired_generation,
            self.assignment_digest,
        )
    }

    fn from_validated(
        fence: &ValidatedAssignmentFence,
        witness_request_id: [u8; 16],
        authorization: Vec<u8>,
    ) -> Self {
        Self {
            witness_request_id,
            sandbox_id: *fence.sandbox_id(),
            incarnation_id: *fence.incarnation_id(),
            assignment_epoch: fence.assignment_epoch(),
            desired_generation: fence.desired_generation(),
            assignment_digest: *fence.assignment_digest(),
            authorization,
        }
    }

    fn validate_successor(&self, proposed: &Self) -> Result<()> {
        if proposed.assignment_epoch < self.assignment_epoch
            || (proposed.assignment_epoch == self.assignment_epoch
                && proposed.desired_generation < self.desired_generation)
        {
            return Err(HostError::Fence("assignment generation is stale"));
        }
        if proposed.assignment_epoch == self.assignment_epoch {
            if proposed.incarnation_id != self.incarnation_id {
                return Err(HostError::Fence(
                    "equal assignment epoch changed incarnation",
                ));
            }
            if proposed.desired_generation == self.desired_generation
                && proposed.assignment_digest != self.assignment_digest
            {
                return Err(HostError::Fence(
                    "equal assignment generation changed semantic digest",
                ));
            }
        }
        Ok(())
    }
}

fn validate_fence(fence: &DurableFence) -> Result<()> {
    if fence.witness_request_id == [0; 16]
        || fence.sandbox_id == [0; 16]
        || fence.incarnation_id == [0; 16]
        || fence.assignment_epoch == 0
        || fence.desired_generation == 0
        || fence.assignment_digest == [0; 32]
        || fence.authorization.is_empty()
        || fence.authorization.len() > MAXIMUM_STATE_BYTES
    {
        return Err(HostError::State(
            "durable assignment fence contains a sentinel".to_owned(),
        ));
    }
    Ok(())
}

fn validate_request(request: &RequestRecord) -> Result<()> {
    validate_fence(&request.fence)?;
    if request.request_id == [0; 16]
        || request.request_digest == [0; 32]
        || request.effect.is_empty()
        || request.effect.len() > MAXIMUM_STATE_BYTES
        || request.execution_authentication.is_empty()
        || request.execution_authentication.len() > MAXIMUM_EXECUTION_AUTHENTICATION_BYTES
        || request
            .receipt
            .as_ref()
            .is_some_and(|receipt| receipt.is_empty() || receipt.len() > MAXIMUM_RECEIPT_BYTES)
    {
        return Err(HostError::State(
            "durable host request record is invalid".to_owned(),
        ));
    }
    if !request.execution.validate(execution_context(request)?) {
        return Err(HostError::State(
            "durable host execution kind contradicts its request".to_owned(),
        ));
    }
    Ok(())
}

/// Persists complete host state before and after every privileged effect.
pub trait HostStateStore {
    /// Loads and validates the current durable snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for I/O, bounds, checksum, schema, or invariant
    /// failures. Missing state initializes an empty broker.
    fn load(&self) -> Result<HostState>;

    /// Atomically commits one complete replacement snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error unless file contents and the containing directory are
    /// durably synchronized.
    fn commit(&self, state: &HostState) -> Result<()>;
}

/// Stores one checksummed snapshot beneath a pre-created private directory.
#[derive(Clone, Debug)]
pub struct FileHostStateStore {
    directory: PathBuf,
    state_path: PathBuf,
    temporary_path: PathBuf,
}

impl FileHostStateStore {
    /// Opens a private state directory and fixes the state filename.
    ///
    /// # Errors
    ///
    /// Returns an error unless `directory` is a real directory with no group
    /// or other permission bits. Symlink directories are rejected.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self> {
        let directory = directory.into();
        let metadata = fs::symlink_metadata(&directory)
            .map_err(|error| HostError::State(error.to_string()))?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != rustix::process::getuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(HostError::State(
                "host state directory must be a private real directory".to_owned(),
            ));
        }
        Ok(Self {
            state_path: directory.join("state.bin"),
            temporary_path: directory.join("state.next"),
            directory,
        })
    }

    fn write_atomic(&self, bytes: &[u8]) -> Result<()> {
        match fs::remove_file(&self.temporary_path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(HostError::State(error.to_string())),
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.temporary_path)
            .map_err(|error| HostError::State(error.to_string()))?;
        output
            .write_all(bytes)
            .and_then(|()| output.sync_all())
            .map_err(|error| HostError::State(error.to_string()))?;
        fs::rename(&self.temporary_path, &self.state_path)
            .map_err(|error| HostError::State(error.to_string()))?;
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| HostError::State(error.to_string()))
    }
}

impl HostStateStore for FileHostStateStore {
    fn load(&self) -> Result<HostState> {
        let mut input = match File::open(&self.state_path) {
            Ok(input) => input,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(HostState::default()),
            Err(error) => return Err(HostError::State(error.to_string())),
        };
        let file_length = usize::try_from(
            input
                .metadata()
                .map_err(|error| HostError::State(error.to_string()))?
                .size(),
        )
        .map_err(|_| HostError::State("host state size does not fit usize".to_owned()))?;
        if !(HEADER_BYTES..=HEADER_BYTES + MAXIMUM_STATE_BYTES).contains(&file_length) {
            return Err(HostError::State(
                "host state file length is outside its fixed bounds".to_owned(),
            ));
        }
        let mut bytes = vec![0; file_length];
        input
            .read_exact(&mut bytes)
            .map_err(|error| HostError::State(error.to_string()))?;
        decode_envelope(&bytes)
    }

    fn commit(&self, state: &HostState) -> Result<()> {
        let body = state.encode()?;
        if body.len() > MAXIMUM_STATE_BYTES {
            return Err(HostError::State(
                "encoded host state exceeds sixteen MiB".to_owned(),
            ));
        }
        let mut bytes = Vec::with_capacity(HEADER_BYTES + body.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(
            &u64::try_from(body.len())
                .map_err(|_| HostError::State("host state size overflow".to_owned()))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&Sha256::digest(&body));
        bytes.extend_from_slice(&body);
        self.write_atomic(&bytes)
    }
}

fn decode_envelope(bytes: &[u8]) -> Result<HostState> {
    if &bytes[..8] != MAGIC {
        return Err(HostError::State("host state magic mismatch".to_owned()));
    }
    let version = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| HostError::State("host state version field is truncated".to_owned()))?,
    );
    if version != VERSION {
        return Err(HostError::State(
            "host state version is unsupported".to_owned(),
        ));
    }
    let body_length =
        usize::try_from(u64::from_le_bytes(bytes[12..20].try_into().map_err(
            |_| HostError::State("host state length field is truncated".to_owned()),
        )?))
        .map_err(|_| HostError::State("host state body length does not fit usize".to_owned()))?;
    if body_length > MAXIMUM_STATE_BYTES || HEADER_BYTES + body_length != bytes.len() {
        return Err(HostError::State(
            "host state body length is inconsistent".to_owned(),
        ));
    }
    let expected: [u8; 32] = bytes[20..52]
        .try_into()
        .map_err(|_| HostError::State("host state checksum is truncated".to_owned()))?;
    let body = &bytes[HEADER_BYTES..];
    if Sha256::digest(body).as_slice() != expected {
        return Err(HostError::State("host state checksum mismatch".to_owned()));
    }
    HostState::decode(body)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{
        ApplyRuntimeRequest, Audience, BrokerAuthorizationArtifactsV1, BrokerMethod,
        BrokerRequestEnvelope, Feature, GuardianArmCompanionV1, ResourceLimit, RuntimeAction,
    };
    use aos_sandbox_core::format::{
        encode_broker_authorization_plan, encode_ownership_lease, encode_signature,
        encode_trust_policy,
    };
    use aos_sandbox_core::model::{
        KeyReference, SignaturePurpose, SignatureStatement, StableKeyId, TrustPolicy,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, BrokerAssignment, BrokerAudience, BrokerAuthorizationPlan, BrokerGrant,
        BrokerGrantTarget, BrokerPlanTrustAnchor, BrokerVerb, DecodeLimits, DesiredGeneration,
        GuardianPlanBinding, IncarnationId, LeaseAssignment, MediaType, NodeId, ObjectDescriptor,
        ObjectDigest, OwnershipLease, OwnershipLeaseTrustAnchor, PortableMediaType, ProtocolId,
        ProtocolVersion, RawClockProvenance, RawPairedClockSample, RevocationScopeId, SandboxId,
        TrustScopeId, descriptor_for_bytes, sign_statement,
    };
    use aos_sandbox_protocol::session::{
        ValidatedUntrustedAuthorizationArtifacts, decode_request_envelope,
    };
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, decode_runtime_request};
    use buffa::Message as _;
    use ed25519_dalek::SigningKey;

    use super::*;

    fn key_reference(
        name: &str,
        generation: u64,
        usage: KeyUsage,
        key: &SigningKey,
    ) -> KeyReference {
        KeyReference::new(
            StableKeyId::new(name.to_owned()).unwrap(),
            generation,
            ObjectDigest::from_bytes(Sha256::digest(key.verifying_key().as_bytes()).into()),
            usage,
        )
    }

    fn policy(
        scope: TrustScopeId,
        purpose: SignaturePurpose,
        key: KeyReference,
    ) -> (Vec<u8>, ObjectDescriptor) {
        let bytes =
            encode_trust_policy(&TrustPolicy::new(scope, purpose, vec![key], vec![]).unwrap());
        let descriptor = descriptor_for_bytes(
            MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned()).unwrap(),
            &bytes,
        );
        (bytes, descriptor)
    }

    fn authority() -> HostAuthorityV1 {
        let plan_key = SigningKey::from_bytes(&[41; 32]);
        let lease_key = SigningKey::from_bytes(&[42; 32]);
        let plan_scope = TrustScopeId::from_bytes([43; 16]);
        let lease_scope = TrustScopeId::from_bytes([44; 16]);
        let plan_signer = key_reference(
            "state-execution-plan",
            1,
            KeyUsage::BrokerAuthorization,
            &plan_key,
        );
        let lease_signer = key_reference(
            "state-execution-lease",
            1,
            KeyUsage::OwnershipLease,
            &lease_key,
        );
        let (plan_policy, plan_descriptor) = policy(
            plan_scope,
            SignaturePurpose::BrokerAuthorization,
            plan_signer.clone(),
        );
        let (lease_policy, lease_descriptor) = policy(
            lease_scope,
            SignaturePurpose::OwnershipLease,
            lease_signer.clone(),
        );
        let plan_anchor = BrokerPlanTrustAnchor::from_trusted_configuration(
            plan_policy,
            plan_descriptor,
            plan_scope,
            plan_signer,
            plan_key.verifying_key().to_bytes(),
            RevocationScopeId::from_bytes([45; 16]),
            DecodeLimits::default(),
        )
        .unwrap();
        let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
            lease_policy,
            lease_descriptor,
            lease_scope,
            lease_signer,
            lease_key.verifying_key().to_bytes(),
            DecodeLimits::default(),
        )
        .unwrap();

        HostAuthorityV1::new(
            plan_anchor,
            lease_anchor,
            NodeId::from_bytes([46; 16]),
            [47; 16],
            [48; 32],
        )
        .unwrap()
    }

    struct AdmissionFixture {
        plan_key: SigningKey,
        lease_key: SigningKey,
        plan_signer: KeyReference,
        lease_signer: KeyReference,
        plan_policy: Vec<u8>,
        plan_policy_descriptor: ObjectDescriptor,
        plan_scope: TrustScopeId,
        lease_policy: Vec<u8>,
        lease_policy_descriptor: ObjectDescriptor,
        lease_scope: TrustScopeId,
        revocation_scope: RevocationScopeId,
    }

    impl AdmissionFixture {
        fn new() -> Self {
            let plan_key = SigningKey::from_bytes(&[41; 32]);
            let lease_key = SigningKey::from_bytes(&[42; 32]);
            let plan_signer = key_reference(
                "host-plan-controller",
                3,
                KeyUsage::BrokerAuthorization,
                &plan_key,
            );
            let lease_signer = key_reference(
                "host-ownership-authority",
                7,
                KeyUsage::OwnershipLease,
                &lease_key,
            );
            let plan_scope = TrustScopeId::from_bytes([43; 16]);
            let lease_scope = TrustScopeId::from_bytes([44; 16]);
            let (plan_policy, plan_policy_descriptor) = policy(
                plan_scope,
                SignaturePurpose::BrokerAuthorization,
                plan_signer.clone(),
            );
            let (lease_policy, lease_policy_descriptor) = policy(
                lease_scope,
                SignaturePurpose::OwnershipLease,
                lease_signer.clone(),
            );
            Self {
                plan_key,
                lease_key,
                plan_signer,
                lease_signer,
                plan_policy,
                plan_policy_descriptor,
                plan_scope,
                lease_policy,
                lease_policy_descriptor,
                lease_scope,
                revocation_scope: RevocationScopeId::from_bytes([45; 16]),
            }
        }

        fn authority(&self) -> HostAuthorityV1 {
            let plan_anchor = BrokerPlanTrustAnchor::from_trusted_configuration(
                self.plan_policy.clone(),
                self.plan_policy_descriptor.clone(),
                self.plan_scope,
                self.plan_signer.clone(),
                self.plan_key.verifying_key().to_bytes(),
                self.revocation_scope,
                DecodeLimits::default(),
            )
            .unwrap();
            let lease_anchor = OwnershipLeaseTrustAnchor::from_trusted_configuration(
                self.lease_policy.clone(),
                self.lease_policy_descriptor.clone(),
                self.lease_scope,
                self.lease_signer.clone(),
                self.lease_key.verifying_key().to_bytes(),
                DecodeLimits::default(),
            )
            .unwrap();
            HostAuthorityV1::new(
                plan_anchor,
                lease_anchor,
                NodeId::from_bytes([31; 16]),
                [46; 16],
                [47; 32],
            )
            .unwrap()
        }

        fn artifacts(
            &self,
            request_bytes: &[u8],
            lease_generation: u64,
            plan_expires_seconds: i64,
        ) -> ValidatedUntrustedAuthorizationArtifacts {
            let request = decode_runtime_request(
                request_bytes,
                test_peer(),
                test_policy(),
                TEST_BOOTTIME_NANOSECONDS,
            )
            .unwrap();
            let semantics =
                crate::authorization::semantics_v1::canonical_host_semantics_v1(&request).unwrap();
            let assignment = BrokerAssignment::new(
                SandboxId::from_bytes(*request.fence().sandbox_id()),
                IncarnationId::from_bytes(*request.fence().incarnation_id()),
                AssignmentEpoch::new(request.fence().assignment_epoch()),
                DesiredGeneration::new(request.fence().desired_generation()),
                ObjectDigest::from_bytes(*request.fence().assignment_digest()),
            )
            .unwrap();
            let grant = BrokerGrant::new(
                semantics.verb(),
                semantics.target(),
                semantics.commitment(),
                u32::try_from(request_bytes.len()).unwrap(),
                0,
            )
            .unwrap();
            let plan = BrokerAuthorizationPlan::new(
                BrokerAudience::Host,
                ProtocolId::HostBroker,
                ProtocolVersion::new(1, 0),
                assignment,
                NodeId::from_bytes([31; 16]),
                self.lease_signer.clone(),
                vec![grant],
                ObjectDigest::from_bytes([48; 32]),
                self.revocation_scope,
                100,
                plan_expires_seconds,
                Vec::new(),
            )
            .unwrap();
            let broker_plan = encode_broker_authorization_plan(&plan);
            let broker_plan_signature = signed_object(
                &broker_plan,
                PortableMediaType::BrokerAuthorizationPlan,
                self.plan_scope,
                self.plan_signer.clone(),
                SignaturePurpose::BrokerAuthorization,
                &self.plan_policy_descriptor,
                &self.plan_key,
                plan_expires_seconds,
            );
            let lease = OwnershipLease::new(
                LeaseAssignment::new(
                    assignment.sandbox(),
                    assignment.incarnation(),
                    assignment.epoch(),
                    assignment.digest(),
                )
                .unwrap(),
                NodeId::from_bytes([31; 16]),
                lease_generation,
                100,
                300,
                10,
                [u8::try_from(lease_generation).unwrap_or(255); 16],
            )
            .unwrap();
            let ownership_lease = encode_ownership_lease(&lease);
            let ownership_lease_signature = signed_object(
                &ownership_lease,
                PortableMediaType::OwnershipLease,
                self.lease_scope,
                self.lease_signer.clone(),
                SignaturePurpose::OwnershipLease,
                &self.lease_policy_descriptor,
                &self.lease_key,
                300,
            );

            validated_artifacts(BrokerAuthorizationArtifactsV1 {
                broker_plan,
                broker_plan_signature,
                ownership_lease,
                ownership_lease_signature,
                ..Default::default()
            })
        }
    }

    const TEST_WALL_SECONDS: i64 = 150;
    const TEST_BOOTTIME_NANOSECONDS: u64 = 100;

    fn test_peer() -> PeerCredentials {
        PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        }
    }

    fn test_policy() -> PeerPolicy {
        PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }

    fn test_clock() -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([49; 16]).unwrap(),
            [50; 16],
            TEST_WALL_SECONDS,
            TEST_BOOTTIME_NANOSECONDS,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_object(
        bytes: &[u8],
        media_type: PortableMediaType,
        scope: TrustScopeId,
        signer: KeyReference,
        purpose: SignaturePurpose,
        policy: &ObjectDescriptor,
        key: &SigningKey,
        expires_seconds: i64,
    ) -> Vec<u8> {
        let subject = descriptor_for_bytes(
            MediaType::new(media_type.as_str().to_owned()).unwrap(),
            bytes,
        );
        let statement = SignatureStatement::new(
            subject,
            scope,
            signer,
            purpose,
            100,
            Some(expires_seconds),
            policy.clone(),
        )
        .unwrap();
        encode_signature(&sign_statement(statement, key).unwrap())
    }

    fn validated_artifacts(
        artifacts: BrokerAuthorizationArtifactsV1,
    ) -> ValidatedUntrustedAuthorizationArtifacts {
        let envelope = BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME.into(),
            body: vec![1],
            authorization: Some(artifacts).into(),
            ..Default::default()
        };
        decode_request_envelope(&envelope.encode_to_vec(), ProtocolId::HostBroker, 0)
            .unwrap()
            .authorization()
            .unwrap()
            .clone()
    }

    fn runtime_request() -> Vec<u8> {
        let fixture = AdmissionFixture::new();
        let mut request = ApplyRuntimeRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 1;
        header.protocol_minor = 0;
        header.request_id = vec![103; 16];
        header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 1_000;
        header.maximum_response_bytes = 4_096;
        let fence = request.fence.get_or_insert_default();
        fence.sandbox_id = vec![104; 16];
        fence.incarnation_id = vec![105; 16];
        fence.assignment_epoch = 1;
        fence.desired_generation = 1;
        fence.assignment_digest = vec![106; 32];
        request.action = RuntimeAction::RUNTIME_ACTION_LAUNCH.into();
        let plan = request.launch_plan.get_or_insert_default();
        let root = plan.root_image.get_or_insert_default();
        root.media_type = "application/vnd.aos.sandbox.view.v1+cbor".to_owned();
        root.sha256 = vec![107; 32];
        root.encoded_size = 10;
        plan.workspace_handle = vec![108; 32];
        plan.network_handle = vec![109; 32];
        plan.attachment_anchor_handle = vec![110; 32];
        plan.uid_range_start = 65_536;
        plan.uid_range_size = 65_536;
        plan.limits = vec![
            ResourceLimit {
                dimension: 2,
                value: 128,
                ..Default::default()
            },
            ResourceLimit {
                dimension: 3,
                value: 1 << 30,
                ..Default::default()
            },
            ResourceLimit {
                dimension: 4,
                value: 100,
                ..Default::default()
            },
            ResourceLimit {
                dimension: 9,
                value: 1_024,
                ..Default::default()
            },
        ];
        plan.required_features.push(Feature {
            namespace: "aos.sandbox.runtime.linux-systemd".to_owned(),
            major: 1,
            minor: 0,
            ..Default::default()
        });
        let assignment = BrokerAssignment::new(
            SandboxId::from_bytes([104; 16]),
            IncarnationId::from_bytes([105; 16]),
            AssignmentEpoch::new(1),
            DesiredGeneration::new(1),
            ObjectDigest::from_bytes([106; 32]),
        )
        .unwrap();
        let lease = OwnershipLease::new(
            LeaseAssignment::new(
                assignment.sandbox(),
                assignment.incarnation(),
                assignment.epoch(),
                assignment.digest(),
            )
            .unwrap(),
            NodeId::from_bytes([31; 16]),
            1,
            100,
            300,
            10,
            [1; 16],
        )
        .unwrap();
        let ownership_lease = encode_ownership_lease(&lease);
        let lease_digest = descriptor_for_bytes(
            MediaType::new(PortableMediaType::OwnershipLease.as_str().to_owned()).unwrap(),
            &ownership_lease,
        )
        .digest();
        let binding = GuardianPlanBinding::new(
            assignment,
            NodeId::from_bytes([31; 16]),
            test_clock().host_boot_id(),
            1,
            lease_digest,
        )
        .unwrap();
        let guardian_plan = BrokerAuthorizationPlan::new(
            BrokerAudience::Guardian,
            ProtocolId::Guardian,
            ProtocolVersion::new(1, 0),
            assignment,
            NodeId::from_bytes([31; 16]),
            fixture.lease_signer.clone(),
            vec![
                BrokerGrant::new(
                    BrokerVerb::GuardianArm,
                    BrokerGrantTarget::Assignment,
                    binding.commitment(),
                    binding.encoded_len(),
                    4,
                )
                .unwrap(),
            ],
            ObjectDigest::from_bytes([111; 32]),
            fixture.revocation_scope,
            100,
            300,
            Vec::new(),
        )
        .unwrap();
        let broker_plan = encode_broker_authorization_plan(&guardian_plan);
        let broker_plan_signature = signed_object(
            &broker_plan,
            PortableMediaType::BrokerAuthorizationPlan,
            fixture.plan_scope,
            fixture.plan_signer.clone(),
            SignaturePurpose::BrokerAuthorization,
            &fixture.plan_policy_descriptor,
            &fixture.plan_key,
            300,
        );
        request.guardian_arm = Some(GuardianArmCompanionV1 {
            broker_plan,
            broker_plan_signature,
            ..Default::default()
        })
        .into();
        request.encode_to_vec()
    }

    fn guardian_request_record() -> RequestRecord {
        let request_id = [51; 16];
        let request_digest = [52; 32];
        let fence = DurableFence {
            witness_request_id: request_id,
            sandbox_id: [53; 16],
            incarnation_id: [54; 16],
            assignment_epoch: 55,
            desired_generation: 56,
            assignment_digest: [57; 32],
            authorization: vec![58],
        };
        let execution = DurableExecution::guardian_fixture(ExecutionContext {
            action: HostAction::Launch,
            request_id,
            request_digest,
            sandbox_id: fence.sandbox_id,
            incarnation_id: fence.incarnation_id,
            assignment_epoch: fence.assignment_epoch,
            desired_generation: fence.desired_generation,
            assignment_digest: fence.assignment_digest,
            receipt_present: false,
        });
        RequestRecord {
            request_id,
            request_digest,
            fence,
            action: 1,
            execution,
            execution_authentication: Vec::new(),
            effect: vec![59],
            receipt: None,
        }
    }

    fn stable_fields() -> StableAuthorityFields {
        StableAuthorityFields {
            transport_request_digest: [61; 32],
            semantic_request_digest: [62; 32],
            verb: 1,
            target: vec![1],
            sandbox_id: [63; 16],
            incarnation_id: [64; 16],
            assignment_epoch: 65,
            desired_generation: 66,
            assignment_digest: [67; 32],
            node_id: [68; 16],
            plan_digest: [69; 32],
            ownership_stable_key_id: b"ownership-key".to_vec(),
            ownership_generation: 70,
            ownership_public_key_sha256: [71; 32],
            ownership_usage: 2,
        }
    }

    fn admitted_records(
        fixture: &AdmissionFixture,
        authority: &HostAuthorityV1,
        request_bytes: &[u8],
        lease_generation: u64,
        plan_expires_seconds: i64,
        prior_fence: Option<&[u8]>,
    ) -> VerifiedBrokerAdmission {
        let request = decode_runtime_request(
            request_bytes,
            test_peer(),
            test_policy(),
            TEST_BOOTTIME_NANOSECONDS,
        )
        .unwrap();
        let artifacts = fixture.artifacts(request_bytes, lease_generation, plan_expires_seconds);
        authority
            .admit(
                &artifacts,
                &request,
                request_bytes,
                ProtocolVersion::new(1, 0),
                &test_clock(),
                prior_fence,
            )
            .unwrap()
    }

    fn authenticated_guardian_state(
        fixture: &AdmissionFixture,
        authority: &HostAuthorityV1,
        request_bytes: &[u8],
    ) -> HostState {
        let request = decode_runtime_request(
            request_bytes,
            test_peer(),
            test_policy(),
            TEST_BOOTTIME_NANOSECONDS,
        )
        .unwrap();
        let request_id = *request.header().request_id();
        let request_digest: [u8; 32] = Sha256::digest(request_bytes).into();
        let admitted = admitted_records(fixture, authority, request_bytes, 1, 300, None);
        let sealed_fence = authority
            .seal_fence(request.fence().sandbox_id(), &admitted.fence)
            .unwrap();
        let sealed_effect = authority
            .seal_effect(&request_id, &admitted.effect)
            .unwrap();
        let context = ExecutionContext {
            action: HostAction::Launch,
            request_id,
            request_digest,
            sandbox_id: *request.fence().sandbox_id(),
            incarnation_id: *request.fence().incarnation_id(),
            assignment_epoch: request.fence().assignment_epoch(),
            desired_generation: request.fence().desired_generation(),
            assignment_digest: *request.fence().assignment_digest(),
            receipt_present: false,
        };
        let execution = DurableExecution::guardian_fixture(context);
        let mut state = HostState::default();
        assert_eq!(
            state
                .admit_guardian(
                    request.fence(),
                    request_id,
                    request_digest,
                    execution,
                    sealed_fence,
                    &admitted,
                    sealed_effect,
                    authority,
                )
                .unwrap(),
            Admission::New
        );
        state
    }

    fn runtime_proof() -> transition::RuntimeProofSnapshot {
        transition::RuntimeProofSnapshot {
            host_boot_id: [111; 16],
            supervisor: transition::ProcessProofSnapshot {
                pid: 112,
                thread_group_id: 112,
                parent_pid: 1,
                cgroup_id: 113,
                start_time_ticks: 114,
            },
            payload: transition::ProcessProofSnapshot {
                pid: 115,
                thread_group_id: 115,
                parent_pid: 112,
                cgroup_id: 116,
                start_time_ticks: 117,
            },
            supervisor_cgroup_id: 113,
            payload_cgroup_id: 116,
            workspace_mount_id: 118,
            payload_root_mount_id: 119,
            network_namespace: transition::NamespaceProofSnapshot {
                device: 120,
                inode: 121,
            },
            mount_namespace: transition::NamespaceProofSnapshot {
                device: 122,
                inode: 123,
            },
            user_namespace: transition::NamespaceProofSnapshot {
                device: 124,
                inode: 125,
            },
        }
    }

    fn guardian_request(request_id: u8) -> Vec<u8> {
        let mut request = ApplyRuntimeRequest::decode_from_slice(&runtime_request()).unwrap();
        request.header.get_or_insert_default().request_id = vec![request_id; 16];
        request.encode_to_vec()
    }

    fn lifecycle_request(
        request_id: u8,
        action: RuntimeAction,
        incarnation_id: [u8; 16],
        assignment_epoch: u64,
        desired_generation: u64,
        assignment_digest: [u8; 32],
    ) -> Vec<u8> {
        let mut request = ApplyRuntimeRequest::decode_from_slice(&runtime_request()).unwrap();
        request.header.get_or_insert_default().request_id = vec![request_id; 16];
        let fence = request.fence.get_or_insert_default();
        fence.incarnation_id = incarnation_id.to_vec();
        fence.assignment_epoch = assignment_epoch;
        fence.desired_generation = desired_generation;
        fence.assignment_digest = assignment_digest.to_vec();
        request.action = action.into();
        request.launch_plan = None.into();
        request.guardian_arm = None.into();
        request.encode_to_vec()
    }

    fn append_completed_guardian(
        state: &mut HostState,
        fixture: &AdmissionFixture,
        authority: &HostAuthorityV1,
        request_bytes: &[u8],
    ) {
        let request = decode_runtime_request(
            request_bytes,
            test_peer(),
            test_policy(),
            TEST_BOOTTIME_NANOSECONDS,
        )
        .unwrap();
        let request_id = *request.header().request_id();
        let request_digest: [u8; 32] = Sha256::digest(request_bytes).into();
        let prior_fence = state
            .prior_authorization(request.fence().sandbox_id())
            .map(<[u8]>::to_vec);
        let admitted = admitted_records(
            fixture,
            authority,
            request_bytes,
            1,
            300,
            prior_fence.as_deref(),
        );
        let context = ExecutionContext {
            action: HostAction::Launch,
            request_id,
            request_digest,
            sandbox_id: *request.fence().sandbox_id(),
            incarnation_id: *request.fence().incarnation_id(),
            assignment_epoch: request.fence().assignment_epoch(),
            desired_generation: request.fence().desired_generation(),
            assignment_digest: *request.fence().assignment_digest(),
            receipt_present: false,
        };
        let execution = DurableExecution::guardian_fixture(context);
        let sealed_fence = authority
            .seal_fence(request.fence().sandbox_id(), &admitted.fence)
            .unwrap();
        let sealed_effect = authority
            .seal_effect(&request_id, &admitted.effect)
            .unwrap();
        state
            .admit_guardian(
                request.fence(),
                request_id,
                request_digest,
                execution,
                sealed_fence,
                &admitted,
                sealed_effect,
                authority,
            )
            .unwrap();

        let receipt = vec![request_id[0]];
        let completed_effect = admitted.effect.complete(receipt.clone()).unwrap();
        let record = state.requests.get_mut(&request_id).unwrap();
        let DurableExecution::GuardianLaunch(launch) = &mut record.execution else {
            panic!("Guardian admission retained the wrong execution kind");
        };
        launch.phase = transition::GuardianLaunchPhase::Complete {
            guardian_invocation: [126; 16],
            payload_invocation: [127; 16],
            observation_sequence: 1,
            worker_proof: runtime_proof(),
        };
        record.effect = authority
            .seal_effect(&request_id, &completed_effect)
            .unwrap();
        record.receipt = Some(receipt);
        let stable = stable_authority_digest(&completed_effect, &admitted.fence).unwrap();
        let digest = record
            .execution
            .authentication_digest(execution_context(record).unwrap(), stable)
            .unwrap();
        record.execution_authentication = authority
            .seal_execution_record(&request_id, &digest)
            .unwrap();
    }

    fn append_lifecycle(
        state: &mut HostState,
        fixture: &AdmissionFixture,
        authority: &HostAuthorityV1,
        request_bytes: &[u8],
        action: HostAction,
        complete: bool,
    ) {
        let request = decode_runtime_request(
            request_bytes,
            test_peer(),
            test_policy(),
            TEST_BOOTTIME_NANOSECONDS,
        )
        .unwrap();
        let request_id = *request.header().request_id();
        let request_digest: [u8; 32] = Sha256::digest(request_bytes).into();
        let prior_fence = state
            .prior_authorization(request.fence().sandbox_id())
            .map(<[u8]>::to_vec);
        let admitted = admitted_records(
            fixture,
            authority,
            request_bytes,
            1,
            300,
            prior_fence.as_deref(),
        );
        let sealed_fence = authority
            .seal_fence(request.fence().sandbox_id(), &admitted.fence)
            .unwrap();
        let sealed_effect = authority
            .seal_effect(&request_id, &admitted.effect)
            .unwrap();
        state
            .admit(
                request.fence(),
                request_id,
                request_digest,
                action.code(),
                sealed_fence,
                &admitted,
                sealed_effect,
                authority,
            )
            .unwrap();
        if !complete {
            return;
        }
        let receipt = vec![request_id[0]];
        let completed_effect = admitted.effect.complete(receipt.clone()).unwrap();
        let sealed_effect = authority
            .seal_effect(&request_id, &completed_effect)
            .unwrap();
        state
            .complete(request_id, request_digest, sealed_effect, receipt)
            .unwrap();
    }

    fn append_completed_lifecycle(
        state: &mut HostState,
        fixture: &AdmissionFixture,
        authority: &HostAuthorityV1,
        request_bytes: &[u8],
        action: HostAction,
    ) {
        append_lifecycle(state, fixture, authority, request_bytes, action, true);
    }

    fn append_guardian_composite_stop(
        state: &mut HostState,
        fixture: &AdmissionFixture,
        authority: &HostAuthorityV1,
        request_bytes: &[u8],
        lineage: CompletedGuardianLineage,
        payload_invocation: [u8; 16],
        guardian_invocation: [u8; 16],
    ) {
        let request = decode_runtime_request(
            request_bytes,
            test_peer(),
            test_policy(),
            TEST_BOOTTIME_NANOSECONDS,
        )
        .unwrap();
        let request_id = *request.header().request_id();
        let request_digest: [u8; 32] = Sha256::digest(request_bytes).into();
        let prior_fence = state
            .prior_authorization(request.fence().sandbox_id())
            .map(<[u8]>::to_vec);
        let admitted = admitted_records(
            fixture,
            authority,
            request_bytes,
            1,
            300,
            prior_fence.as_deref(),
        );
        let context = ExecutionContext {
            action: HostAction::Stop,
            request_id,
            request_digest,
            sandbox_id: *request.fence().sandbox_id(),
            incarnation_id: *request.fence().incarnation_id(),
            assignment_epoch: request.fence().assignment_epoch(),
            desired_generation: request.fence().desired_generation(),
            assignment_digest: *request.fence().assignment_digest(),
            receipt_present: false,
        };
        let target = transition::CompositeStopTarget::GuardianComposite {
            source_launch_request_id: lineage.source_request_id,
            incarnation_id: lineage.incarnation_id,
            launch_binding: lineage.binding,
            payload: transition::StopUnitTarget::Exact {
                binding: Some(lineage.binding),
                invocation: payload_invocation,
            },
            guardian: transition::StopUnitTarget::Exact {
                binding: Some(lineage.binding),
                invocation: guardian_invocation,
            },
        };
        let execution = DurableExecution::composite_stop(context, target).unwrap();
        let sealed_fence = authority
            .seal_fence(request.fence().sandbox_id(), &admitted.fence)
            .unwrap();
        let sealed_effect = authority
            .seal_effect(&request_id, &admitted.effect)
            .unwrap();
        state
            .admit_composite_stop(
                request.fence(),
                request_id,
                request_digest,
                execution,
                sealed_fence,
                &admitted,
                sealed_effect,
                authority,
            )
            .unwrap();
    }

    fn replace_outer_authorization(
        state: &mut HostState,
        authority: &HostAuthorityV1,
        admitted: &VerifiedBrokerAdmission,
        replace_fence: bool,
        replace_effect: bool,
    ) {
        let request_id = *admitted.effect.request_id();
        let sandbox_id = *admitted.fence.assignment().sandbox().as_bytes();
        if replace_fence {
            let sealed = authority.seal_fence(&sandbox_id, &admitted.fence).unwrap();
            state
                .requests
                .get_mut(&request_id)
                .unwrap()
                .fence
                .authorization = sealed.clone();
            state.fences.get_mut(&sandbox_id).unwrap().authorization = sealed;
        }
        if replace_effect {
            state.requests.get_mut(&request_id).unwrap().effect = authority
                .seal_effect(&request_id, &admitted.effect)
                .unwrap();
        }
    }

    #[test]
    fn empty_state_round_trips_and_checksum_corruption_fails() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = FileHostStateStore::open(directory.path()).unwrap();
        store.commit(&HostState::default()).unwrap();
        assert!(store.load().is_ok());

        let path = directory.path().join("state.bin");
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(store.load().is_err());
    }

    #[test]
    fn public_state_directory_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(FileHostStateStore::open(directory.path()).is_err());
    }

    #[test]
    fn unknown_state_versions_fail_closed() {
        let current = serde_json::json!({
            "fences": [],
            "requests": [],
            "observation_sequences": [{"incarnation_id": vec![7; 16], "sequence": 9}]
        });
        let body = serde_json::to_vec(&current).unwrap();
        let decoded = decode_envelope(&envelope_with_version(VERSION, &body)).unwrap();
        assert_eq!(decoded.observation_sequences.get(&[7; 16]), Some(&9));

        for version in [0, 2, 4, u32::MAX] {
            assert!(decode_envelope(&envelope_with_version(version, &body)).is_err());
        }
    }

    #[test]
    fn query_effect_is_exact_and_does_not_mutate_state() {
        let request_id = [1; 16];
        let request_digest = [2; 32];
        let mut state = HostState::default();
        state.requests.insert(
            request_id,
            RequestRecord {
                request_id,
                request_digest,
                fence: DurableFence {
                    witness_request_id: request_id,
                    sandbox_id: [3; 16],
                    incarnation_id: [4; 16],
                    assignment_epoch: 5,
                    desired_generation: 6,
                    assignment_digest: [7; 32],
                    authorization: vec![8],
                },
                action: HostAction::Freeze.code(),
                execution: DurableExecution::DirectLifecycle,
                execution_authentication: vec![9],
                effect: vec![9],
                receipt: None,
            },
        );
        let before = state.clone();
        assert_eq!(
            state.query_effect(&request_id, request_digest).unwrap(),
            RuntimeEffectQuery::Pending
        );
        assert!(state.query_effect(&request_id, [10; 32]).is_err());
        assert_eq!(
            state.query_effect(&[11; 16], [12; 32]).unwrap(),
            RuntimeEffectQuery::Absent
        );
        assert_eq!(state, before);

        state.requests.get_mut(&request_id).unwrap().receipt = Some(vec![13, 14]);
        assert_eq!(
            state.query_effect(&request_id, request_digest).unwrap(),
            RuntimeEffectQuery::Complete(vec![13, 14])
        );
    }

    #[test]
    fn stable_authority_digest_binds_every_refresh_invariant() {
        let baseline = stable_fields();
        let expected = baseline.digest().unwrap();

        macro_rules! assert_bound {
            ($field:ident, $value:expr) => {{
                let mut changed = baseline.clone();
                changed.$field = $value;
                assert_ne!(changed.digest().unwrap(), expected, stringify!($field));
            }};
        }

        assert_bound!(transport_request_digest, [72; 32]);
        assert_bound!(semantic_request_digest, [73; 32]);
        assert_bound!(verb, 2);
        assert_bound!(target, vec![2; 33]);
        assert_bound!(sandbox_id, [74; 16]);
        assert_bound!(incarnation_id, [75; 16]);
        assert_bound!(assignment_epoch, 76);
        assert_bound!(desired_generation, 77);
        assert_bound!(assignment_digest, [78; 32]);
        assert_bound!(node_id, [79; 16]);
        assert_bound!(plan_digest, [80; 32]);
        assert_bound!(ownership_stable_key_id, b"other-key".to_vec());
        assert_bound!(ownership_generation, 81);
        assert_bound!(ownership_public_key_sha256, [82; 32]);
        assert_bound!(ownership_usage, 3);
    }

    #[test]
    fn guardian_execution_requires_exact_authentication_on_the_live_path() {
        let authority = authority();
        let stable_authority = stable_fields().digest().unwrap();
        let mut request = guardian_request_record();

        assert!(validate_request(&request).is_err());

        let digest = request
            .execution
            .authentication_digest(execution_context(&request).unwrap(), stable_authority)
            .unwrap();
        request.execution_authentication = authority
            .seal_execution_record(&request.request_id, &digest)
            .unwrap();
        validate_request(&request).unwrap();
        validate_execution_authentication(&authority, &request, stable_authority).unwrap();

        ensure_live_execution_enabled(&request.execution).unwrap();

        let mut changed_phase = request.clone();
        let DurableExecution::GuardianLaunch(record) = &mut changed_phase.execution else {
            panic!("Guardian fixture has the wrong execution kind");
        };
        record.phase = transition::GuardianLaunchPhase::GuardianStartIssued;
        assert!(
            validate_execution_authentication(&authority, &changed_phase, stable_authority)
                .is_err()
        );

        let mut relocated = request.clone();
        relocated.request_id[0] ^= 1;
        assert!(
            validate_execution_authentication(&authority, &relocated, stable_authority).is_err()
        );

        let mut tampered = request;
        tampered.execution_authentication[0] ^= 1;
        assert!(
            validate_execution_authentication(&authority, &tampered, stable_authority).is_err()
        );
    }

    #[test]
    fn recovered_guardian_execution_authenticates_outer_refresh_on_the_live_path() {
        let fixture = AdmissionFixture::new();
        let authority = fixture.authority();
        let request_bytes = runtime_request();
        let request_id = [103; 16];
        let state = authenticated_guardian_state(&fixture, &authority, &request_bytes);

        state.validate_authenticated(&authority).unwrap();

        let mut missing = state.clone();
        missing
            .requests
            .get_mut(&request_id)
            .unwrap()
            .execution_authentication = Vec::new();
        assert!(missing.validate_authenticated(&authority).is_err());
        assert!(HostState::decode(&missing.encode().unwrap()).is_err());

        let mut oversized = state.clone();
        oversized
            .requests
            .get_mut(&request_id)
            .unwrap()
            .execution_authentication = vec![1; MAXIMUM_EXECUTION_AUTHENTICATION_BYTES + 1];
        assert!(HostState::decode(&oversized.encode().unwrap()).is_err());

        let prior_fence = state.request_authorization(&request_id).unwrap().to_vec();
        let renewed = admitted_records(
            &fixture,
            &authority,
            &request_bytes,
            2,
            300,
            Some(&prior_fence),
        );
        let initial_effect = authority
            .open_effect(&request_id, state.effect(&request_id).unwrap())
            .unwrap();
        let initial_fence = authority
            .open_fence(
                &[104; 16],
                state.request_authorization(&request_id).unwrap(),
            )
            .unwrap();
        assert_eq!(
            stable_authority_digest(&initial_effect, &initial_fence).unwrap(),
            stable_authority_digest(&renewed.effect, &renewed.fence).unwrap()
        );
        assert_ne!(
            initial_effect.local_lease_record(),
            renewed.effect.local_lease_record()
        );

        let retained_execution_authentication = state
            .requests
            .get(&request_id)
            .unwrap()
            .execution_authentication
            .clone();
        let mut refreshed = state.clone();
        replace_outer_authorization(&mut refreshed, &authority, &renewed, true, true);
        assert_eq!(
            refreshed
                .requests
                .get(&request_id)
                .unwrap()
                .execution_authentication,
            retained_execution_authentication
        );
        let refreshed = HostState::decode(&refreshed.encode().unwrap()).unwrap();
        refreshed.validate_authenticated(&authority).unwrap();

        let mut mismatched_lease = state.clone();
        replace_outer_authorization(&mut mismatched_lease, &authority, &renewed, false, true);
        let mismatch_error = mismatched_lease
            .validate_authenticated(&authority)
            .unwrap_err()
            .to_string();
        assert!(mismatch_error.contains("different authorization state"));

        let changed_plan = admitted_records(&fixture, &authority, &request_bytes, 1, 299, None);
        assert_ne!(
            stable_authority_digest(&initial_effect, &initial_fence).unwrap(),
            stable_authority_digest(&changed_plan.effect, &changed_plan.fence).unwrap()
        );
        let mut changed_stable_authority = state.clone();
        replace_outer_authorization(
            &mut changed_stable_authority,
            &authority,
            &changed_plan,
            true,
            true,
        );
        let changed_error = changed_stable_authority
            .validate_authenticated(&authority)
            .unwrap_err()
            .to_string();
        assert!(changed_error.contains("authentication contradicts"));

        let mut changed_status = state;
        let complete_effect = initial_effect.complete(vec![110]).unwrap();
        changed_status.requests.get_mut(&request_id).unwrap().effect = authority
            .seal_effect(&request_id, &complete_effect)
            .unwrap();
        let status_error = changed_status
            .validate_authenticated(&authority)
            .unwrap_err()
            .to_string();
        assert!(status_error.contains("status contradicts its receipt"));
    }

    #[test]
    fn completed_guardian_lineage_survives_freeze_thaw_and_reopen() {
        let fixture = AdmissionFixture::new();
        let authority = fixture.authority();
        let mut state = HostState::default();
        append_completed_guardian(&mut state, &fixture, &authority, &guardian_request(103));

        let freeze = lifecycle_request(
            104,
            RuntimeAction::RUNTIME_ACTION_FREEZE,
            [105; 16],
            1,
            2,
            [107; 32],
        );
        append_completed_lifecycle(
            &mut state,
            &fixture,
            &authority,
            &freeze,
            HostAction::Freeze,
        );
        let GuardianLineage::Complete(frozen) = state
            .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
            .unwrap()
        else {
            panic!("completed Guardian launch was not classified as current");
        };
        assert_eq!(frozen.source_request_id, [103; 16]);
        assert_eq!(frozen.guardian_invocation, [126; 16]);
        assert_eq!(frozen.payload_invocation, [127; 16]);
        assert_eq!(frozen.worker_proof, runtime_proof());

        let mut reopened = HostState::decode(&state.encode().unwrap()).unwrap();
        let thaw = lifecycle_request(
            105,
            RuntimeAction::RUNTIME_ACTION_THAW,
            [105; 16],
            1,
            3,
            [108; 32],
        );
        append_completed_lifecycle(&mut reopened, &fixture, &authority, &thaw, HostAction::Thaw);
        let GuardianLineage::Complete(thawed) = reopened
            .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
            .unwrap()
        else {
            panic!("completed same-epoch Thaw did not preserve Guardian lineage");
        };
        assert_eq!(thawed, frozen);

        let reopened = HostState::decode(&reopened.encode().unwrap()).unwrap();
        assert_eq!(
            reopened
                .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
                .unwrap(),
            GuardianLineage::Complete(frozen)
        );
    }

    #[test]
    fn pending_terminal_and_replacement_fences_shadow_guardian_lineage() {
        let fixture = AdmissionFixture::new();
        let authority = fixture.authority();

        let mut pending = HostState::default();
        append_completed_guardian(&mut pending, &fixture, &authority, &guardian_request(103));
        let freeze = lifecycle_request(
            104,
            RuntimeAction::RUNTIME_ACTION_FREEZE,
            [105; 16],
            1,
            2,
            [107; 32],
        );
        // Scope callers classify authenticated history before any retained-pin
        // fast path, so the pending successor cannot export the old launch.
        append_lifecycle(
            &mut pending,
            &fixture,
            &authority,
            &freeze,
            HostAction::Freeze,
            false,
        );
        assert_eq!(
            pending
                .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
                .unwrap(),
            GuardianLineage::Shadowed
        );

        let mut killed = HostState::default();
        append_completed_guardian(&mut killed, &fixture, &authority, &guardian_request(103));
        let terminal = lifecycle_request(
            105,
            RuntimeAction::RUNTIME_ACTION_KILL,
            [105; 16],
            1,
            2,
            [107; 32],
        );
        append_completed_lifecycle(
            &mut killed,
            &fixture,
            &authority,
            &terminal,
            HostAction::Kill,
        );
        assert_eq!(
            killed
                .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
                .unwrap(),
            GuardianLineage::Shadowed
        );

        let mut replacement = HostState::default();
        append_completed_guardian(
            &mut replacement,
            &fixture,
            &authority,
            &guardian_request(103),
        );
        let freeze = lifecycle_request(
            106,
            RuntimeAction::RUNTIME_ACTION_FREEZE,
            [130; 16],
            2,
            1,
            [131; 32],
        );
        append_completed_lifecycle(
            &mut replacement,
            &fixture,
            &authority,
            &freeze,
            HostAction::Freeze,
        );
        assert_eq!(
            replacement
                .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
                .unwrap(),
            GuardianLineage::Shadowed
        );
        assert_eq!(
            replacement
                .completed_guardian_lineage(&[104; 16], &[130; 16], &authority)
                .unwrap(),
            GuardianLineage::Absent
        );
    }

    #[test]
    fn higher_assignment_epoch_shadows_guardian_lineage_across_reopen_and_lifecycle() {
        let fixture = AdmissionFixture::new();
        let authority = fixture.authority();
        let mut state = HostState::default();
        append_completed_guardian(&mut state, &fixture, &authority, &guardian_request(103));

        let freeze = lifecycle_request(
            104,
            RuntimeAction::RUNTIME_ACTION_FREEZE,
            [105; 16],
            2,
            1,
            [107; 32],
        );
        append_completed_lifecycle(
            &mut state,
            &fixture,
            &authority,
            &freeze,
            HostAction::Freeze,
        );
        assert_eq!(
            state
                .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
                .unwrap(),
            GuardianLineage::Shadowed
        );

        let mut reopened = HostState::decode(&state.encode().unwrap()).unwrap();
        assert_eq!(
            reopened
                .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
                .unwrap(),
            GuardianLineage::Shadowed
        );
        let thaw = lifecycle_request(
            105,
            RuntimeAction::RUNTIME_ACTION_THAW,
            [105; 16],
            2,
            2,
            [108; 32],
        );
        append_completed_lifecycle(&mut reopened, &fixture, &authority, &thaw, HostAction::Thaw);
        assert_eq!(
            reopened
                .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
                .unwrap(),
            GuardianLineage::Shadowed
        );

        let reopened = HostState::decode(&reopened.encode().unwrap()).unwrap();
        assert_eq!(
            reopened
                .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
                .unwrap(),
            GuardianLineage::Shadowed
        );
    }

    #[test]
    fn guardian_composite_stop_links_require_epoch_and_exact_invocations() {
        let fixture = AdmissionFixture::new();
        let authority = fixture.authority();

        let mut wrong_invocation = HostState::default();
        append_completed_guardian(
            &mut wrong_invocation,
            &fixture,
            &authority,
            &guardian_request(103),
        );
        let GuardianLineage::Complete(lineage) = wrong_invocation
            .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
            .unwrap()
        else {
            panic!("completed Guardian launch lost its lineage");
        };
        let stop = lifecycle_request(
            104,
            RuntimeAction::RUNTIME_ACTION_STOP,
            [105; 16],
            1,
            2,
            [107; 32],
        );
        append_guardian_composite_stop(
            &mut wrong_invocation,
            &fixture,
            &authority,
            &stop,
            lineage,
            [128; 16],
            lineage.guardian_invocation,
        );
        assert!(
            wrong_invocation
                .validate_authenticated(&authority)
                .unwrap_err()
                .to_string()
                .contains("target contradicts its completed Guardian launch")
        );

        let mut wrong_guardian_invocation = HostState::default();
        append_completed_guardian(
            &mut wrong_guardian_invocation,
            &fixture,
            &authority,
            &guardian_request(103),
        );
        let GuardianLineage::Complete(lineage) = wrong_guardian_invocation
            .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
            .unwrap()
        else {
            panic!("completed Guardian launch lost its lineage");
        };
        append_guardian_composite_stop(
            &mut wrong_guardian_invocation,
            &fixture,
            &authority,
            &stop,
            lineage,
            lineage.payload_invocation,
            [129; 16],
        );
        assert!(
            wrong_guardian_invocation
                .validate_authenticated(&authority)
                .unwrap_err()
                .to_string()
                .contains("target contradicts its completed Guardian launch")
        );

        let mut wrong_epoch = HostState::default();
        append_completed_guardian(
            &mut wrong_epoch,
            &fixture,
            &authority,
            &guardian_request(103),
        );
        let GuardianLineage::Complete(lineage) = wrong_epoch
            .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
            .unwrap()
        else {
            panic!("completed Guardian launch lost its lineage");
        };
        let stop = lifecycle_request(
            104,
            RuntimeAction::RUNTIME_ACTION_STOP,
            [105; 16],
            2,
            1,
            [107; 32],
        );
        append_guardian_composite_stop(
            &mut wrong_epoch,
            &fixture,
            &authority,
            &stop,
            lineage,
            lineage.payload_invocation,
            lineage.guardian_invocation,
        );
        let error = HostState::decode(&wrong_epoch.encode().unwrap())
            .unwrap_err()
            .to_string();
        assert!(error.contains("source contradicts its retained assignment"));
    }

    #[test]
    fn malformed_ambiguous_and_tampered_guardian_lineage_fails_closed() {
        let fixture = AdmissionFixture::new();
        let authority = fixture.authority();
        let mut state = HostState::default();
        append_completed_guardian(&mut state, &fixture, &authority, &guardian_request(103));

        let mut malformed = state.clone();
        let DurableExecution::GuardianLaunch(record) =
            &mut malformed.requests.get_mut(&[103; 16]).unwrap().execution
        else {
            panic!("Guardian fixture has the wrong execution kind");
        };
        let transition::GuardianLaunchPhase::Complete {
            guardian_invocation,
            ..
        } = &mut record.phase
        else {
            panic!("Guardian fixture is not complete");
        };
        *guardian_invocation = [0; 16];
        assert!(
            malformed
                .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
                .is_err()
        );

        let mut tampered = state.clone();
        let DurableExecution::GuardianLaunch(record) =
            &mut tampered.requests.get_mut(&[103; 16]).unwrap().execution
        else {
            panic!("Guardian fixture has the wrong execution kind");
        };
        let transition::GuardianLaunchPhase::Complete { worker_proof, .. } = &mut record.phase
        else {
            panic!("Guardian fixture is not complete");
        };
        worker_proof.host_boot_id[0] ^= 1;
        assert!(
            tampered
                .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
                .unwrap_err()
                .to_string()
                .contains("authentication contradicts")
        );

        append_completed_guardian(&mut state, &fixture, &authority, &guardian_request(104));
        assert!(
            state
                .completed_guardian_lineage(&[104; 16], &[105; 16], &authority)
                .unwrap_err()
                .to_string()
                .contains("ambiguous completed Guardian launch lineage")
        );
    }

    #[test]
    fn final_schema_reopen_accepts_exact_outer_lease_refresh() {
        let fixture = AdmissionFixture::new();
        let authority = fixture.authority();
        let request_bytes = runtime_request();
        let request_id = [103; 16];
        let state = authenticated_guardian_state(&fixture, &authority, &request_bytes);
        let state = HostState::decode(&state.encode().unwrap()).unwrap();
        state.validate_authenticated(&authority).unwrap();
        let prior_fence = state.request_authorization(&request_id).unwrap().to_vec();
        let renewed = admitted_records(
            &fixture,
            &authority,
            &request_bytes,
            2,
            300,
            Some(&prior_fence),
        );
        let mut refreshed = state;
        replace_outer_authorization(&mut refreshed, &authority, &renewed, true, true);

        let reopened = HostState::decode(&refreshed.encode().unwrap()).unwrap();
        reopened.validate_authenticated(&authority).unwrap();
    }

    fn envelope_with_version(version: u32, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&version.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&Sha256::digest(body));
        bytes.extend_from_slice(body);
        bytes
    }
}
