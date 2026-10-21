//! Recompiles current parentless Create inputs at Root's independent cut.
//!
//! The same paid Controller reader and Root policy journal supply current
//! publisher/signed heads. Fresh Source17 and independent Cache verification
//! stay live around the pure compiler. B remains complete comparison input.

use std::error::Error as StdError;
use std::mem::size_of;

use aos_sandbox_model::{
    CanonicalAssignmentManifestV1, ResourceDimension as D, ResourceVector,
};
use aos_sandbox_model::model::{Policy, SandboxSpec};
use aos_sandbox_policy::{
    CompiledPolicyCandidateV1, PolicyCompilerInputV1,
};
use aos_sandbox_protocol::policy_data::RetainedPublisherCompilerOriginV3;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    ready::ReadyBundleDataV1,
    source_current::SourceCurrentReplyFieldsV1,
    cache_held::current_proof::CacheCurrentProofBodyDataV1,
};

use crate::journal::{Journal, JournalError};
use crate::policy_compiler::create_q04::Q04CutIdentityV1;
use crate::policy_compiler::public_create_source::{
    CurrentCreateProjectPolicySourceV1, current_parentless_create_project_source_v1,
};
use crate::policy_compiler::root_signed_sources::RootSignedProjectSourcesV1;
use super::super::policy_inputs::RootCurrentPolicyInputDataV1;

type Error = Box<dyn StdError>;

#[derive(Debug, thiserror::Error)]
#[error("the current Root Create compiler input or complete assignment changed")]
struct Changed;

#[derive(Default)]
pub(super) struct RootCurrentCompiledPolicyV1 {
    result: Option<Result<RootCurrentCompiledValuesV1, Error>>,
    entered: bool,
    closed: bool,
}

// These successful originals remain resident through the existing independent
// Root/Controller names, native-position, peer and paired-clock afterposts.
struct RootCurrentCompiledValuesV1 {
    source: CurrentCreateProjectPolicySourceV1,
    signed: RootSignedProjectSourcesV1,
    publisher: Policy,
    specification: SandboxSpec,
    input: PolicyCompilerInputV1,
    candidate: CompiledPolicyCandidateV1,
    origin: RetainedPublisherCompilerOriginV3,
    publisher_expires_at: i64,
}

impl RootCurrentCompiledPolicyV1 {
    pub(super) fn observe_once(
        &mut self,
        controller: &mut Journal,
        root_policy: aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1<'_>,
        policy_data: &RootCurrentPolicyInputDataV1<'_>,
        source_current: SourceCurrentReplyFieldsV1,
        cache_current: &CacheCurrentProofBodyDataV1,
        bundle: ReadyBundleDataV1<'_>,
        parent: &Q04CutIdentityV1,
        assignment: &CanonicalAssignmentManifestV1,
        now: i64,
    ) {
        if self.entered {
            self.closed = true;
            return;
        }
        self.entered = true;
        self.result = Some(compile_current(
            controller, root_policy, policy_data, source_current, cache_current,
            bundle, parent, assignment, now,
        ));
    }

    pub(super) fn require_complete(&self) -> Result<(), JournalError> {
        if !self.closed && matches!(self.result, Some(Ok(_))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(super) fn require_live_at_v1(&self, sample: aos_sandbox_model::RawPairedClockSample)
        -> Result<(), JournalError>
    {
        self.require_complete()?;
        let values = self.result.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        if sample.wall_seconds() >= values.signed.0.head().expires_at()
            || sample.wall_seconds() >= values.signed.1.expires_at()
            || sample.wall_seconds() >= values.publisher_expires_at
        { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    pub(super) fn expires_at_v1(&self) -> Result<i64, JournalError> {
        self.require_complete()?;
        let values = self.result.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok(values.publisher_expires_at.min(values.signed.0.head().expires_at())
            .min(values.signed.1.expires_at()))
    }

    pub(super) fn candidate_v1(&self) -> Result<&CompiledPolicyCandidateV1, JournalError> {
        self.require_complete()?;
        self.result.as_ref().and_then(|result| result.as_ref().ok())
            .map(|values| &values.candidate).ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.result.as_ref().and_then(|result| result.as_ref().err()).map(|error| error.as_ref())
    }

    pub(super) fn additional_receiving_demand_v1(actual_encoded_bytes: u64)
        -> Result<ResourceVector, JournalError>
    {
        let invalid = || JournalError::JournalTooLarge;
        // Four complete eight-MiB output objects may coexist with compiler
        // construction, full-origin comparison and retained derived output.
        // Existing schemas retain their original caps; no input supplies them.
        let output = (aos_sandbox_protocol::policy_data::MAXIMUM_CANONICAL_OBJECT_BYTES as u64)
            .checked_mul(4).and_then(|bytes| bytes.checked_mul(4)).ok_or_else(invalid)?;
        let bytes = actual_encoded_bytes.checked_mul(64)
            .and_then(|bytes| bytes.checked_add(output))
            .and_then(|bytes| u64::try_from(
                aos_sandbox_policy::root_policy_inputs_data::verification_return_control_bytes_v1()?,
            ).ok().and_then(|controls| bytes.checked_add(controls)))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<RootCurrentCompiledValuesV1>() as u64))
            .and_then(|bytes| bytes.checked_add(4096))
            .and_then(|bytes| bytes.checked_add(
                aos_sandbox_protocol::publisher_policy::current_create::
                    source_recipe_additional_control_bytes_v1()?,
            ))
            .ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OutputBytes, output))
    }
}

fn compile_current(
    controller: &mut Journal,
    root_policy: aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1<'_>,
    policy_data: &RootCurrentPolicyInputDataV1<'_>,
    source_current: SourceCurrentReplyFieldsV1,
    cache_current: &CacheCurrentProofBodyDataV1,
    bundle: ReadyBundleDataV1<'_>,
    parent: &Q04CutIdentityV1,
    assignment: &CanonicalAssignmentManifestV1,
    now: i64,
) -> Result<RootCurrentCompiledValuesV1, Error> {
    aos_sandbox_policy::compile_root_current_policy_data_v1!(
        inputs = (controller, root_policy, policy_data, source_current, cache_current,
            bundle, parent, assignment, now),
        values = RootCurrentCompiledValuesV1, verifier = RootCurrentInputVerifierV1,
        bindings = (source, signed),
        source = current_parentless_create_project_source_v1(controller,
            parent.operation(), parent.sandbox()),
        publisher_expiry = {
            let store = crate::publisher_admin::policy::PublisherPolicyStore::load(controller,
                crate::publisher_admin::policy::PublisherPolicyLimits::default())?;
            store.current_policy(source.project())?.ok_or(Changed)?.expires_at()
        },
        signed = policy_data.verify_current_sources_v1(root_policy, now)
            .map_err(crate::policy_compiler::root_signed_sources::RootSignedSourcesErrorV1::from),
        changed = Changed,
        preview_error = crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut,
        capacity_error = crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut,
        layer_error = [crate::policy_compiler::PolicyDeploymentHeadErrorV1::from],
        input_error = [crate::policy_compiler::public_create_source::CurrentCreateCompilerInputErrorV1::from]
    )
}

aos_sandbox_policy::define_root_current_input_verifier_v1!(
    RootCurrentInputVerifierV1, CurrentCreateProjectPolicySourceV1);
