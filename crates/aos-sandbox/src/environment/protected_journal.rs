//! Dormant protected-journal adapter for immutable environment generations.
//!
//! Records are ordered as generation state, lease/activation effect, current
//! publication, then checkpoint. This preserves pending-before-effect and
//! generation-before-current publication without wiring a Nix or mount service.

use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceId, Revision, SandboxId};

use crate::journal::{Journal, RecordNamespace};
use crate::lifecycle::protected_journal_adapter::{
    AppliedDomainTransactionV1, DomainCommitOutcomeV1, DomainOutcomeUnknownV1,
    DomainPostcommitCapabilityV1, DomainRecoveryV1, PreparedDomainTransactionV1,
    ProtectedDomainEnvelopeV1, ProtectedDomainJournalErrorV1, ProtectedDomainJournalV1,
    ProtectedDomainKeyV1, ProtectedDomainProjectionV1, ProtectedDomainReplayPhaseV1,
    ProtectedDomainReplayTransactionV1, ProtectedDomainSchemaV1, ProtectedDomainSnapshotV1,
    ProtectedRecordRoleV1, ProtectedReducerPhaseV1, ReplayedDomainPostcommitV1,
    ValidatedDomainPostcommitV1, encode_reducer_payload_with_validator,
};

use super::{
    EnvironmentActivationPhaseV1, EnvironmentActivationTransactionV1,
    EnvironmentGenerationHistoryV1, EnvironmentGenerationManifestV1,
    decode_environment_activation_v1, decode_environment_generation_v1,
    encode_environment_activation_v1, encode_environment_generation_v1,
};

/// Selects one closed environment journal family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum EnvironmentProtectedRecordKindV1 {
    /// Stores one immutable environment generation and closure commitment.
    Generation = 1,
    /// Stores a GC-root, execution-lease, or activation effect boundary.
    LeaseEffect = 2,
    /// Publishes the generation selected for future execution admission.
    Current = 3,
    /// Publishes a verified environment replay checkpoint without compaction authority.
    Checkpoint = 4,
    /// Stores one exact constrained-build transaction before an external effect.
    BuildEffect = 5,
    /// Publishes one protected-observed terminal constrained-build outcome.
    BuildTerminal = 6,
}

/// Defines the closed environment adapter schema.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EnvironmentProtectedJournalSchemaV1;

impl ProtectedDomainSchemaV1 for EnvironmentProtectedJournalSchemaV1 {
    type Kind = EnvironmentProtectedRecordKindV1;
    type ReplayValidator = EnvironmentGenerationHistoryV1;

    const MAGIC: [u8; 8] = *b"AOSEPJ01";
    const HASH_DOMAIN: &'static [u8] = b"aos.sandbox.environment.protected-journal.v1\0";
    const KEY_PREFIX: &'static [u8] = b"\0aos-environment-v1\0";
    const MAXIMUM_PAYLOAD_BYTES: usize = 96 * 1024 * 1024;

    fn kind_code(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn kind_from_code(code: u8) -> Option<Self::Kind> {
        match code {
            1 => Some(Self::Kind::Generation),
            2 => Some(Self::Kind::LeaseEffect),
            3 => Some(Self::Kind::Current),
            4 => Some(Self::Kind::Checkpoint),
            5 => Some(Self::Kind::BuildEffect),
            6 => Some(Self::Kind::BuildTerminal),
            _ => None,
        }
    }

    fn namespace(kind: Self::Kind) -> RecordNamespace {
        match kind {
            Self::Kind::Generation | Self::Kind::Current | Self::Kind::BuildTerminal => {
                RecordNamespace::DesiredState
            }
            Self::Kind::LeaseEffect | Self::Kind::BuildEffect => RecordNamespace::Effect,
            Self::Kind::Checkpoint => RecordNamespace::RuntimeGeneration,
        }
    }

    fn order(kind: Self::Kind) -> u8 {
        match kind {
            Self::Kind::Generation => 1,
            Self::Kind::BuildEffect => 2,
            Self::Kind::BuildTerminal => 3,
            Self::Kind::LeaseEffect => 4,
            Self::Kind::Current => 5,
            Self::Kind::Checkpoint => 6,
        }
    }

    fn role(kind: Self::Kind) -> ProtectedRecordRoleV1 {
        match kind {
            Self::Kind::Generation => ProtectedRecordRoleV1::State,
            Self::Kind::LeaseEffect | Self::Kind::BuildEffect => ProtectedRecordRoleV1::Effect,
            Self::Kind::Current | Self::Kind::Checkpoint | Self::Kind::BuildTerminal => {
                ProtectedRecordRoleV1::Publication
            }
        }
    }

    fn is_checkpoint(kind: Self::Kind) -> bool {
        matches!(kind, Self::Kind::Checkpoint)
    }

    fn family(kind: Self::Kind) -> u8 {
        kind as u8
    }

    fn decode_reducer_phase(
        manifests: &Self::ReplayValidator,
        kind: Self::Kind,
        identity: &[u8],
        body: &[u8],
    ) -> Option<ProtectedReducerPhaseV1> {
        if identity.len() != 48 || body.len() < 64 {
            return None;
        }
        match kind {
            Self::Kind::Generation
                if decode_environment_generation_v1(body)
                    .and_then(|decoded| encode_environment_generation_v1(&decoded))
                    .is_ok_and(|encoded| encoded == body)
                    && body.get(16..48) == identity.get(..32)
                    && body.get(body.len().checked_sub(32)?..body.len().checked_sub(16)?)
                        == identity.get(32..48) =>
            {
                Some(ProtectedReducerPhaseV1::Observed)
            }
            Self::Kind::LeaseEffect | Self::Kind::Current => {
                let activation = decode_environment_activation_v1(body, manifests).ok()?;
                if encode_environment_activation_v1(&activation)
                    .ok()?
                    .as_slice()
                    != body
                    || activation.project().as_bytes() != &identity[..16]
                    || activation.sandbox().as_bytes() != &identity[16..32]
                    || activation.transaction().as_bytes() != &identity[32..48]
                {
                    return None;
                }
                match (kind, activation.phase()) {
                    (
                        Self::Kind::LeaseEffect,
                        EnvironmentActivationPhaseV1::Desired
                        | EnvironmentActivationPhaseV1::Prepared,
                    ) => Some(ProtectedReducerPhaseV1::Prepared),
                    (
                        Self::Kind::Current,
                        EnvironmentActivationPhaseV1::Committed
                        | EnvironmentActivationPhaseV1::Observed
                        | EnvironmentActivationPhaseV1::Released,
                    ) => Some(ProtectedReducerPhaseV1::Terminal),
                    _ => None,
                }
            }
            Self::Kind::BuildEffect | Self::Kind::BuildTerminal => {
                let selector = selector_for_build_body(manifests, identity, body)?;
                let record =
                    super::execution::decode_nix_build_journal_record_v1(body, &selector).ok()?;
                if super::execution::encode_nix_build_journal_record_v1(&record).as_slice() != body
                    || record.state().request().operation().as_bytes() != &identity[32..48]
                {
                    return None;
                }
                match (kind, record.state().phase()) {
                    (Self::Kind::BuildEffect, super::NixBuildPhaseV1::Prepared) => {
                        Some(ProtectedReducerPhaseV1::Prepared)
                    }
                    (
                        Self::Kind::BuildTerminal,
                        super::NixBuildPhaseV1::Completed | super::NixBuildPhaseV1::Rejected,
                    ) => Some(ProtectedReducerPhaseV1::Terminal),
                    _ => None,
                }
            }
            Self::Kind::Generation | Self::Kind::Checkpoint => None,
        }
    }

    fn semantic_tuple(_kind: Self::Kind, identity: &[u8], _body: &[u8]) -> Option<[u8; 32]> {
        identity.get(..32)?.try_into().ok()
    }

    fn validates_identity(_kind: Self::Kind, identity: &[u8]) -> bool {
        identity.len() == 48
            && identity
                .chunks_exact(16)
                .all(|component| component != [0; 16])
    }
}

/// Selects one typed canonical environment reducer record.
pub(crate) enum EnvironmentReducerRecordV1<'record> {
    /// Encodes one immutable generation record.
    Generation(&'record EnvironmentGenerationManifestV1),
    /// Encodes one activation phase into effect or current-state storage.
    Activation(&'record EnvironmentActivationTransactionV1),
    /// Encodes one canonical constrained-build phase.
    Build(&'record super::execution::NixBuildJournalRecordV1),
}

/// Canonical environment shared-journal key.
pub type EnvironmentProtectedJournalKeyV1 =
    ProtectedDomainKeyV1<EnvironmentProtectedJournalSchemaV1>;
/// Canonical environment value and predecessor CAS.
pub type EnvironmentProtectedJournalEnvelopeV1 =
    ProtectedDomainEnvelopeV1<EnvironmentProtectedJournalSchemaV1>;
/// Sealed environment journal currentness snapshot.
pub type EnvironmentProtectedJournalSnapshotV1 =
    ProtectedDomainSnapshotV1<EnvironmentProtectedJournalSchemaV1>;
/// Replayed materialized environment projection.
pub type EnvironmentProtectedJournalProjectionV1 =
    ProtectedDomainProjectionV1<EnvironmentProtectedJournalSchemaV1>;
/// Environment transaction group reconstructed during bounded cold replay.
pub type EnvironmentJournalReplayTransactionV1 =
    ProtectedDomainReplayTransactionV1<EnvironmentProtectedJournalSchemaV1>;
/// Fail-closed environment cold-replay phase.
pub type EnvironmentJournalReplayPhaseV1 = ProtectedDomainReplayPhaseV1;
/// Semantic phase decoded from one environment reducer body.
pub type EnvironmentReducerPhaseV1 = ProtectedReducerPhaseV1;
/// Exact prepared environment transaction.
pub type PreparedEnvironmentJournalTransactionV1 =
    PreparedDomainTransactionV1<EnvironmentProtectedJournalSchemaV1>;
/// Exact ambiguous environment transaction recovery token.
pub type EnvironmentJournalOutcomeUnknownV1 =
    DomainOutcomeUnknownV1<EnvironmentProtectedJournalSchemaV1>;
/// Environment transaction commit outcome.
pub type EnvironmentJournalCommitOutcomeV1 =
    DomainCommitOutcomeV1<EnvironmentProtectedJournalSchemaV1>;
/// Environment outcome-unknown recovery classification.
pub type EnvironmentJournalRecoveryV1 = DomainRecoveryV1<EnvironmentProtectedJournalSchemaV1>;
/// Exact-readback environment transaction result.
pub type AppliedEnvironmentJournalTransactionV1 =
    AppliedDomainTransactionV1<EnvironmentProtectedJournalSchemaV1>;
/// Composite postcommit environment transaction authority.
pub type EnvironmentPostcommitCapabilityV1 =
    DomainPostcommitCapabilityV1<EnvironmentProtectedJournalSchemaV1>;
/// Current, consumed environment transaction authority.
pub type ValidatedEnvironmentPostcommitV1<'current> =
    ValidatedDomainPostcommitV1<'current, EnvironmentProtectedJournalSchemaV1>;
/// Current environment postcommit authority reconstructed during cold replay.
pub type ReplayedEnvironmentPostcommitV1 =
    ReplayedDomainPostcommitV1<EnvironmentProtectedJournalSchemaV1>;
/// Protected environment journal owner.
pub type EnvironmentProtectedJournalV1<'journal> =
    ProtectedDomainJournalV1<'journal, EnvironmentProtectedJournalSchemaV1>;
/// Environment adapter validation or durability failure.
pub type EnvironmentProtectedJournalErrorV1 = ProtectedDomainJournalErrorV1;

/// Constructs the canonical key for one sandbox environment subject.
///
/// # Errors
///
/// Returns [`EnvironmentProtectedJournalErrorV1`] only if the fixed typed
/// identity cannot be represented by the bounded key schema.
pub fn environment_protected_key_v1(
    kind: EnvironmentProtectedRecordKindV1,
    project: ProjectId,
    sandbox: SandboxId,
    environment: ResourceId,
) -> Result<EnvironmentProtectedJournalKeyV1, EnvironmentProtectedJournalErrorV1> {
    if project.as_bytes() == &[0; 16]
        || sandbox.as_bytes() == &[0; 16]
        || environment.as_bytes() == &[0; 16]
    {
        return Err(EnvironmentProtectedJournalErrorV1::NonCanonicalRecord);
    }
    let mut identity = Vec::with_capacity(48);
    identity.extend_from_slice(project.as_bytes());
    identity.extend_from_slice(sandbox.as_bytes());
    identity.extend_from_slice(environment.as_bytes());
    EnvironmentProtectedJournalKeyV1::new(kind, identity)
}

/// Claims the dormant environment adapter over a protected-open journal.
pub(crate) fn claim_environment_protected_journal_v1(
    journal: &mut Journal,
    manifests: EnvironmentGenerationHistoryV1,
) -> Result<EnvironmentProtectedJournalV1<'_>, EnvironmentProtectedJournalErrorV1> {
    EnvironmentProtectedJournalV1::claim_with_validator(journal, manifests)
}

/// Wraps one reducer-issued canonical environment body for journal admission.
pub(crate) fn environment_reducer_envelope_v1(
    key: EnvironmentProtectedJournalKeyV1,
    revision: u64,
    predecessor: Option<ObjectDigest>,
    record: EnvironmentReducerRecordV1<'_>,
    manifests: &EnvironmentGenerationHistoryV1,
) -> Result<EnvironmentProtectedJournalEnvelopeV1, EnvironmentProtectedJournalErrorV1> {
    let body = match record {
        EnvironmentReducerRecordV1::Generation(generation)
            if key.kind() == EnvironmentProtectedRecordKindV1::Generation
                && generation.project().as_bytes() == &key.identity()[..16]
                && generation.sandbox().as_bytes() == &key.identity()[16..32] =>
        {
            encode_environment_generation_v1(generation)
        }
        EnvironmentReducerRecordV1::Activation(activation)
            if activation.project().as_bytes() == &key.identity()[..16]
                && activation.sandbox().as_bytes() == &key.identity()[16..32]
                && activation.transaction().as_bytes() == &key.identity()[32..48]
                && matches!(
                    (key.kind(), activation.phase()),
                    (
                        EnvironmentProtectedRecordKindV1::LeaseEffect,
                        EnvironmentActivationPhaseV1::Desired
                            | EnvironmentActivationPhaseV1::Prepared
                    ) | (
                        EnvironmentProtectedRecordKindV1::Current,
                        EnvironmentActivationPhaseV1::Committed
                            | EnvironmentActivationPhaseV1::Observed
                            | EnvironmentActivationPhaseV1::Released
                    )
                ) =>
        {
            encode_environment_activation_v1(activation)
        }
        EnvironmentReducerRecordV1::Build(build)
            if matches!(
                (key.kind(), build.state().phase()),
                (
                    EnvironmentProtectedRecordKindV1::BuildEffect,
                    super::NixBuildPhaseV1::Prepared
                ) | (
                    EnvironmentProtectedRecordKindV1::BuildTerminal,
                    super::NixBuildPhaseV1::Completed | super::NixBuildPhaseV1::Rejected
                )
            ) && build
                .state()
                .request()
                .selector()
                .manifest_record()
                .project()
                .as_bytes()
                == &key.identity()[..16]
                && build
                    .state()
                    .request()
                    .selector()
                    .manifest_record()
                    .sandbox()
                    .as_bytes()
                    == &key.identity()[16..32]
                && build.state().request().operation().as_bytes() == &key.identity()[32..48] =>
        {
            Ok(super::execution::encode_nix_build_journal_record_v1(build))
        }
        EnvironmentReducerRecordV1::Generation(_)
        | EnvironmentReducerRecordV1::Activation(_)
        | EnvironmentReducerRecordV1::Build(_) => {
            return Err(EnvironmentProtectedJournalErrorV1::NonCanonicalRecord);
        }
    }
    .map_err(|_| EnvironmentProtectedJournalErrorV1::NonCanonicalRecord)?;
    let payload = encode_reducer_payload_with_validator::<EnvironmentProtectedJournalSchemaV1>(
        &key, &body, manifests,
    )?;
    EnvironmentProtectedJournalEnvelopeV1::new_with_validator(
        key,
        revision,
        predecessor,
        payload,
        manifests,
    )
}

fn selector_for_build_body(
    manifests: &EnvironmentGenerationHistoryV1,
    identity: &[u8],
    body: &[u8],
) -> Option<super::EnvironmentSelectorV1> {
    if body.len() != 336 || identity.len() != 48 {
        return None;
    }
    let generation = u64::from_be_bytes(body.get(64..72)?.try_into().ok()?);
    let manifest_digest = body.get(72..104)?;
    let sandbox = SandboxId::from_bytes(identity.get(16..32)?.try_into().ok()?);
    let (manifest, digest) = manifests
        .generations
        .get(&(sandbox, Revision::new(generation)))?;
    if manifest.project().as_bytes() != &identity[..16]
        || digest.digest().as_bytes() != manifest_digest
    {
        return None;
    }
    super::EnvironmentSelectorV1::from_manifest(manifest).ok()
}
