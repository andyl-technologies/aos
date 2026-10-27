//! Shares exact Policy publication schemas and passive byte/model comparison.
//!
//! Prerequisites, record keys, output codecs and independent recipes compile
//! without native journals. They authenticate no runtime role or prepared
//! transaction. Native-enabled Linux builds retain their actual owning error
//! causes; all prepared/verified/instance and state-writer custody stays native.

use std::{
    collections::{BTreeMap, BTreeSet},
};

use aos_sandbox_model::{
    DecodeLimits, MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType, ProjectId,
    SandboxId,
    format::{
        decode_optimization, decode_policy, descriptor_for_bytes, encode_optimization,
        encode_policy,
    },
};
use sha2::{Digest as _, Sha256};

use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::records::{
    ProtectedDomainEnvelopeV1, ProtectedDomainKeyV1, ProtectedDomainProjectionV1,
    ProtectedDomainSchemaV1, ProtectedRecordRoleV1, ProtectedReducerPhaseV1,
    decode_reducer_payload_with_validator, encode_reducer_payload_with_validator,
};

use crate::{
    CandidateAuthorityV1, CompiledPolicyCandidateV1, PolicyCompilerInputV1, PolicyModelError,
};
use crate::normalized_policy_input_digest_v1;
use aos_sandbox_protocol::policy_data::compiled_policy_candidate_digest_v1;

use aos_sandbox_protocol::domain_ledger::DomainLedgerDataError;

mod error;
mod data;
mod schema;
pub(crate) mod records;
pub(crate) mod geometry;
pub(crate) mod canonical_output;

pub use error::{PolicyCompilerJournalErrorV1, ProtectedDomainJournalErrorV1};
pub use data::{PolicyPublicationPrerequisitesV1, Q04IndependentPublicationRecipeV1,
    q04_independent_publication_data_v1};
pub(crate) use data::PublicationBodyFieldsV1;
pub use schema::{PolicyCompilerJournalRecordKindV1, PolicyCompilerJournalSchemaV1,
    PolicyCompilerReplayValidatorV1};
pub(crate) use schema::PolicyEffectStateV1;
pub use records::{DecodedCandidateHeaderV1, compare_recompiled_candidate_derivation_v1,
    validated_candidate_body};
pub(crate) use records::*;

/// Names the canonical nonauthorizing publication record key.
pub type PolicyCompilerJournalKeyV1 = ProtectedDomainKeyV1<PolicyCompilerJournalSchemaV1>;
/// Carries the canonical publication value and predecessor CAS comparison.
pub type PolicyCompilerJournalEnvelopeV1 = ProtectedDomainEnvelopeV1<PolicyCompilerJournalSchemaV1>;
/// Carries replayed publication records as passive comparison DATA.
pub type PolicyCompilerJournalProjectionV1 = ProtectedDomainProjectionV1<PolicyCompilerJournalSchemaV1>;

pub(crate) const CURRENT_MAGIC: &[u8; 8] = b"AOSPCU01";
pub(crate) const CANDIDATE_MAGIC: &[u8; 8] = b"AOSPCC01";
pub(crate) const CANDIDATE_PLAN_OFFSET: usize = 478;
pub(crate) const CANDIDATE_V3_FIXED_BYTES: usize = CANDIDATE_PLAN_OFFSET + 5 * 32;
pub(crate) const MAXIMUM_AUTHENTICATED_REPLAY_PREREQUISITES: usize = 4_096;
pub(crate) const DIAGNOSTICS_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.diagnostics.v1";
pub(crate) const PREREQUISITE_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.prerequisites.v1\0";


/// Reuses canonical lower recovery-coordinate DATA without native custody.
pub use aos_sandbox_protocol::domain_ledger::transaction::RecoveryReport;

/// Reports protected replay of policy state and its authority bindings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyCompilerProtectedOpenReportV1 {
    /// Reports compiled-policy state replay.
    pub state: RecoveryReport,
    /// Reports compiler-authority binding replay.
    pub authority: RecoveryReport,
}


#[cfg(all(feature = "native-journal", target_os = "linux"))]
pub use crate::native::publication::{CurrentNixPolicyOpeningV1,
    HeldResolvedRuntimePolicyV1, PolicyCompilerStateReadbackOwnerV1};
#[cfg(all(feature = "native-journal", target_os = "linux"))]
pub use crate::native::PolicyCompilerProtectedOwnerV1;

#[cfg(not(all(feature = "native-journal", target_os = "linux")))]
mod unsupported;
#[cfg(not(all(feature = "native-journal", target_os = "linux")))]
pub use unsupported::{CurrentNixPolicyOpeningV1, HeldResolvedRuntimePolicyV1,
    PolicyCompilerProtectedOwnerV1, PolicyCompilerStateReadbackOwnerV1};
