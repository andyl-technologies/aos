//! Owns complete nonauthorizing Publisher namespace schemas and replay.
//!
//! Canonical revisions, resource bindings, generation heads, project-authorization
//! rows and signed Git bootstrap history share one codec and replay engine.
//! Supplied rows and signature keys establish no fixed issuer, native custody,
//! protected currentness, mutation admission or resource permit.

use aos_sandbox_model::model::{CacheDomain, CacheDomainKind};
use aos_sandbox_model::{
    DecodeLimits, ObjectDescriptor, ObjectDigest, Operation, PrincipalId, ProjectId, ResourceId,
    ResourceKind, RevocationScopeId,
};
use sha2::{Digest as _, Sha256};
use aos_sandbox_model::RecordNamespace;
use crate::domain_ledger::transaction::JournalTransaction;


#[doc(hidden)]
pub const POLICY_REVISION_PREFIX: &[u8] = b"policy/revision/";
#[doc(hidden)]
pub const POLICY_CURRENT_PREFIX: &[u8] = b"policy/current/";
#[doc(hidden)]
pub const RESOURCE_PREFIX: &[u8] = b"resource/";
#[doc(hidden)]
pub const CONTROLLER_REVISION_PREFIX: &[u8] = b"controller/revision/";
#[doc(hidden)]
pub const CONTROLLER_CURRENT_KEY: &[u8] = b"controller/current";
#[doc(hidden)]
pub const REVOCATION_REVISION_PREFIX: &[u8] = b"revocation/revision/";
#[doc(hidden)]
pub const REVOCATION_CURRENT_PREFIX: &[u8] = b"revocation/current/";
#[doc(hidden)]
pub const PROJECT_REVOCATION_PREFIX: &[u8] = b"revocation/project/";

#[doc(hidden)]
pub const POLICY_REVISION_MAGIC: &[u8; 8] = b"AOSPOLR1";
#[doc(hidden)]
pub const POLICY_CURRENT_MAGIC: &[u8; 8] = b"AOSPOLH1";
#[doc(hidden)]
pub const RESOURCE_MAGIC: &[u8; 8] = b"AOSRESB1";
#[doc(hidden)]
pub const CONTROLLER_REVISION_MAGIC: &[u8; 8] = b"AOSCTLR1";
#[doc(hidden)]
pub const CONTROLLER_CURRENT_MAGIC: &[u8; 8] = b"AOSCTLH1";
#[doc(hidden)]
pub const REVOCATION_REVISION_MAGIC: &[u8; 8] = b"AOSREVR1";
#[doc(hidden)]
pub const REVOCATION_CURRENT_MAGIC: &[u8; 8] = b"AOSREVH1";
#[doc(hidden)]
pub const PROJECT_REVOCATION_MAGIC: &[u8; 8] = b"AOSREVP1";
// The signed project claim commits the protected mapping and exact scope generation:
// SHA-256(domain || project:16 || scope:16 || generation:u64-be).
#[doc(hidden)]
pub const PROJECT_REVOCATION_DOMAIN: &[u8] = b"aos.sandbox.publisher-project-revocation-head.v1\0";
// The project cache claim follows the current publisher revision, even when
// the disclosure domain itself remains unchanged between revisions.
#[doc(hidden)]
pub const PROJECT_CACHE_DOMAIN_HEAD_DOMAIN: &[u8] =
    b"aos.sandbox.publisher-project-cache-domain-head.v1\0";

#[doc(hidden)]
pub const MAXIMUM_POLICY_BYTES: usize = 4 * 1024 * 1024;
#[doc(hidden)]
pub const MAXIMUM_RECORDS: usize = 65_536;
#[doc(hidden)]
pub const MAXIMUM_RECORD_BYTES: usize = MAXIMUM_POLICY_BYTES + 128;
#[doc(hidden)]
pub const MAXIMUM_MATERIALIZED_BYTES: usize = 512 * 1024 * 1024;

mod model;
pub use model::*;
pub use crate::policy_data::PreparedPublisherPolicyRevisionV1;
pub mod record;
pub use record::*;
pub mod read_data;
pub use read_data::PublisherReadDataV2;
pub mod account_coverage;
pub mod git_source;
pub mod project_authorization_rows;
pub mod replay;
pub mod current_data;
pub use PublisherPolicySchemaErrorV1 as PublisherPolicyError;

/// Computes the original project-bound head commitment from supplied DATA.
pub use crate::policy_data::project_revocation_digest;

/// Computes the original project-bound head commitment from supplied DATA.
pub fn project_cache_domain_digest(
    project: ProjectId,
    generation: u64,
    policy_digest: ObjectDigest,
    domain: CacheDomain,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(PROJECT_CACHE_DOMAIN_HEAD_DOMAIN)
            .chain_update(project.as_bytes())
            .chain_update(generation.to_be_bytes())
            .chain_update(policy_digest.as_bytes())
            .chain_update([1_u8])
            .chain_update(domain.domain_id().as_bytes())
            .finalize()
            .into(),
    )
}

/// Shares complete current public-Create and Publisher DATA recipes.
pub mod current_create;

/// Prices nonauthorizing historical Publisher namespace representations.
pub mod receiving_data;
