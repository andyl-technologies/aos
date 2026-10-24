//! Shares complete current-public-Create and Publisher comparison recipes.
//!
//! DATA models retain private fields. Native callers invoke the lexical recipes
//! with their actual protected/health checks at each original frontier; diagnostic
//! callers use the same comparisons without claiming native provenance. No recipe
//! constructs a protected owner, authenticates a fixed issuer or grants capacity.

use aos_sandbox_model::{ObjectDigest, OperationId, ProjectId, SandboxId, RevocationScopeId};
use aos_sandbox_model::model::CacheDomain;

/// Defines the same private-field source model for DATA or its genuine upper enclosure.
///
/// Distinct instantiations are nominally distinct: a DATA result cannot convert
/// into the upper protected-built source accepted by its relation verifier.
#[macro_export]
macro_rules! define_current_create_project_source_model_v1 {
    ($name:ident, $historical_visibility:vis) => {
        /// Retains exact canonical publisher bytes under a current Create selector.
        ///
        /// This read-only value follows the retained operation, projection,
        /// publisher, cache-domain, or revocation head. Before any compiler binding
        /// or effect, the caller must rejoin those heads under protected custody.
        pub struct $name {
            operation: OperationId,
            operation_revision: ObjectDigest,
            accepted_generation: u64,
            sandbox: SandboxId,
            project: ProjectId,
            projection_revision: ObjectDigest,
            policy_generation: u64,
            policy_digest: ObjectDigest,
            cache_domain: CacheDomain,
            cache_domain_head: ObjectDigest,
            revocation_scope: RevocationScopeId,
            revocation_generation: u64,
            revocation_head: ObjectDigest,
            canonical_policy: Vec<u8>,
            commitment: ObjectDigest,
        }

        impl $name {


            /// Returns the same historical head commitments without native admission.
            $historical_visibility fn historical_heads(&self) -> $crate::domain_ledger::project_source::HistoricalCreateProjectSourceHeadsV1 {
                $crate::domain_ledger::project_source::HistoricalCreateProjectSourceHeadsV1::from_historical_fields(
                    self.projection_revision,
                    self.policy_generation,
                    self.policy_digest,
                    self.cache_domain_head,
                    self.revocation_scope,
                    self.revocation_generation,
                    self.revocation_head,
                )
            }

            /// Returns the admitted public Create operation identity.
            #[must_use]
            pub const fn operation(&self) -> OperationId {
                self.operation
            }

            /// Returns the exact accepted operation and effect-record revision.
            #[must_use]
            pub const fn operation_revision(&self) -> ObjectDigest {
                self.operation_revision
            }

            /// Returns the protected admission generation of the selected Create.
            #[must_use]
            pub const fn accepted_generation(&self) -> u64 {
                self.accepted_generation
            }

            /// Returns the exact selected sandbox identity.
            #[must_use]
            pub const fn sandbox(&self) -> SandboxId {
                self.sandbox
            }

            /// Returns the protected project partition.
            #[must_use]
            pub const fn project(&self) -> ProjectId {
                self.project
            }

            /// Returns the complete checked public projection record digest.
            #[must_use]
            pub const fn projection_revision(&self) -> ObjectDigest {
                self.projection_revision
            }

            /// Returns the exact current publisher generation observed at the join.
            #[must_use]
            pub const fn policy_generation(&self) -> u64 {
                self.policy_generation
            }

            /// Returns the canonical publisher policy object's digest.
            #[must_use]
            pub const fn policy_digest(&self) -> ObjectDigest {
                self.policy_digest
            }

            /// Returns the publisher-selected project disclosure domain.
            #[must_use]
            pub const fn cache_domain(&self) -> CacheDomain {
                self.cache_domain
            }

            /// Returns the publisher-owned current project cache-domain head.
            #[must_use]
            pub const fn cache_domain_head(&self) -> ObjectDigest {
                self.cache_domain_head
            }

            /// Returns the protected scope selected for this project.
            #[must_use]
            pub const fn revocation_scope(&self) -> RevocationScopeId {
                self.revocation_scope
            }

            /// Returns the exact current generation of the selected revocation scope.
            #[must_use]
            pub const fn revocation_generation(&self) -> u64 {
                self.revocation_generation
            }

            /// Returns the independent protected project revocation head observed
            /// with the publisher revision.
            #[must_use]
            pub const fn revocation_head(&self) -> ObjectDigest {
                self.revocation_head
            }

            /// Returns exact canonical publisher policy bytes validated by its store.
            #[must_use]
            pub fn canonical_policy(&self) -> &[u8] {
                &self.canonical_policy
            }

            /// Returns the versioned query-time source commitment.
            #[must_use]
            pub const fn commitment(&self) -> ObjectDigest {
                self.commitment
            }
        }

    };
}

crate::define_current_create_project_source_model_v1!(CurrentCreateProjectPolicySourceDataV1, pub);

/// Defines the original current Publisher result fields without native authority.
#[macro_export]
macro_rules! define_current_publisher_policy_data_model_v2 {
    ($name:ident, $fields_visibility:vis) => {
        pub struct $name {
            $fields_visibility policy_generation: u64,
            $fields_visibility policy_digest: ObjectDigest,
            $fields_visibility cache_domain: CacheDomain,
            $fields_visibility cache_domain_head: ObjectDigest,
            $fields_visibility revocation_scope: RevocationScopeId,
            $fields_visibility revocation_generation: u64,
            $fields_visibility revocation_head: ObjectDigest,
            $fields_visibility canonical_policy: Vec<u8>,
            $fields_visibility expires: i64,
        }
    };
}

crate::define_current_publisher_policy_data_model_v2!(CurrentPublisherPolicyDataV2, pub(super));

/// Reports missing, expired or malformed current Publisher comparison DATA.
#[derive(Debug, thiserror::Error)]
pub enum CurrentPublisherPolicyDataErrorV2 {
    /// The current descriptor or validity differs from the requested policy.
    #[error("the current protected publisher policy differs or expired")]
    NotCurrent,
    /// The complete Publisher schema or cross-link replay failed.
    #[error(transparent)]
    Publisher(#[from] super::PublisherPolicySchemaErrorV1),
}

/// Reports the original pure current-public-Create comparison refusal.
#[derive(Debug, thiserror::Error)]
pub enum CurrentCreateProjectSourceDataErrorV1 {
    /// The Operation, projection or Publisher join does not select this source.
    #[error("the current public Create source differs")]
    NotCurrent,
    /// The complete original admission history is malformed.
    #[error(transparent)]
    Operation(#[from] crate::domain_ledger::create_admission::CreateAdmissionDataErrorV1),
    /// The exact public projection is malformed.
    #[error(transparent)]
    Projection(#[from] crate::public_api::projection::PublicProjectionError),
    /// The Publisher descriptor, complete schema or validity does not agree.
    #[error(transparent)]
    Publisher(#[from] CurrentPublisherPolicyDataErrorV2),
}

/// Expands the sole Publisher/current-policy comparison at original guard frontiers.
///
/// The guard block is lexical code on the caller's real owner, never a runtime
/// callback, trait or supplied health token. The explicit Publisher transfer tuple
/// restores the old temporary-drop frontier and has its own control quote.
#[macro_export]
macro_rules! current_publisher_policy_data_recipe_v2 {
    (
        rows = $rows:expr, project = $project:expr,
        requested_media_type = $media:expr, requested_digest = $digest:expr,
        requested_bytes = $bytes:expr, observed_wall = $wall:expr,
        protected = $protected:block,
        outputs = ($policy_generation:ident, $policy_digest:ident, $cache_domain:ident,
            $cache_domain_head:ident, $revocation_scope:ident, $revocation_generation:ident,
            $revocation_head:ident, $canonical_policy:ident, $expires:ident)
    ) => {
        use $crate::publisher_policy::{PublisherPolicyLimits, PublisherPolicySchemaErrorV1};
        use $crate::publisher_policy::current_create::CurrentPublisherPolicyDataErrorV2 as PublisherError;
        use $crate::publisher_policy::current_data::{current_policy_from_data_v2, revocation_head_from_data_v2};
        use $crate::publisher_policy::record::{decode_project_revocation_binding, project_revocation_key};

        let ($policy_generation, $policy_digest, $cache_domain, $cache_domain_head, $revocation_scope, $revocation_generation, $revocation_head, $canonical_policy, $expires) = {
            $protected
            let publisher_rows = $rows;
            $crate::publisher_policy::replay::validate_namespace(publisher_rows, PublisherPolicyLimits::default())
                .map_err(PublisherError::Publisher)?;
            $protected
            let revision = current_policy_from_data_v2(publisher_rows, $project)
                .map_err(PublisherError::Publisher)?.ok_or(PublisherError::NotCurrent)?;
            let revocation = {
                $protected
                let (bound_project, scope) = publisher_rows
                    .get(aos_sandbox_model::RecordNamespace::PublisherPolicy, &project_revocation_key($project))
                    .map(decode_project_revocation_binding).transpose().map_err(PublisherError::Publisher)?
                    .ok_or(PublisherError::NotCurrent)?;
                if bound_project != $project {
                    return Err(PublisherError::Publisher(PublisherPolicySchemaErrorV1::CorruptState).into());
                }
                $protected
                let revocation = revocation_head_from_data_v2(publisher_rows, scope)
                    .map_err(PublisherError::Publisher)?
                    .ok_or(PublisherError::Publisher(PublisherPolicySchemaErrorV1::CorruptState))?;
                let revocation_digest = $crate::publisher_policy::project_revocation_digest($project, scope, revocation.generation);
                $crate::publisher_policy::PublisherProjectRevocationHeadV1::from_historical_fields(
                    $project, scope, revocation.generation, revocation_digest,
                )
            };
            let cache_domain = {
                $protected
                let cache_policy = current_policy_from_data_v2(publisher_rows, $project)
                    .map_err(PublisherError::Publisher)?.ok_or(PublisherError::NotCurrent)?;
                let domain = cache_policy.policy().cache_domain();
                if domain.kind() != aos_sandbox_model::model::CacheDomainKind::Project
                    || domain.domain_id().as_bytes() != $project.as_bytes()
                {
                    return Err(PublisherError::Publisher(PublisherPolicySchemaErrorV1::InvalidProjectCacheDomainBinding).into());
                }
                let cache_policy_digest = cache_policy.descriptor().digest();
                let cache_digest = $crate::publisher_policy::project_cache_domain_digest(
                    $project, cache_policy.generation(), cache_policy_digest, domain,
                );
                $crate::publisher_policy::PublisherProjectCacheDomainHeadV1::from_historical_fields(
                    $project, cache_policy.generation(), cache_policy_digest, domain, cache_digest,
                )
            };
            let descriptor = revision.descriptor();
            if $media != descriptor.media_type().as_str()
                || $digest != descriptor.digest().as_bytes()
                || $bytes != descriptor.encoded_size()
            {
                return Err(PublisherError::NotCurrent.into());
            }
            let now = match $wall {
                Some(now) => now,
                None => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| PublisherError::NotCurrent)?;
                    i64::try_from(now.as_secs()).map_err(|_| PublisherError::NotCurrent)?
                }
            };
            if now < revision.not_before() || now >= revision.expires_at() {
                return Err(PublisherError::NotCurrent.into());
            }

            let $policy_generation = revision.generation();
            let $policy_digest = descriptor.digest();
            let $cache_domain_head = cache_domain.digest();
            let $cache_domain = cache_domain.domain();
            let $revocation_scope = revocation.scope();
            let $revocation_generation = revocation.generation();
            let $revocation_head = revocation.digest();
            let $canonical_policy = revision.canonical_policy().to_vec();
            let $expires = revision.expires_at();
            ($policy_generation, $policy_digest, $cache_domain, $cache_domain_head, $revocation_scope, $revocation_generation, $revocation_head, $canonical_policy, $expires)
        };
    };
}

/// Expands the sole original parentless public-Create source comparison.
///
/// Each lexical guard executes at the old native point. Output bindings avoid
/// moving a DATA result into an authority-bearing upper model.
#[macro_export]
macro_rules! current_parentless_create_project_source_recipe_v1 {
    (
        rows = $rows:expr, operation = $operation:ident, sandbox = $sandbox:ident,
        observed_wall = $wall:expr,
        protected = $protected:block, retained_protected = $retained:block,
        projection_healthy = $projection_healthy:block, publisher_protected = $publisher:block,
        outputs = ($operation_revision:ident, $accepted_generation:ident, $project:ident,
            $projection_revision:ident, $policy_generation:ident, $policy_digest:ident,
            $cache_domain:ident, $cache_domain_head:ident, $revocation_scope:ident,
            $revocation_generation:ident, $revocation_head:ident, $canonical_policy:ident, $commitment:ident)
    ) => {
        use $crate::publisher_policy::current_create::CurrentCreateProjectSourceDataErrorV1 as SourceError;
        use $crate::domain_ledger::create_admission::{recovered_public_operation_admission_from_rows_v1,
            retained_create_sandbox_admission_from_rows_v1};
        use $crate::public_api::projection::{PublicProjectionKindV1, PublicProjectionResourceV1,
            PublicProjectionError};

        $protected
        if $operation.as_bytes() == &[0; 16] || $sandbox.as_bytes() == &[0; 16] {
            return Err(SourceError::NotCurrent.into());
        }
        let create_source_rows = $rows;
        let admission = recovered_public_operation_admission_from_rows_v1(create_source_rows, $operation)
            .map_err(SourceError::Operation)?.ok_or(SourceError::NotCurrent)?;
        $retained
        let ($operation_revision, $accepted_generation, request_digest) =
            retained_create_sandbox_admission_from_rows_v1(create_source_rows, $operation, false)
                .map_err(SourceError::Operation)?.ok_or(SourceError::NotCurrent)?;
        $crate::checked_public_projection_read_data_v1!(
            kind = PublicProjectionKindV1::Sandbox, resource_id = *$sandbox.as_bytes(),
            invalid_identity = SourceError::Projection(PublicProjectionError::InvalidIdentity).into(),
            healthy = $projection_healthy, key = projection_key,
            read = create_source_rows.get_record_data_v1(aos_sandbox_model::RecordNamespace::DesiredState, &projection_key),
            output = projection
        );
        let projection = projection.ok_or(SourceError::NotCurrent)?;
        let PublicProjectionResourceV1::Sandbox(sandbox_resource) = projection.resource() else {
            return Err(SourceError::NotCurrent.into());
        };
        if projection.operation() != $operation
            || sandbox_resource.sandbox_id.as_slice() != $sandbox.as_bytes()
            || !sandbox_resource.parent_sandbox_id.is_empty()
            || sandbox_resource.resource_version != $crate::public_api::mutation_history::compiler_resource_version(
                $operation, $crate::public_api::PublicOperationMethodV1::CreateSandbox, 1, request_digest)
        {
            return Err(SourceError::NotCurrent.into());
        }
        let $project = projection.project();
        if sandbox_resource.project_id.as_slice() != $project.as_bytes() || admission.project() != $project {
            return Err(SourceError::NotCurrent.into());
        }
        let desired = sandbox_resource.desired.as_option().ok_or(SourceError::NotCurrent)?;
        let requested_policy = desired.requested_policy.as_option().ok_or(SourceError::NotCurrent)?;
        let effective_policy = sandbox_resource.effective_policy.as_option().ok_or(SourceError::NotCurrent)?;
        if requested_policy != effective_policy || desired.specification.as_option().is_none() {
            return Err(SourceError::NotCurrent.into());
        }
        let $projection_revision = projection.revision();
        $crate::current_publisher_policy_data_recipe_v2!(
            rows = $crate::publisher_policy::PublisherReadDataV2::from_state_v2(create_source_rows.materialized_state_data_v1()),
            project = $project, requested_media_type = requested_policy.media_type.as_str(),
            requested_digest = requested_policy.sha256.as_slice(), requested_bytes = requested_policy.encoded_size,
            observed_wall = $wall, protected = $publisher,
            outputs = ($policy_generation, $policy_digest, $cache_domain, $cache_domain_head,
                $revocation_scope, $revocation_generation, $revocation_head, $canonical_policy, create_publisher_expires)
        );
        let $commitment = $crate::domain_ledger::project_source::create_project_source_commitment_v1(
            $operation, $operation_revision, $accepted_generation, $sandbox, $project,
            $crate::domain_ledger::project_source::HistoricalCreateProjectSourceHeadsV1::from_historical_fields(
                $projection_revision, $policy_generation, $policy_digest, $cache_domain_head,
                $revocation_scope, $revocation_generation, $revocation_head,
            ),
        );
    };
}

/// Compares supplied complete rows and returns nonauthorizing current-Create DATA.
///
/// # Errors
/// Returns the original admission, projection, Publisher, descriptor or validity refusal.
pub fn current_parentless_create_project_source_from_rows_v1(
    rows: crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
    operation: OperationId, sandbox: SandboxId, observed_wall: Option<i64>,
) -> Result<CurrentCreateProjectPolicySourceDataV1, CurrentCreateProjectSourceDataErrorV1> {
    crate::current_parentless_create_project_source_recipe_v1!(
        rows = rows, operation = operation, sandbox = sandbox, observed_wall = observed_wall,
        protected = {}, retained_protected = {}, projection_healthy = {}, publisher_protected = {},
        outputs = (operation_revision, accepted_generation, project, projection_revision, policy_generation, policy_digest, cache_domain, cache_domain_head, revocation_scope, revocation_generation, revocation_head, canonical_policy, commitment)
    );
    Ok(CurrentCreateProjectPolicySourceDataV1 { operation, operation_revision, accepted_generation, sandbox, project, projection_revision, policy_generation, policy_digest, cache_domain, cache_domain_head, revocation_scope, revocation_generation, revocation_head, canonical_policy, commitment })
}

impl CurrentPublisherPolicyDataV2 {
    /// Returns the observed policy generation DATA.
    pub const fn policy_generation(&self) -> u64 { self.policy_generation }

    /// Returns the observed policy digest DATA.
    pub const fn policy_digest(&self) -> ObjectDigest { self.policy_digest }

    /// Returns the observed cache domain DATA.
    pub const fn cache_domain(&self) -> CacheDomain { self.cache_domain }

    /// Returns the observed cache domain head DATA.
    pub const fn cache_domain_head(&self) -> ObjectDigest { self.cache_domain_head }

    /// Returns the observed revocation scope DATA.
    pub const fn revocation_scope(&self) -> RevocationScopeId { self.revocation_scope }

    /// Returns the observed revocation generation DATA.
    pub const fn revocation_generation(&self) -> u64 { self.revocation_generation }

    /// Returns the observed revocation head DATA.
    pub const fn revocation_head(&self) -> ObjectDigest { self.revocation_head }

    /// Returns the observed expires DATA.
    pub const fn expires(&self) -> i64 { self.expires }

    /// Borrows the exact checked canonical policy bytes.
    pub fn canonical_policy(&self) -> &[u8] { &self.canonical_policy }
}

/// Quotes the new concrete transfer and projection controls of one Source recipe.
///
/// This counts additional interfaces, independently of resident owner geometry,
/// canonical-policy buffers and the unchanged full replay demand. Native callers
/// must add it once to their actual pre-entry invoice; this supplies no capacity.
/// Returns `None` if a concrete control size or the checked sum is unrepresentable.
#[must_use]
pub fn source_recipe_additional_control_bytes_v1() -> Option<u64> {
    use std::mem::size_of;
    use crate::domain_ledger::create_admission::CreateAdmissionDataErrorV1;
    use crate::domain_ledger::public_operation::PublicOperationAdmissionV1;
    use crate::domain_ledger::readonly::{HistoricalLedgerComparisonV2, HistoricalLedgerRowsDataV2};
    use super::{PreparedPublisherPolicyRevisionV1, PublisherPolicySchemaErrorV1, PublisherReadDataV2,
        PublisherProjectRevocationHeadV1, PublisherProjectCacheDomainHeadV1, PublisherRevocationHeadV1};

    type PublisherTransfer = (u64, ObjectDigest, CacheDomain, ObjectDigest,
        RevocationScopeId, u64, ObjectDigest, Vec<u8>, i64);
    type Admission = Option<PublicOperationAdmissionV1>;
    type Revision = Option<(ObjectDigest, u64, [u8; 32])>;
    type Policy = Option<PreparedPublisherPolicyRevisionV1>;
    type Scope = Option<PublisherRevocationHeadV1>;
    type Binding = Option<(ProjectId, RevocationScopeId)>;

    let controls = [
        // The lexical Publisher output restores the original temporary-drop frontier.
        size_of::<PublisherTransfer>(),
        // Actual view return/binding, three admission arguments and two map-lending receivers.
        size_of::<HistoricalLedgerRowsDataV2<'_>>(),
        size_of::<HistoricalLedgerRowsDataV2<'_>>(),
        size_of::<HistoricalLedgerRowsDataV2<'_>>(),
        size_of::<HistoricalLedgerRowsDataV2<'_>>(),
        size_of::<HistoricalLedgerRowsDataV2<'_>>(),
        size_of::<HistoricalLedgerRowsDataV2<'_>>(),
        size_of::<HistoricalLedgerRowsDataV2<'_>>(),
        // Actual recovered, retained and retained's nested recovered comparison locals.
        size_of::<HistoricalLedgerComparisonV2<'_>>(),
        size_of::<HistoricalLedgerComparisonV2<'_>>(),
        size_of::<HistoricalLedgerComparisonV2<'_>>(),
        // Explicit state lending and the new neutral Publisher view return/binding.
        size_of::<&std::collections::BTreeMap<(aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>>(),
        size_of::<PublisherReadDataV2<'_>>(),
        size_of::<PublisherReadDataV2<'_>>(),
        // Passive head construction return interfaces preserve their old local scopes.
        size_of::<PublisherProjectRevocationHeadV1>(),
        size_of::<PublisherProjectCacheDomainHeadV1>(),
        // Each new owning map-error interface has its actual input/output type.
        size_of::<Result<Admission, CreateAdmissionDataErrorV1>>(),
        size_of::<Result<Admission, CurrentCreateProjectSourceDataErrorV1>>(),
        size_of::<Result<Revision, CreateAdmissionDataErrorV1>>(),
        size_of::<Result<Revision, CurrentCreateProjectSourceDataErrorV1>>(),
        size_of::<Result<(usize, usize), PublisherPolicySchemaErrorV1>>(),
        size_of::<Result<(usize, usize), CurrentPublisherPolicyDataErrorV2>>(),
        // First current policy and the separate cache-domain current policy.
        size_of::<Result<Policy, PublisherPolicySchemaErrorV1>>(),
        size_of::<Result<Policy, CurrentPublisherPolicyDataErrorV2>>(),
        size_of::<Result<Policy, PublisherPolicySchemaErrorV1>>(),
        size_of::<Result<Policy, CurrentPublisherPolicyDataErrorV2>>(),
        size_of::<Result<Binding, PublisherPolicySchemaErrorV1>>(),
        size_of::<Result<Binding, CurrentPublisherPolicyDataErrorV2>>(),
        size_of::<Result<Scope, PublisherPolicySchemaErrorV1>>(),
        size_of::<Result<Scope, CurrentPublisherPolicyDataErrorV2>>(),
        // Owning flat-error projection and this checked quote's own return/control.
        size_of::<CurrentCreateProjectSourceDataErrorV1>(),
        size_of::<CurrentPublisherPolicyDataErrorV2>(),
        size_of::<Option<u64>>(),
        size_of::<u64>(),
    ];
    controls.into_iter().try_fold(0_u64, |total, bytes| {
        total.checked_add(u64::try_from(bytes).ok()?)
    })
}
