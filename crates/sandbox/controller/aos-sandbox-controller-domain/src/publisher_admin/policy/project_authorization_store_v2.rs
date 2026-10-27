//! Protected, nonauthorizing retention of signed project-limit decisions.
//!
//! The publisher owner commits one immutable request row and its current
//! epoch head in a single protected journal transaction. Historical rows
//! replay against their immutable AOSPOLR1 revision and reconstructable
//! AOSPOLH1 pointer; a current read separately rejects a later publisher
//! head. Cold load validates structure only. The current authenticated read
//! separately obtains the fixed issuer credential and reverifies the exact
//! packet; retained rows alone are not authority. No Source seed or Create
//! capability is issued here.
//!
//! ```text
//! project-auth/row/<project:16><request:16> =
//!   AOSPAUR2 | project:16 | request:16 | epoch:u64be |
//!   issuer-generation:u64be | publisher-generation:u64be |
//!   AOSPOLH1-digest:32 | AOSPOLR1-digest:32 | packet-digest:32 |
//!   seven ceilings:u32be each | exact AOSPSC02 packet:224
//! project-auth/current/<project:16> =
//!   AOSPAUH2 | project:16 | epoch:u64be | request:16 | row-digest:32
//! AOSPAUR3 retains exact AOSPSC03[400]; AOSPAUH3 selects that row.
//! Both recipes share the same protected keys and monotonic epoch kernel.
//! ```

use aos_sandbox_protocol::publisher_project_authorization::{
    HEAD_DOMAIN,
    PinnedPublisherProjectAuthorizationIssuerV2,
    REVISION_DOMAIN,
    commitment,
    encode_project_authorization_issuer_credential_v2,
};

use std::collections::BTreeMap;
use std::path::Path;

use aos_sandbox_model::source_tree_model::TreeLimitsV1;
use aos_sandbox_model::{ObjectDigest, ProjectId};
use aos_sandbox_protocol::source_project_authorization::{
    PROJECT_AUTHORIZATION_SOURCE_BYTES_V2 as PACKET_BYTES,
    PROJECT_AUTHORIZATION_SOURCE_BYTES_V3,
    parse_unverified_project_authorization_claims_v2, project_authorization_packet_digest,
};
use sha2::{Digest as _, Sha256};
#[cfg(any(target_os = "linux", test))]
use thiserror::Error;

use crate::journal::controller::production_journal_limits;
#[cfg(target_os = "linux")]
use aos_sandbox_broker::source_seed_credential::verify_controller_source_tree_seed_from_fixed_issuer_v1;
#[cfg(any(target_os = "linux", test))]
use aos_sandbox_protocol::controller_source_seed::{
    ControllerSourceTreeSeedErrorV1, ControllerSourceTreeSeedExpectedV1,
    PinnedControllerSourceTreeSeedIssuerV1, VerifiedControllerSourceTreeSeedV1,
    verify_controller_source_tree_seed_v1,
};
use crate::journal::{CommitResult, Journal, JournalRecord, RecordNamespace};

use super::project_authorization_source_v2::{
    ProjectAuthorizationSourceErrorV2,
    ProjectAuthorizationSourceExpectedV2,
    ProtectedProjectAuthorizationIssuerV2,
    VerifiedPublisherProjectAuthorizationSourceV2,
    verify_current_project_authorization_source_v2,
};
use super::{
    PublisherProjectGenesisErrorV1, PublisherPolicyError, PublisherPolicyStore, decode_policy_revision, encode_policy_head,
    policy_current_key, policy_revision_key,
};

const CONTROLLER_ROOT: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";
#[cfg(any(target_os = "linux", test))]
const RETAINED_HEAD_DOMAIN: &[u8] = b"aos.sandbox.publisher-project-authorization.retained-current-head.v2\0";
#[cfg(any(target_os = "linux", test))]
const RETAINED_HEAD_DOMAIN_V3: &[u8] = b"aos.sandbox.publisher-project-authorization.retained-current-head.v3\0";
use aos_sandbox_protocol::publisher_policy::project_authorization_rows::*;
// A bounded observation from this store's existing authenticated current read.
// Retaining these fields alone does not retain the Controller writer or heads.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceSuccessorAuthorizationDataV2 {
    pub(crate) publisher_generation: u64,
    pub(crate) publisher_head: ObjectDigest,
    pub(crate) publisher_revision: ObjectDigest,
    pub(crate) authorization_head: ObjectDigest,
    pub(crate) limits: TreeLimitsV1,
    pub(crate) packet: Vec<u8>,
}

/// Describes only the durability result, never Source or Create authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProjectAuthorizationRetentionV2 {
    Committed(CommitResult),
    ExactReplay,
}

/// Reports why a Controller-held initial-tree seed preflight is unavailable.
///
/// Passing this preflight, including its current-pair DATA read, does not spend
/// the seed epoch or authorize Source journal mutation.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Error)]
pub(crate) enum CurrentSourceTreeSeedPreflightErrorV1 {
    /// No authenticated project decision is current for the requested project.
    #[error("no current project authorization is retained")]
    MissingAuthorization,
    /// The retained decision or its fixed issuer is unavailable or stale.
    #[error(transparent)]
    Authorization(#[from] ProjectAuthorizationSourceErrorV2),
    /// The seed or its distinct fixed issuer is unavailable or stale.
    #[error(transparent)]
    Seed(#[from] ControllerSourceTreeSeedErrorV1),
    /// The current pair cannot form the existing nonauthorizing acceptance data.
    #[error(transparent)]
    Acceptance(#[from] super::PublisherProjectGenesisErrorV1),
}


#[cfg(any(target_os = "linux", test))]
fn retained_head_digest(bytes: &[u8]) -> ObjectDigest {
    let domain = if bytes.get(..8) == Some(b"AOSPAUH3".as_slice()) {
        RETAINED_HEAD_DOMAIN_V3
    } else {
        RETAINED_HEAD_DOMAIN
    };
    commitment(domain, bytes)
}


fn row_from_verified(
    verified: VerifiedPublisherProjectAuthorizationSourceV2,
    packet: &[u8],
) -> Result<RetainedProjectAuthorizationRowV2, ProjectAuthorizationSourceErrorV2> {
    // The shared verifier has already checked the exact version and width.
    project_authorization_packet_digest(packet)?;
    Ok(RetainedProjectAuthorizationRowV2::from_historical_fields(
            verified.project(),
            verified.request_id(),
            verified.epoch(),
            verified.issuer_generation(),
            verified.publisher_generation(),
            verified.publisher_head_digest(),
            verified.publisher_revision_digest(),
            verified.packet_digest(),
            verified.limits(),
            packet.to_vec()
        ))
}


impl PublisherPolicyStore<'_> {
    /// Rechecks the fixed issuer and borrows the actual current authorization.
    ///
    /// This bounded copy is DATA from this store's still-held Controller cut.
    /// Neither historical genesis heads nor caller-supplied head values are
    /// used to select it.
    #[cfg(target_os = "linux")]
    pub(crate) fn current_source_successor_authorization_v2(
        &self,
        project: ProjectId,
    ) -> Result<SourceSuccessorAuthorizationDataV2, ProjectAuthorizationSourceErrorV2> {
        let verified = self
            .current_authenticated_project_authorization_from_fixed_issuer_v2(project)?
            .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
        let row = self
            .current_retained_project_authorization_v2(project)?
            .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
        let authorization_head = self.current_project_authorization_head_digest_v2(project)?;

        self.require_fixed_controller_writer_v2()?;
        Ok(SourceSuccessorAuthorizationDataV2 {
            publisher_generation: verified.publisher_generation(),
            publisher_head: verified.publisher_head_digest(),
            publisher_revision: verified.publisher_revision_digest(),
            authorization_head,
            limits: verified.limits(),
            // The same authenticated current kernel selected this whole
            // canonical packet. A successor must retain all signed dimensions.
            packet: row.into_packet(),
        })
    }

    fn require_fixed_controller_writer_v2(&self) -> Result<(), ProjectAuthorizationSourceErrorV2> {
        let uid = self
            .journal
            .protected_owner_uid()
            .map_err(PublisherPolicyError::from)?;
        self.journal
            .require_protected_named_location(
                Path::new(CONTROLLER_ROOT),
                CONTROLLER_JOURNAL,
                uid,
                production_journal_limits(),
            )
            .map_err(PublisherPolicyError::from)?;
        Ok(())
    }

    /// Checks one seed against the authenticated current Controller row.
    ///
    /// The caller must retain this store's Controller writer. Both issuer
    /// credentials come from their fixed privileged names and are rechecked
    /// around the joined read. The result is only a preflight observation: it
    /// neither spends an epoch nor grants Source append authority.
    ///
    /// # Errors
    ///
    /// Rejects missing or stale current rows, unavailable issuer credentials,
    /// a changed publisher pointer or revision, and any seed mismatch.
    #[cfg(target_os = "linux")]
    pub(crate) fn preflight_current_source_tree_seed_from_fixed_issuers_v1(
        &self,
        project: ProjectId,
        packet: &[u8],
    ) -> Result<VerifiedControllerSourceTreeSeedV1, CurrentSourceTreeSeedPreflightErrorV1> {
        self.require_fixed_controller_writer_v2()?;
        let authorization_issuer =
            ProtectedProjectAuthorizationIssuerV2::from_systemd_credentials()?;
        authorization_issuer.recheck()?;
        let (authorization, head_digest) =
            self.current_source_genesis_authorization_v1(project, authorization_issuer.pin())?;
        let verified = verify_seed_for_current_authorization_v1(
            packet,
            authorization,
            head_digest,
            verify_controller_source_tree_seed_from_fixed_issuer_v1,
        )?;
        authorization_issuer.recheck()?;
        self.require_fixed_controller_writer_v2()?;
        Ok(verified)
    }

    #[cfg(any(target_os = "linux", test))]
    fn current_source_genesis_authorization_v1(
        &self,
        project: ProjectId,
        issuer: &PinnedPublisherProjectAuthorizationIssuerV2,
    ) -> Result<
        (VerifiedPublisherProjectAuthorizationSourceV2, ObjectDigest),
        CurrentSourceTreeSeedPreflightErrorV1,
    > {
        let authorization = self
            .current_authenticated_project_authorization_v2(project, issuer)?
            .ok_or(CurrentSourceTreeSeedPreflightErrorV1::MissingAuthorization)?;
        let head_digest = self.current_project_authorization_head_digest_v2(project)?;
        Ok((authorization, head_digest))
    }

    #[cfg(any(target_os = "linux", test))]
    fn current_project_authorization_head_digest_v2(
        &self,
        project: ProjectId,
    ) -> Result<ObjectDigest, ProjectAuthorizationSourceErrorV2> {
        // The preceding authenticated read validated this pair. The store's
        // Controller writer prevents either record changing before this read.
        let head_bytes = self
            .journal
            .get(RecordNamespace::PublisherPolicy, &head_key(project))
            .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
        Ok(retained_head_digest(head_bytes))
    }

    /// Authenticates the current retained decision with the fixed issuer pin.
    ///
    /// Structural journal replay does not establish the AOSPSC02 signature.
    /// A future Source consumer must use this read while retaining the
    /// Controller writer, then keep that writer through its Source append.
    ///
    /// # Errors
    ///
    /// Rejects missing or replaced credential custody, a changed publisher
    /// head, invalid signature, or a retained row inconsistent with its packet.
    pub(crate) fn current_authenticated_project_authorization_from_fixed_issuer_v2(
        &self,
        project: ProjectId,
    ) -> Result<
        Option<VerifiedPublisherProjectAuthorizationSourceV2>,
        ProjectAuthorizationSourceErrorV2,
    > {
        self.require_fixed_controller_writer_v2()?;
        let issuer = ProtectedProjectAuthorizationIssuerV2::from_systemd_credentials()?;
        issuer.recheck()?;
        let current = self.current_authenticated_project_authorization_v2(project, issuer.pin())?;
        issuer.recheck()?;
        self.require_fixed_controller_writer_v2()?;
        Ok(current)
    }

    fn current_authenticated_project_authorization_v2(
        &self,
        project: ProjectId,
        issuer: &PinnedPublisherProjectAuthorizationIssuerV2,
    ) -> Result<
        Option<VerifiedPublisherProjectAuthorizationSourceV2>,
        ProjectAuthorizationSourceErrorV2,
    > {
        let Some(row) = self.current_retained_project_authorization_v2(project)? else {
            return Ok(None);
        };
        let floor = row
            .epoch()
            .checked_sub(1)
            .ok_or(PublisherPolicyError::CorruptState)?;
        let expected = ProjectAuthorizationSourceExpectedV2::new(project, row.request_id(), floor)?;
        let verified =
            verify_current_project_authorization_source_v2(self, row.packet(), issuer, expected)?;
        if verified.project() != row.project()
            || verified.request_id() != row.request_id()
            || verified.epoch() != row.epoch()
            || verified.issuer_generation() != row.issuer_generation()
            || verified.publisher_generation() != row.publisher_generation()
            || verified.publisher_head_digest() != row.publisher_head_digest()
            || verified.publisher_revision_digest() != row.publisher_revision_digest()
            || verified.packet_digest() != row.packet_digest()
            || verified.limits() != row.limits()
        {
            return Err(PublisherPolicyError::CorruptState.into());
        }
        Ok(Some(verified))
    }

    /// Retains a signed decision using the fixed privileged issuer credential.
    ///
    /// The credential is rechecked around the protected journal transaction.
    /// This is an owner-internal retention step, not Source append authority.
    ///
    /// # Errors
    ///
    /// Rejects absent, malformed, or replaced issuer custody and all invalid
    /// packet, current-head, or journal states.
    pub(crate) fn retain_project_authorization_from_fixed_issuer_v2(
        &mut self,
        transaction_id: [u8; 16],
        project: ProjectId,
        request_id: [u8; 16],
        packet: &[u8],
    ) -> Result<ProjectAuthorizationRetentionV2, ProjectAuthorizationSourceErrorV2> {
        self.require_fixed_controller_writer_v2()?;
        let issuer = ProtectedProjectAuthorizationIssuerV2::from_systemd_credentials()?;
        issuer.recheck()?;
        let result = self.retain_project_authorization_source_v2(
            transaction_id,
            project,
            request_id,
            packet,
            issuer.pin(),
        )?;
        issuer.recheck()?;
        self.require_fixed_controller_writer_v2()?;
        Ok(result)
    }

    /// Joins both administrative signatures to actual current publisher state.
    pub(crate) fn prepare_source_genesis_acceptance_from_fixed_issuers_v1(
        &mut self,
        project: ProjectId,
        seed: [u8; 224],
        authorization: impl AsRef<[u8]>,
    ) -> Result<
        aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceRecordV1,
        super::PublisherProjectGenesisErrorV1,
    > {
        use super::PublisherProjectGenesisErrorV1;
        use aos_sandbox_broker::systemd_credentials::PinnedSystemdCredential;

        let authorization = authorization.as_ref();

        self.require_fixed_controller_writer_v2()?;
        let claims = parse_unverified_project_authorization_claims_v2(&authorization)?;
        if claims.project() != project {
            return Err(PublisherProjectGenesisErrorV1::NonCanonical);
        }
        // Reject an invalid seed or mismatched prospective head before the
        // administrative epoch is retained. This is a read-only precondition
        // under the actual writer, never prospective-current authority. Both
        // original issuer files stay retained across the effect and readback.
        let seed_pin = PinnedSystemdCredential::load_controller_source_tree_seed_issuer_v1()
            .map_err(|_| PublisherProjectGenesisErrorV1::Stale)?;
        let authorization_pin = PinnedSystemdCredential::load_project_authorization_issuer_v2()
            .map_err(|_| PublisherProjectGenesisErrorV1::Stale)?;
        let seed_issuer = PinnedControllerSourceTreeSeedIssuerV1::decode(seed_pin.bytes())?;
        let authorization_issuer =
            PinnedPublisherProjectAuthorizationIssuerV2::decode(authorization_pin.bytes())
                .map_err(crate::publisher_admin::policy::ProjectAuthorizationSourceErrorV2::from)?;
        seed_pin
            .recheck()
            .map_err(|_| PublisherProjectGenesisErrorV1::Stale)?;
        authorization_pin
            .recheck()
            .map_err(|_| PublisherProjectGenesisErrorV1::Stale)?;
        self.preflight_source_genesis_retention_v1(
            project,
            claims.request_id(),
            seed,
            authorization,
            &seed_issuer,
            &authorization_issuer,
            administrative_roles_digest_v1(seed_pin.bytes(), authorization_pin.bytes()),
        )
        .map_err(|error| match error {
            CurrentSourceTreeSeedPreflightErrorV1::MissingAuthorization => {
                PublisherProjectGenesisErrorV1::Stale
            }
            CurrentSourceTreeSeedPreflightErrorV1::Authorization(error) => error.into(),
            CurrentSourceTreeSeedPreflightErrorV1::Seed(error) => error.into(),
            CurrentSourceTreeSeedPreflightErrorV1::Acceptance(error) => error,
        })?;
        seed_pin
            .recheck()
            .map_err(|_| PublisherProjectGenesisErrorV1::Stale)?;
        authorization_pin
            .recheck()
            .map_err(|_| PublisherProjectGenesisErrorV1::Stale)?;
        self.require_fixed_controller_writer_v2()?;

        let transaction = commitment(
            b"aos.sandbox.source-genesis.project-authorization-retention.v1\0",
            authorization,
        );
        let mut transaction_id = [0; 16];
        transaction_id.copy_from_slice(&transaction.as_bytes()[..16]);
        self.retain_project_authorization_from_fixed_issuer_v2(
            transaction_id,
            project,
            claims.request_id(),
            &authorization,
        )?;
        seed_pin
            .recheck()
            .map_err(|_| PublisherProjectGenesisErrorV1::Stale)?;
        authorization_pin
            .recheck()
            .map_err(|_| PublisherProjectGenesisErrorV1::Stale)?;
        self.require_fixed_controller_writer_v2()?;
        // Reauthenticate the actual committed current head; the preflight DATA
        // is never cached across this journal effect or a coordinator phase.
        self.current_source_genesis_acceptance_from_fixed_issuers_v1(project, seed, authorization)
    }

    #[cfg(any(target_os = "linux", test))]
    #[allow(clippy::too_many_arguments)]
    fn preflight_source_genesis_retention_v1(
        &self,
        project: ProjectId,
        request_id: [u8; 16],
        seed: [u8; 224],
        authorization: impl AsRef<[u8]>,
        seed_issuer: &PinnedControllerSourceTreeSeedIssuerV1,
        authorization_issuer: &PinnedPublisherProjectAuthorizationIssuerV2,
        administrative_roles: ObjectDigest,
    ) -> Result<(), CurrentSourceTreeSeedPreflightErrorV1> {
        let authorization = authorization.as_ref();
        let (verified, _) = self.verify_project_authorization_retention_v2(
            project,
            request_id,
            &authorization,
            authorization_issuer,
        )?;
        let row = row_from_verified(verified, &authorization)?;
        let head = head_for_row(&row);
        assemble_current_source_genesis_pair_v1(
            seed,
            authorization,
            verified,
            retained_head_digest(&encode_head(head)),
            seed_issuer,
            authorization_issuer,
            administrative_roles,
        )?;
        Ok(())
    }

    pub(crate) fn current_source_genesis_acceptance_from_fixed_issuers_v1(
        &self,
        project: ProjectId,
        seed: [u8; 224],
        authorization: impl AsRef<[u8]>,
    ) -> Result<
        aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceRecordV1,
        super::PublisherProjectGenesisErrorV1,
    > {
        use super::PublisherProjectGenesisErrorV1;

        self.inspect_current_source_genesis_pair_from_fixed_issuers_v1(project, seed, authorization)
            .map_err(|error| match error {
                CurrentSourceTreeSeedPreflightErrorV1::Acceptance(error) => error,
                _ => PublisherProjectGenesisErrorV1::Stale,
            })
    }

    /// Reads the exact current pair once under this store's Controller writer.
    ///
    /// Both fixed issuer files remain retained until the joined read is checked
    /// again. The result is the existing acceptance DATA, not admission or a
    /// cacheable currentness proof. Later phases must perform their own read.
    ///
    /// # Errors
    ///
    /// Distinguishes absent current authorization from invalid signatures,
    /// changed publisher or authorization heads, replaced issuer custody,
    /// differing packets and shared administrative role keys.
    #[cfg(target_os = "linux")]
    pub(crate) fn inspect_current_source_genesis_pair_from_fixed_issuers_v1(
        &self,
        project: ProjectId,
        seed: [u8; 224],
        authorization: impl AsRef<[u8]>,
    ) -> Result<
        aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceRecordV1,
        CurrentSourceTreeSeedPreflightErrorV1,
    > {
        use aos_sandbox_broker::systemd_credentials::PinnedSystemdCredential;

        let authorization = authorization.as_ref();

        self.require_fixed_controller_writer_v2()?;
        let authorization_pin = PinnedSystemdCredential::load_project_authorization_issuer_v2()
            .map_err(|_| ProjectAuthorizationSourceErrorV2::Credential)?;
        let authorization_issuer =
            PinnedPublisherProjectAuthorizationIssuerV2::decode(authorization_pin.bytes())
                .map_err(crate::publisher_admin::policy::ProjectAuthorizationSourceErrorV2::from)?;
        authorization_pin
            .recheck()
            .map_err(|_| ProjectAuthorizationSourceErrorV2::Credential)?;
        let (current, authorization_head) =
            self.current_source_genesis_authorization_v1(project, &authorization_issuer)?;

        // Preserve the missing-authorization result before attempting seed
        // validation. Both roles then use these same retained credential bytes.
        let seed_pin = PinnedSystemdCredential::load_controller_source_tree_seed_issuer_v1()
            .map_err(|_| ControllerSourceTreeSeedErrorV1::Credential)?;
        let seed_issuer = PinnedControllerSourceTreeSeedIssuerV1::decode(seed_pin.bytes())?;
        seed_pin
            .recheck()
            .map_err(|_| ControllerSourceTreeSeedErrorV1::Credential)?;
        let pair = assemble_current_source_genesis_pair_v1(
            seed,
            authorization,
            current,
            authorization_head,
            &seed_issuer,
            &authorization_issuer,
            administrative_roles_digest_v1(seed_pin.bytes(), authorization_pin.bytes()),
        )?;

        seed_pin
            .recheck()
            .map_err(|_| ControllerSourceTreeSeedErrorV1::Credential)?;
        authorization_pin
            .recheck()
            .map_err(|_| ProjectAuthorizationSourceErrorV2::Credential)?;
        self.require_fixed_controller_writer_v2()?;
        Ok(pair)
    }

    /// Rejoins completed genesis provenance without claiming old heads are current.
    pub(crate) fn recheck_historical_source_genesis_acceptance_from_fixed_issuers_v1(
        &self,
        acceptance: &aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceRecordV1,
    ) -> Result<(), super::PublisherProjectGenesisErrorV1> {
        use aos_sandbox_protocol::publisher_project_authorization::verify_signed_project_authorization_claims_v2;
        use super::PublisherProjectGenesisErrorV1;
        use aos_sandbox_protocol::controller_source_seed::ControllerSourceTreeSeedExpectedV1;
        use aos_sandbox_broker::source_seed_credential::verify_controller_source_tree_seed_from_fixed_issuer_v1;
        use aos_sandbox_broker::systemd_credentials::PinnedSystemdCredential;

        self.require_fixed_controller_writer_v2()?;
        let seed = acceptance.seed_claims()?;
        let bytes = self
            .journal
            .get(
                RecordNamespace::PublisherPolicy,
                &row_key(acceptance.project(), seed.request_id()),
            )
            .ok_or(PublisherProjectGenesisErrorV1::Stale)?;
        let row = decode_row(bytes).map_err(PublisherPolicyError::from)?;
        validate_historical_row(super::super::PublisherReadDataV2::from_state_v2(self.journal.historical_read_view_v1().materialized_state_v1()), &row).map_err(PublisherPolicyError::from)?;
        if row.packet() != acceptance.auth_packet()
            || row.publisher_head_digest() != acceptance.publisher_pointer()
            || row.publisher_revision_digest() != acceptance.publisher_revision()
        {
            return Err(PublisherProjectGenesisErrorV1::Stale);
        }
        let historical_head = encode_head(RetainedProjectAuthorizationHeadV2::from_historical_fields(
            row.packet().len() == PROJECT_AUTHORIZATION_SOURCE_BYTES_V3,
            row.project(),
            row.epoch(),
            row.request_id(),
            project_auth_row_digest(bytes)
        ));
        if retained_head_digest(&historical_head) != acceptance.authorization_head() {
            return Err(PublisherProjectGenesisErrorV1::Stale);
        }
        let seed_pin = PinnedSystemdCredential::load_controller_source_tree_seed_issuer_v1()
            .map_err(|_| PublisherProjectGenesisErrorV1::Stale)?;
        let authorization_pin = PinnedSystemdCredential::load_project_authorization_issuer_v2()
            .map_err(|_| PublisherProjectGenesisErrorV1::Stale)?;
        if administrative_roles_digest_v1(seed_pin.bytes(), authorization_pin.bytes())
            != acceptance.administrative_roles()
        {
            return Err(PublisherProjectGenesisErrorV1::Stale);
        }
        let issuer =
            PinnedPublisherProjectAuthorizationIssuerV2::decode(authorization_pin.bytes())
                .map_err(crate::publisher_admin::policy::ProjectAuthorizationSourceErrorV2::from)?;
        verify_signed_project_authorization_claims_v2(acceptance.auth_packet(), &issuer)
            .map_err(crate::publisher_admin::policy::ProjectAuthorizationSourceErrorV2::from)?;
        verify_controller_source_tree_seed_from_fixed_issuer_v1(
            acceptance.seed_packet(),
            ControllerSourceTreeSeedExpectedV1::new(
                row.project(),
                row.publisher_generation(),
                row.publisher_head_digest(),
                acceptance.authorization_head(),
                row.request_id(),
                0,
            )?,
        )?;
        seed_pin
            .recheck()
            .map_err(|_| PublisherProjectGenesisErrorV1::Stale)?;
        authorization_pin
            .recheck()
            .map_err(|_| PublisherProjectGenesisErrorV1::Stale)?;
        self.require_fixed_controller_writer_v2()?;
        Ok(())
    }

    /// Retains a signed administrative decision with an already checked pin.
    ///
    /// Only the fixed-credential entry point may call this in production.
    ///
    /// # Errors
    ///
    /// Rejects changed publisher heads, signer/request/epoch reuse, malformed
    /// rows, or journal errors. An I/O error requires a fresh protected reopen.
    fn retain_project_authorization_source_v2(
        &mut self,
        transaction_id: [u8; 16],
        project: ProjectId,
        request_id: [u8; 16],
        packet: &[u8],
        issuer: &PinnedPublisherProjectAuthorizationIssuerV2,
    ) -> Result<ProjectAuthorizationRetentionV2, ProjectAuthorizationSourceErrorV2> {
        let (verified, exact_replay) =
            self.verify_project_authorization_retention_v2(project, request_id, packet, issuer)?;
        if exact_replay {
            return Ok(ProjectAuthorizationRetentionV2::ExactReplay);
        }
        let row = row_from_verified(verified, packet)?;
        let row_bytes = encode_row(&row);
        let next_head = head_for_row(&row);
        let result = self.commit_bounded(
            transaction_id,
            vec![
                JournalRecord::put(
                    RecordNamespace::PublisherPolicy,
                    row_key(project, request_id),
                    row_bytes,
                ),
                JournalRecord::put(
                    RecordNamespace::PublisherPolicy,
                    head_key(project),
                    encode_head(next_head),
                ),
            ],
        )?;
        Ok(ProjectAuthorizationRetentionV2::Committed(result))
    }

    // Shares only the exact current publisher/request/epoch calculation used
    // by retention and its pre-effect seed check. No journal effect or opaque
    // current/Root authority is created by these ephemeral verified DATA.
    fn verify_project_authorization_retention_v2(
        &self,
        project: ProjectId,
        request_id: [u8; 16],
        packet: &[u8],
        issuer: &PinnedPublisherProjectAuthorizationIssuerV2,
    ) -> Result<
        (VerifiedPublisherProjectAuthorizationSourceV2, bool),
        ProjectAuthorizationSourceErrorV2,
    > {
        self.journal
            .ensure_protected_authority()
            .map_err(PublisherPolicyError::from)?;
        let head = self
            .journal
            .get(RecordNamespace::PublisherPolicy, &head_key(project))
            .map(decode_head)
            .transpose()?;
        let previous = self
            .journal
            .get(
                RecordNamespace::PublisherPolicy,
                &row_key(project, request_id),
            )
            .map(decode_row)
            .transpose()?;
        let exact_replay = previous.as_ref().is_some_and(|row| {
            row.packet() == packet
                && head.is_some_and(|head| {
                    head.request_id() == request_id
                        && head.epoch() == row.epoch()
                        && head.resource_version() == row.resource_version()
                        && head.row_digest() == project_auth_row_digest(&encode_row(row))
                })
        });
        if previous.is_some() && !exact_replay {
            return Err(ProjectAuthorizationSourceErrorV2::Stale);
        }
        let floor = if exact_replay {
            head.ok_or(ProjectAuthorizationSourceErrorV2::Stale)?
                .epoch()
                .checked_sub(1)
                .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?
        } else {
            head.map_or(0, |head| head.epoch())
        };
        let expected = ProjectAuthorizationSourceExpectedV2::new(project, request_id, floor)?;
        let verified =
            verify_current_project_authorization_source_v2(self, packet, issuer, expected)?;
        Ok((verified, exact_replay))
    }

    /// Reads the retained current decision only while its publisher cut matches.
    ///
    /// This read does not reverify the issuer signature and is not a Source
    /// seed capability. A subsequent policy update leaves historical rows
    /// replayable while making the current decision stale.
    ///
    /// # Errors
    ///
    /// Rejects a malformed retained pair, missing policy, or changed pointer
    /// or revision bytes.
    fn current_retained_project_authorization_v2(
        &self,
        project: ProjectId,
    ) -> Result<Option<RetainedProjectAuthorizationRowV2>, ProjectAuthorizationSourceErrorV2> {
        self.journal
            .ensure_protected_authority()
            .map_err(PublisherPolicyError::from)?;
        let Some(head_bytes) = self
            .journal
            .get(RecordNamespace::PublisherPolicy, &head_key(project))
        else {
            return Ok(None);
        };
        let head = decode_head(head_bytes)?;
        let row_bytes = self
            .journal
            .get(
                RecordNamespace::PublisherPolicy,
                &row_key(project, head.request_id()),
            )
            .ok_or(PublisherPolicyError::CorruptState)?;
        let row = decode_row(row_bytes).map_err(PublisherPolicyError::from)?;
        if head.project() != project
            || head.epoch() != row.epoch()
            || head.resource_version() != (row.packet().len() == PROJECT_AUTHORIZATION_SOURCE_BYTES_V3)
            || head.row_digest() != project_auth_row_digest(row_bytes)
        {
            return Err(PublisherPolicyError::CorruptState.into());
        }
        let current = self
            .current_policy(project)?
            .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
        let current_head = self
            .journal
            .get(
                RecordNamespace::PublisherPolicy,
                &policy_current_key(project),
            )
            .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
        let current_revision = self
            .journal
            .get(
                RecordNamespace::PublisherPolicy,
                &policy_revision_key(project, current.generation()),
            )
            .ok_or(ProjectAuthorizationSourceErrorV2::Stale)?;
        if row.publisher_generation() != current.generation()
            || row.publisher_head_digest() != commitment(HEAD_DOMAIN, current_head)
            || row.publisher_revision_digest() != commitment(REVISION_DOMAIN, current_revision)
        {
            return Err(ProjectAuthorizationSourceErrorV2::Stale);
        }
        Ok(Some(row))
    }
}

fn head_for_row(row: &RetainedProjectAuthorizationRowV2) -> RetainedProjectAuthorizationHeadV2 {
    RetainedProjectAuthorizationHeadV2::from_historical_fields(
            row.packet().len() == PROJECT_AUTHORIZATION_SOURCE_BYTES_V3,
            row.project(),
            row.epoch(),
            row.request_id(),
            project_auth_row_digest(&encode_row(row))
        )
}

fn administrative_roles_digest_v1(
    seed_credential: &[u8],
    authorization_credential: &[u8],
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.source-genesis.administrative-roles.v1\0")
            .chain_update(seed_credential)
            .chain_update(authorization_credential)
            .finalize()
            .into(),
    )
}

// These arguments are DATA derived in one current read, not an authority
// constructor. The production caller retains both fixed credentials and the
// Controller writer; no joined result survives to replace a later recheck.
#[cfg(any(target_os = "linux", test))]
fn assemble_current_source_genesis_pair_v1(
    seed: [u8; 224],
    authorization: impl AsRef<[u8]>,
    current: VerifiedPublisherProjectAuthorizationSourceV2,
    authorization_head: ObjectDigest,
    seed_issuer: &PinnedControllerSourceTreeSeedIssuerV1,
    authorization_issuer: &PinnedPublisherProjectAuthorizationIssuerV2,
    administrative_roles: ObjectDigest,
) -> Result<
    aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceRecordV1,
    CurrentSourceTreeSeedPreflightErrorV1,
> {
    use aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceRecordV1;
    use super::PublisherProjectGenesisErrorV1;

    let authorization = authorization.as_ref();

    verify_seed_for_current_authorization_v1(
        &seed,
        current,
        authorization_head,
        |packet, expected| verify_controller_source_tree_seed_v1(packet, seed_issuer, expected),
    )?;
    if current.packet_digest() != project_authorization_packet_digest(authorization)
        .map_err(ProjectAuthorizationSourceErrorV2::from)?
        || seed_issuer.verifying_key() == authorization_issuer.verifying_key()
    {
        return Err(PublisherProjectGenesisErrorV1::Stale.into());
    }
    Ok(ControllerSourceGenesisAcceptanceRecordV1::new(
        seed,
        authorization,
        current.publisher_head_digest(),
        current.publisher_revision_digest(),
        authorization_head,
        administrative_roles,
    )
    .map_err(PublisherProjectGenesisErrorV1::from)?)
}

#[cfg(any(target_os = "linux", test))]
fn verify_seed_for_current_authorization_v1(
    packet: &[u8],
    authorization: VerifiedPublisherProjectAuthorizationSourceV2,
    authorization_head_digest: ObjectDigest,
    verify_seed: impl FnOnce(
        &[u8],
        ControllerSourceTreeSeedExpectedV1,
    ) -> Result<
        VerifiedControllerSourceTreeSeedV1,
        ControllerSourceTreeSeedErrorV1,
    >,
) -> Result<VerifiedControllerSourceTreeSeedV1, CurrentSourceTreeSeedPreflightErrorV1> {
    let epoch_floor = authorization
        .epoch()
        .checked_sub(1)
        .ok_or(ControllerSourceTreeSeedErrorV1::Stale)?;
    let expected = ControllerSourceTreeSeedExpectedV1::new(
        authorization.project(),
        authorization.publisher_generation(),
        authorization.publisher_head_digest(),
        authorization_head_digest,
        authorization.request_id(),
        epoch_floor,
    )?;
    let verified = verify_seed(packet, expected)?;
    if verified.seed().epoch() != authorization.epoch()
        || verified.seed().limits() != authorization.limits()
    {
        return Err(ControllerSourceTreeSeedErrorV1::Stale.into());
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use crate::JournalTransaction;
    use aos_sandbox_protocol::source_genesis_acceptance::ControllerSourceGenesisAcceptanceRecordV1;
    use super::PublisherProjectGenesisErrorV1;
    use aos_sandbox_protocol::controller_source_seed::{
        ControllerSourceTreeSeedV1, PinnedControllerSourceTreeSeedIssuerV1,
        encode_controller_source_tree_seed_credential_v1, sign_controller_source_tree_seed_v1,
        verify_controller_source_tree_seed_v1,
    };

    use super::*;

    use crate::publisher_admin::policy::project_authorization_test_fixture::{
        TestDirectory, packet as signed_packet, pin as issuer_pin, policy as policy_at,
    };
    use crate::publisher_admin::policy::{PublisherPolicyLimits};
    use aos_sandbox_protocol::policy_data::PreparedPublisherPolicyRevisionV1;

    #[test]
    fn administrative_roles_digest_preserves_old_preimage_and_role_order() {
        let seed_signer = SigningKey::from_bytes(&[19; 32]);
        let authorization_signer = SigningKey::from_bytes(&[20; 32]);
        let seed =
            encode_controller_source_tree_seed_credential_v1(11, &seed_signer.verifying_key())
                .unwrap();
        let authorization = encode_project_authorization_issuer_credential_v2(
            7,
            &authorization_signer.verifying_key(),
        )
        .unwrap();

        let old_preimage = [seed.as_slice(), authorization.as_slice()].concat();
        let digest = administrative_roles_digest_v1(&seed, &authorization);

        assert_eq!(
            digest,
            commitment(
                b"aos.sandbox.source-genesis.administrative-roles.v1\0",
                &old_preimage
            ),
        );
        assert_ne!(
            digest,
            administrative_roles_digest_v1(&authorization, &seed)
        );
    }

    fn policy(project: ProjectId, generation: u64) -> PreparedPublisherPolicyRevisionV1 {
        policy_at(project, generation, 100)
    }

    fn packet(
        store: &PublisherPolicyStore<'_>,
        project: ProjectId,
        request_id: [u8; 16],
        epoch: u64,
        signer: &SigningKey,
    ) -> [u8; PACKET_BYTES] {
        signed_packet(store, project, signer, 7, request_id, epoch)
    }

    fn pin(signer: &SigningKey) -> PinnedPublisherProjectAuthorizationIssuerV2 {
        issuer_pin(signer, 7)
    }

    fn initial_store(journal: &mut Journal, project: ProjectId) -> PublisherPolicyStore<'_> {
        let mut store =
            PublisherPolicyStore::load(journal, PublisherPolicyLimits::default()).unwrap();
        store
            .publish_policy_from_trusted_controller([3; 16], None, &policy(project, 1))
            .unwrap();
        store
    }

    #[test]
    fn prospective_seed_preflight_precedes_retention_and_matches_actual_head() {
        // Actual protected journal and signature-leaf fixtures, not fixed
        // production credentials, a Root flight, or an ancestry/read grant.
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([17; 16]);
        let authorization_signer = SigningKey::from_bytes(&[18; 32]);
        let seed_signer = SigningKey::from_bytes(&[19; 32]);
        let authorization_issuer = pin(&authorization_signer);
        let seed_credential =
            encode_controller_source_tree_seed_credential_v1(11, &seed_signer.verifying_key())
                .unwrap();
        let seed_issuer = PinnedControllerSourceTreeSeedIssuerV1::decode(&seed_credential).unwrap();
        let authorization_credential = encode_project_authorization_issuer_credential_v2(
            7,
            &authorization_signer.verifying_key(),
        )
        .unwrap();
        let roles = administrative_roles_digest_v1(&seed_credential, &authorization_credential);
        let mut journal = directory.open();
        let mut store = initial_store(&mut journal, project);
        let authorization = packet(&store, project, [20; 16], 9, &authorization_signer);
        let (verified, replay) = store
            .verify_project_authorization_retention_v2(
                project,
                [20; 16],
                &authorization,
                &authorization_issuer,
            )
            .unwrap();
        assert!(!replay);
        let row = row_from_verified(verified, &authorization).unwrap();
        let expected_head = encode_head(RetainedProjectAuthorizationHeadV2::from_historical_fields(
            false,
            project,
            9,
            [20; 16],
            commitment(ROW_DOMAIN, &encode_row(&row))
        ));
        let expected_digest = commitment(RETAINED_HEAD_DOMAIN, &expected_head);
        let seed = ControllerSourceTreeSeedV1::new(
            project,
            verified.limits(),
            verified.publisher_generation(),
            verified.publisher_head_digest(),
            expected_digest,
            [20; 16],
            9,
        )
        .unwrap();
        let seed_packet = sign_controller_source_tree_seed_v1(seed, 11, &seed_signer).unwrap();
        let initial_sequence = store.journal.snapshot_sequence();
        let initial_rows = store
            .journal
            .all_records()
            .map(|(namespace, key, value)| (namespace, key.to_vec(), value.to_vec()))
            .collect::<Vec<_>>();

        let mut altered = seed_packet;
        altered[223] ^= 1;
        assert!(matches!(
            store.preflight_source_genesis_retention_v1(
                project,
                [20; 16],
                altered,
                authorization,
                &seed_issuer,
                &authorization_issuer,
                roles,
            ),
            Err(CurrentSourceTreeSeedPreflightErrorV1::Seed(
                ControllerSourceTreeSeedErrorV1::Signature
            ))
        ));
        let wrong_head_seed = ControllerSourceTreeSeedV1::new(
            project,
            verified.limits(),
            verified.publisher_generation(),
            verified.publisher_head_digest(),
            ObjectDigest::from_bytes([21; 32]),
            [20; 16],
            9,
        )
        .unwrap();
        let wrong_head =
            sign_controller_source_tree_seed_v1(wrong_head_seed, 11, &seed_signer).unwrap();
        assert!(matches!(
            store.preflight_source_genesis_retention_v1(
                project,
                [20; 16],
                wrong_head,
                authorization,
                &seed_issuer,
                &authorization_issuer,
                roles,
            ),
            Err(CurrentSourceTreeSeedPreflightErrorV1::Seed(
                ControllerSourceTreeSeedErrorV1::Stale
            ))
        ));
        store
            .preflight_source_genesis_retention_v1(
                project,
                [20; 16],
                seed_packet,
                authorization,
                &seed_issuer,
                &authorization_issuer,
                roles,
            )
            .unwrap();
        assert_eq!(store.journal.snapshot_sequence(), initial_sequence);
        assert_eq!(
            store
                .journal
                .all_records()
                .map(|(namespace, key, value)| (namespace, key.to_vec(), value.to_vec()))
                .collect::<Vec<_>>(),
            initial_rows
        );
        assert!(
            store
                .current_retained_project_authorization_v2(project)
                .unwrap()
                .is_none()
        );

        store
            .retain_project_authorization_source_v2(
                [22; 16],
                project,
                [20; 16],
                &authorization,
                &authorization_issuer,
            )
            .unwrap();
        assert_eq!(
            store
                .current_project_authorization_head_digest_v2(project)
                .unwrap(),
            expected_digest
        );
        assert_eq!(
            store
                .journal
                .get(RecordNamespace::PublisherPolicy, &head_key(project))
                .unwrap(),
            expected_head.as_slice()
        );
        let retained_sequence = store.journal.snapshot_sequence();
        store
            .preflight_source_genesis_retention_v1(
                project,
                [20; 16],
                seed_packet,
                authorization,
                &seed_issuer,
                &authorization_issuer,
                roles,
            )
            .unwrap();
        assert!(matches!(
            store
                .retain_project_authorization_source_v2(
                    [22; 16],
                    project,
                    [20; 16],
                    &authorization,
                    &authorization_issuer,
                )
                .unwrap(),
            ProjectAuthorizationRetentionV2::ExactReplay
        ));
        assert_eq!(store.journal.snapshot_sequence(), retained_sequence);

        let successor = packet(&store, project, [23; 16], 10, &authorization_signer);
        store
            .retain_project_authorization_source_v2(
                [24; 16],
                project,
                [23; 16],
                &successor,
                &authorization_issuer,
            )
            .unwrap();
        assert!(matches!(
            store.preflight_source_genesis_retention_v1(
                project,
                [20; 16],
                seed_packet,
                authorization,
                &seed_issuer,
                &authorization_issuer,
                roles,
            ),
            Err(CurrentSourceTreeSeedPreflightErrorV1::Authorization(
                ProjectAuthorizationSourceErrorV2::Stale
            ))
        ));
    }

    #[test]
    fn current_seed_preflight_joins_both_signatures_and_exact_controller_cut() {
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let authorization_signer = SigningKey::from_bytes(&[2; 32]);
        let seed_signer = SigningKey::from_bytes(&[42; 32]);
        let seed_credential =
            encode_controller_source_tree_seed_credential_v1(11, &seed_signer.verifying_key())
                .unwrap();
        let seed_issuer = PinnedControllerSourceTreeSeedIssuerV1::decode(&seed_credential).unwrap();
        let mut journal = directory.open();
        let mut store = initial_store(&mut journal, project);
        let authorization_packet = packet(&store, project, [4; 16], 9, &authorization_signer);
        store
            .retain_project_authorization_source_v2(
                [5; 16],
                project,
                [4; 16],
                &authorization_packet,
                &pin(&authorization_signer),
            )
            .unwrap();
        let authorization_issuer = pin(&authorization_signer);
        let (authorization, head_digest) = store
            .current_source_genesis_authorization_v1(project, &authorization_issuer)
            .unwrap();
        assert_eq!(
            Some(authorization),
            store
                .current_authenticated_project_authorization_v2(project, &authorization_issuer)
                .unwrap()
        );
        let seed = ControllerSourceTreeSeedV1::new(
            project,
            authorization.limits(),
            authorization.publisher_generation(),
            authorization.publisher_head_digest(),
            head_digest,
            authorization.request_id(),
            authorization.epoch(),
        )
        .unwrap();
        let seed_packet =
            sign_controller_source_tree_seed_v1(seed, seed_issuer.generation(), &seed_signer)
                .unwrap();
        let verify = |packet: &[u8], expected| {
            verify_controller_source_tree_seed_v1(packet, &seed_issuer, expected)
        };
        assert_eq!(
            verify_seed_for_current_authorization_v1(
                &seed_packet,
                authorization,
                head_digest,
                verify,
            )
            .unwrap()
            .seed(),
            seed
        );
        let authorization_credential = encode_project_authorization_issuer_credential_v2(
            7,
            &authorization_signer.verifying_key(),
        )
        .unwrap();
        let roles = administrative_roles_digest_v1(&seed_credential, &authorization_credential);
        assert_eq!(
            roles,
            commitment(
                b"aos.sandbox.source-genesis.administrative-roles.v1\0",
                &[
                    seed_credential.as_slice(),
                    authorization_credential.as_slice()
                ]
                .concat(),
            )
        );
        let assemble = |seed_packet, authorization_packet| {
            assemble_current_source_genesis_pair_v1(
                seed_packet,
                authorization_packet,
                authorization,
                head_digest,
                &seed_issuer,
                &authorization_issuer,
                roles,
            )
        };
        let pair = assemble(seed_packet, authorization_packet).unwrap();
        let expected = ControllerSourceGenesisAcceptanceRecordV1::new(
            seed_packet,
            authorization_packet,
            authorization.publisher_head_digest(),
            authorization.publisher_revision_digest(),
            head_digest,
            roles,
        )
        .unwrap();
        assert_eq!(pair, expected);

        let mismatch = |seed: ControllerSourceTreeSeedV1| {
            let packet =
                sign_controller_source_tree_seed_v1(seed, seed_issuer.generation(), &seed_signer)
                    .unwrap();
            assemble(packet, authorization_packet)
        };
        let changed =
            |limits, publisher_generation, publisher_head, authorization_head, request, epoch| {
                ControllerSourceTreeSeedV1::new(
                    project,
                    limits,
                    publisher_generation,
                    publisher_head,
                    authorization_head,
                    request,
                    epoch,
                )
                .unwrap()
            };
        for altered in [
            changed(
                seed.limits(),
                2,
                seed.publisher_head(),
                head_digest,
                [4; 16],
                9,
            ),
            changed(
                seed.limits(),
                1,
                ObjectDigest::from_bytes([8; 32]),
                head_digest,
                [4; 16],
                9,
            ),
            changed(
                seed.limits(),
                1,
                seed.publisher_head(),
                ObjectDigest::from_bytes([8; 32]),
                [4; 16],
                9,
            ),
            changed(
                seed.limits(),
                1,
                seed.publisher_head(),
                head_digest,
                [8; 16],
                9,
            ),
            changed(
                seed.limits(),
                1,
                seed.publisher_head(),
                head_digest,
                [4; 16],
                10,
            ),
            changed(
                TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 2).unwrap(),
                1,
                seed.publisher_head(),
                head_digest,
                [4; 16],
                9,
            ),
        ] {
            assert!(matches!(
                mismatch(altered),
                Err(CurrentSourceTreeSeedPreflightErrorV1::Seed(
                    ControllerSourceTreeSeedErrorV1::Stale
                ))
            ));
        }

        let mut altered_seed = seed_packet;
        altered_seed[223] ^= 1;
        assert!(matches!(
            assemble(altered_seed, authorization_packet),
            Err(CurrentSourceTreeSeedPreflightErrorV1::Seed(
                ControllerSourceTreeSeedErrorV1::Signature
            ))
        ));
        let other_authorization = packet(&store, project, [8; 16], 9, &authorization_signer);
        assert!(matches!(
            assemble(seed_packet, other_authorization),
            Err(CurrentSourceTreeSeedPreflightErrorV1::Acceptance(
                PublisherProjectGenesisErrorV1::Stale
            ))
        ));
        let shared_key_issuer = pin(&seed_signer);
        assert!(matches!(
            assemble_current_source_genesis_pair_v1(
                seed_packet,
                authorization_packet,
                authorization,
                head_digest,
                &seed_issuer,
                &shared_key_issuer,
                roles,
            ),
            Err(CurrentSourceTreeSeedPreflightErrorV1::Acceptance(
                PublisherProjectGenesisErrorV1::Stale
            ))
        ));

        let rotated_key = SigningKey::from_bytes(&[43; 32]);
        let rotated_credential =
            encode_controller_source_tree_seed_credential_v1(11, &rotated_key.verifying_key())
                .unwrap();
        let rotated_issuer =
            PinnedControllerSourceTreeSeedIssuerV1::decode(&rotated_credential).unwrap();
        assert!(matches!(
            verify_seed_for_current_authorization_v1(
                &seed_packet,
                authorization,
                head_digest,
                |packet, expected| {
                    verify_controller_source_tree_seed_v1(packet, &rotated_issuer, expected)
                },
            ),
            Err(CurrentSourceTreeSeedPreflightErrorV1::Seed(
                ControllerSourceTreeSeedErrorV1::Signature
            ))
        ));

        store
            .publish_policy_from_trusted_controller([6; 16], Some(1), &policy(project, 2))
            .unwrap();
        assert!(matches!(
            store.current_authenticated_project_authorization_v2(project, &authorization_issuer),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
        assert!(matches!(
            store.current_source_genesis_authorization_v1(project, &authorization_issuer),
            Err(CurrentSourceTreeSeedPreflightErrorV1::Authorization(
                ProjectAuthorizationSourceErrorV2::Stale
            ))
        ));
    }

    #[test]
    fn current_pair_read_preserves_missing_authorization() {
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let authorization_signer = SigningKey::from_bytes(&[2; 32]);
        let mut journal = directory.open();
        let store = initial_store(&mut journal, project);

        assert!(matches!(
            store.current_source_genesis_authorization_v1(project, &pin(&authorization_signer)),
            Err(CurrentSourceTreeSeedPreflightErrorV1::MissingAuthorization)
        ));
        assert!(
            store
                .current_authenticated_project_authorization_v2(
                    project,
                    &pin(&authorization_signer)
                )
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .current_retained_project_authorization_v2(project)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn copied_protected_controller_rows_cannot_pass_fixed_current_reads() {
        let source_directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let authorization_signer = SigningKey::from_bytes(&[2; 32]);
        let mut source_journal = source_directory.open();
        let mut source = initial_store(&mut source_journal, project);
        let authorization_packet = packet(&source, project, [4; 16], 9, &authorization_signer);
        source
            .retain_project_authorization_source_v2(
                [5; 16],
                project,
                [4; 16],
                &authorization_packet,
                &pin(&authorization_signer),
            )
            .unwrap();
        let copied_records = source
            .journal
            .all_records()
            .map(|(namespace, key, value)| {
                JournalRecord::put(namespace, key.to_vec(), value.to_vec())
            })
            .collect();
        drop(source);
        drop(source_journal);

        let copy_directory = TestDirectory::new();
        let mut copied_journal = copy_directory.open_with_limits(production_journal_limits());
        copied_journal
            .commit(&JournalTransaction::new([99; 16], copied_records).unwrap())
            .unwrap();
        let copy =
            PublisherPolicyStore::load(&mut copied_journal, PublisherPolicyLimits::default())
                .unwrap();
        let authorization = copy
            .current_authenticated_project_authorization_v2(project, &pin(&authorization_signer))
            .unwrap()
            .unwrap();
        let authorization_head = copy
            .current_project_authorization_head_digest_v2(project)
            .unwrap();
        let seed_signer = SigningKey::from_bytes(&[42; 32]);
        let seed = ControllerSourceTreeSeedV1::new(
            project,
            authorization.limits(),
            authorization.publisher_generation(),
            authorization.publisher_head_digest(),
            authorization_head,
            authorization.request_id(),
            authorization.epoch(),
        )
        .unwrap();
        let seed_packet = sign_controller_source_tree_seed_v1(seed, 11, &seed_signer).unwrap();

        assert!(matches!(
            copy.current_authenticated_project_authorization_from_fixed_issuer_v2(project),
            Err(ProjectAuthorizationSourceErrorV2::Publisher(
                PublisherPolicyError::Journal(_)
            ))
        ));
        assert!(matches!(
            copy.preflight_current_source_tree_seed_from_fixed_issuers_v1(project, &seed_packet),
            Err(CurrentSourceTreeSeedPreflightErrorV1::Authorization(
                ProjectAuthorizationSourceErrorV2::Publisher(PublisherPolicyError::Journal(_))
            ))
        ));
        assert!(matches!(
            copy.inspect_current_source_genesis_pair_from_fixed_issuers_v1(
                project,
                seed_packet,
                authorization_packet,
            ),
            Err(CurrentSourceTreeSeedPreflightErrorV1::Authorization(
                ProjectAuthorizationSourceErrorV2::Publisher(PublisherPolicyError::Journal(_))
            ))
        ));
    }

    #[test]
    fn exact_attempt_survives_cold_replay_and_spends_request_and_epoch() {
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let signer = SigningKey::from_bytes(&[2; 32]);
        let mut journal = directory.open();
        let mut store = initial_store(&mut journal, project);
        let first = packet(&store, project, [4; 16], 9, &signer);
        assert!(matches!(
            store.retain_project_authorization_source_v2(
                [5; 16],
                project,
                [4; 16],
                &first,
                &pin(&signer)
            ),
            Ok(ProjectAuthorizationRetentionV2::Committed(_))
        ));
        let current = store
            .current_retained_project_authorization_v2(project)
            .unwrap()
            .unwrap();
        assert_eq!(current.packet(), first);
        assert_eq!(current.issuer_generation(), 7);
        assert_eq!(
            current.limits(),
            TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 3).unwrap()
        );
        drop(store);
        drop(journal);

        let mut reopened = directory.open();
        let mut store =
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).unwrap();
        let authenticated = store
            .current_authenticated_project_authorization_v2(project, &pin(&signer))
            .unwrap()
            .unwrap();
        assert_eq!(authenticated.request_id(), [4; 16]);
        assert_eq!(authenticated.epoch(), 9);
        assert_eq!(authenticated.limits(), current.limits());
        assert_eq!(
            store
                .retain_project_authorization_source_v2(
                    [6; 16],
                    project,
                    [4; 16],
                    &first,
                    &pin(&signer)
                )
                .unwrap(),
            ProjectAuthorizationRetentionV2::ExactReplay
        );
        let duplicate_epoch = packet(&store, project, [7; 16], 9, &signer);
        assert!(matches!(
            store.retain_project_authorization_source_v2(
                [8; 16],
                project,
                [7; 16],
                &duplicate_epoch,
                &pin(&signer)
            ),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
        let collision = packet(&store, project, [4; 16], 10, &signer);
        assert!(matches!(
            store.retain_project_authorization_source_v2(
                [9; 16],
                project,
                [4; 16],
                &collision,
                &pin(&signer)
            ),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
        let second = packet(&store, project, [7; 16], 10, &signer);
        assert!(matches!(
            store.retain_project_authorization_source_v2(
                [10; 16],
                project,
                [7; 16],
                &second,
                &pin(&signer)
            ),
            Ok(ProjectAuthorizationRetentionV2::Committed(_))
        ));
        assert!(matches!(
            store.retain_project_authorization_source_v2(
                [11; 16],
                project,
                [4; 16],
                &first,
                &pin(&signer)
            ),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
    }

    #[test]
    fn policy_advance_preserves_history_but_stales_current_authorization() {
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let signer = SigningKey::from_bytes(&[2; 32]);
        let mut journal = directory.open();
        let mut store = initial_store(&mut journal, project);
        let first = packet(&store, project, [4; 16], 9, &signer);
        store
            .retain_project_authorization_source_v2(
                [5; 16],
                project,
                [4; 16],
                &first,
                &pin(&signer),
            )
            .unwrap();
        store
            .publish_policy_from_trusted_controller([6; 16], Some(1), &policy(project, 2))
            .unwrap();
        drop(store);
        drop(journal);

        let mut reopened = directory.open();
        let mut store =
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).unwrap();
        assert!(matches!(
            store.current_retained_project_authorization_v2(project),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
        assert!(matches!(
            store.current_authenticated_project_authorization_v2(project, &pin(&signer)),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
        assert!(matches!(
            store.retain_project_authorization_source_v2(
                [7; 16],
                project,
                [4; 16],
                &first,
                &pin(&signer)
            ),
            Err(ProjectAuthorizationSourceErrorV2::Stale)
        ));
    }

    #[test]
    fn incomplete_pair_and_changed_historical_revision_fail_cold_replay() {
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let signer = SigningKey::from_bytes(&[2; 32]);
        let mut journal = directory.open();
        let mut store = initial_store(&mut journal, project);
        let first = packet(&store, project, [4; 16], 9, &signer);
        store
            .retain_project_authorization_source_v2(
                [5; 16],
                project,
                [4; 16],
                &first,
                &pin(&signer),
            )
            .unwrap();
        let second = packet(&store, project, [7; 16], 10, &signer);
        let verified = verify_current_project_authorization_source_v2(
            &store,
            &second,
            &pin(&signer),
            ProjectAuthorizationSourceExpectedV2::new(project, [7; 16], 9).unwrap(),
        )
        .unwrap();
        let orphan_row = row_from_verified(verified, &second).unwrap();
        drop(store);
        journal
            .commit(
                &JournalTransaction::new(
                    [6; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::PublisherPolicy,
                        row_key(project, [7; 16]),
                        encode_row(&orphan_row),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        let mut reopened = directory.open();
        assert!(matches!(
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()),
            Err(PublisherPolicyError::CorruptState)
        ));

        let directory = TestDirectory::new();
        let mut journal = directory.open();
        let mut store = initial_store(&mut journal, project);
        let first = packet(&store, project, [4; 16], 9, &signer);
        store
            .retain_project_authorization_source_v2(
                [5; 16],
                project,
                [4; 16],
                &first,
                &pin(&signer),
            )
            .unwrap();
        drop(store);
        let changed = policy_at(project, 1, 101);
        let revision = super::super::encode_policy_revision(&changed).unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [8; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::PublisherPolicy,
                        policy_revision_key(project, 1),
                        revision,
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);
        let mut reopened = directory.open();
        assert!(
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).is_err()
        );
    }

    #[test]
    fn changed_row_packet_or_head_digest_fails_cold_replay() {
        let project = ProjectId::from_bytes([1; 16]);
        let signer = SigningKey::from_bytes(&[2; 32]);
        for corrupt_row in [true, false] {
            let directory = TestDirectory::new();
            let mut journal = directory.open();
            let mut store = initial_store(&mut journal, project);
            let first = packet(&store, project, [4; 16], 9, &signer);
            store
                .retain_project_authorization_source_v2(
                    [5; 16],
                    project,
                    [4; 16],
                    &first,
                    &pin(&signer),
                )
                .unwrap();
            drop(store);

            let key = if corrupt_row {
                row_key(project, [4; 16])
            } else {
                head_key(project)
            };
            let mut bytes = journal
                .get(RecordNamespace::PublisherPolicy, &key)
                .unwrap()
                .to_vec();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            journal
                .commit(
                    &JournalTransaction::new(
                        [6; 16],
                        vec![JournalRecord::put(
                            RecordNamespace::PublisherPolicy,
                            key,
                            bytes,
                        )],
                    )
                    .unwrap(),
                )
                .unwrap();
            drop(journal);

            let mut reopened = directory.open();
            assert!(matches!(
                PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()),
                Err(PublisherPolicyError::CorruptState)
            ));
        }
    }

    #[test]
    fn cold_current_read_rejects_rotated_issuer_and_rechecks_packet_signature() {
        let directory = TestDirectory::new();
        let project = ProjectId::from_bytes([1; 16]);
        let signer = SigningKey::from_bytes(&[2; 32]);
        let mut journal = directory.open();
        let mut store = initial_store(&mut journal, project);
        let signed = packet(&store, project, [4; 16], 9, &signer);
        store
            .retain_project_authorization_source_v2(
                [5; 16],
                project,
                [4; 16],
                &signed,
                &pin(&signer),
            )
            .unwrap();
        drop(store);
        drop(journal);

        let mut reopened = directory.open();
        let store =
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).unwrap();
        let (current, head_digest) = store
            .current_source_genesis_authorization_v1(project, &pin(&signer))
            .unwrap();
        assert_eq!(
            Some(current),
            store
                .current_authenticated_project_authorization_v2(project, &pin(&signer))
                .unwrap()
        );
        assert_eq!(
            current.packet_digest(),
            commitment(b"aos.sandbox.publisher-project-authorization.packet.v2\0", &signed),
        );
        assert_eq!(
            head_digest,
            store
                .current_project_authorization_head_digest_v2(project)
                .unwrap()
        );
        let rotated = SigningKey::from_bytes(&[3; 32]);
        assert!(matches!(
            store.current_authenticated_project_authorization_v2(project, &pin(&rotated)),
            Err(ProjectAuthorizationSourceErrorV2::Signature)
        ));
        assert!(matches!(
            store.current_source_genesis_authorization_v1(project, &pin(&rotated)),
            Err(CurrentSourceTreeSeedPreflightErrorV1::Authorization(
                ProjectAuthorizationSourceErrorV2::Signature
            ))
        ));
        drop(store);
        drop(reopened);

        let mut journal = directory.open();
        let key = row_key(project, [4; 16]);
        let mut row =
            decode_row(journal.get(RecordNamespace::PublisherPolicy, &key).unwrap()).unwrap();
        let mut packet = row.packet().to_vec();
        packet[PACKET_BYTES - 1] ^= 1;
        row = RetainedProjectAuthorizationRowV2::from_historical_fields(
            row.project(), row.request_id(), row.epoch(), row.issuer_generation(),
            row.publisher_generation(), row.publisher_head_digest(), row.publisher_revision_digest(),
            commitment(b"aos.sandbox.publisher-project-authorization.packet.v2\0", &packet),
            row.limits(), packet,
        );
        let row_bytes = encode_row(&row);
        let head = RetainedProjectAuthorizationHeadV2::from_historical_fields(
            false,
            project,
            row.epoch(),
            row.request_id(),
            commitment(ROW_DOMAIN, &row_bytes)
        );
        journal
            .commit(
                &JournalTransaction::new(
                    [6; 16],
                    vec![
                        JournalRecord::put(RecordNamespace::PublisherPolicy, key, row_bytes),
                        JournalRecord::put(
                            RecordNamespace::PublisherPolicy,
                            head_key(project),
                            encode_head(head),
                        ),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        drop(journal);

        let mut reopened = directory.open();
        let store =
            PublisherPolicyStore::load(&mut reopened, PublisherPolicyLimits::default()).unwrap();
        assert!(matches!(
            store.current_authenticated_project_authorization_v2(project, &pin(&signer)),
            Err(ProjectAuthorizationSourceErrorV2::Signature)
        ));
        assert!(matches!(
            store.current_source_genesis_authorization_v1(project, &pin(&signer)),
            Err(CurrentSourceTreeSeedPreflightErrorV1::Authorization(
                ProjectAuthorizationSourceErrorV2::Signature
            ))
        ));
    }
}
