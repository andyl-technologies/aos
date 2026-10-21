//! Owns actual native Git bootstrap append and protected Store mutations.
//!
//! Protocol owns the sole signed-source verifier, codecs and historical reducer.
//! This module retains the real credential custody, Journal borrow and COMMIT gates.

use aos_sandbox_protocol::publisher_project_authorization::{
    HEAD_DOMAIN,
    REVISION_DOMAIN,
    commitment,
};

use aos_sandbox_model::{
    ObjectDigest, ProjectId,
};
use sha2::{Digest as _, Sha256};

use aos_sandbox_broker::systemd_credentials::PublisherPolicyBootstrapCredentialCustodyV1;
use aos_sandbox_model::{
    GitUploadCapacityV1, ResourceDimension, ResourceVector,
};

use super::*;

/// Reports the original typed failure of a non-admitting bootstrap.
#[derive(Debug, thiserror::Error)]
pub enum GitUploadBootstrapErrorV1 {
    /// The source or capacity scope is invalid.
    #[error("Git upload bootstrap source is invalid")]
    InvalidSource,
    /// The original signature engine rejected the source.
    #[error("Git upload bootstrap signature is invalid")]
    Signature(#[source] ed25519_dalek::SignatureError),
    /// The canonical object-identity engine rejected the capacity bytes.
    #[error("Git upload bootstrap object commitment is invalid")]
    Descriptor(#[source] aos_sandbox_model::ObjectDescriptorVerificationError),
    /// The canonical capacity decoder rejected the input.
    #[error("Git upload bootstrap capacity is invalid")]
    Capacity(#[source] aos_sandbox_model::CanonicalCborError),
    /// The retained state differs from the original initial source.
    #[error("Git upload bootstrap conflicts with protected state")]
    Conflict,
    /// Protected policy or journal work failed.
    #[error("Git upload bootstrap protected state failed")]
    Store(#[from] PublisherPolicyError),
}

pub use aos_sandbox_protocol::publisher_policy::git_source::VerifiedPublisherPolicySourceV1;
use aos_sandbox_protocol::publisher_policy::git_source::*;

aos_sandbox_protocol::define_provider_native_account_data_recipe_v1!(PublisherPolicyError::CorruptState);

impl PublisherPolicyStore<'_> {
    /// Preserves the existing resource, controller, revocation and policy install order.
    ///
    /// # Errors
    ///
    /// Returns a protected store error or a conflict with the exact signed source.
    pub fn install_initial_policy_from_source_v1(
        &mut self,
        source: &VerifiedPublisherPolicySourceV1,
    ) -> Result<(), GitUploadBootstrapErrorV1> {
        self.install_initial_resource_from_source_v1(source)?;
        self.install_initial_controller_from_source_v1(source)?;
        self.install_initial_revocation_from_source_v1(source)?;
        self.install_initial_policy_head_from_source_v1(source)
    }

    /// Installs or exact-replays only the original initial resource DATA.
    ///
    /// The caller holds the actual trusted store and authorizes this mutation.
    ///
    /// # Errors
    ///
    /// Preserves the original typed store error or exact-source conflict.
    pub fn install_initial_resource_from_source_v1(
        &mut self,
        source: &VerifiedPublisherPolicySourceV1,
    ) -> Result<(), GitUploadBootstrapErrorV1> {
        match self.resource_binding(source.resource().resource())? {
            Some(current) if current == *source.resource() => {}
            Some(_) => return Err(GitUploadBootstrapErrorV1::Conflict),
            None => {
                self.install_resource_from_trusted_controller(
                    source.transaction_id(b"resource"),
                    source.resource(),
                )?;
            }
        }
        Ok(())
    }

    /// Installs or exact-replays only the original initial controller DATA.
    ///
    /// The caller holds the actual trusted store and authorizes this mutation.
    ///
    /// # Errors
    ///
    /// Preserves the original typed store error or exact-source conflict.
    pub fn install_initial_controller_from_source_v1(
        &mut self,
        source: &VerifiedPublisherPolicySourceV1,
    ) -> Result<(), GitUploadBootstrapErrorV1> {
        match self.controller_head()? {
            Some(current) if current == source.controller() => {}
            Some(_) => return Err(GitUploadBootstrapErrorV1::Conflict),
            None => {
                self.advance_controller_from_trusted_controller(
                    source.transaction_id(b"controller"),
                    None,
                    source.controller(),
                )?;
            }
        }
        Ok(())
    }

    /// Installs or exact-replays only the original initial revocation DATA.
    ///
    /// The caller holds the actual trusted store and authorizes this mutation.
    ///
    /// # Errors
    ///
    /// Preserves the original typed store error or exact-source conflict.
    pub fn install_initial_revocation_from_source_v1(
        &mut self,
        source: &VerifiedPublisherPolicySourceV1,
    ) -> Result<(), GitUploadBootstrapErrorV1> {
        match self.revocation_head(source.revocation().scope)? {
            Some(current) if current == source.revocation() => {}
            Some(_) => return Err(GitUploadBootstrapErrorV1::Conflict),
            None => {
                self.advance_revocation_from_trusted_controller(
                    source.transaction_id(b"revocation"),
                    None,
                    source.revocation(),
                )?;
            }
        }
        Ok(())
    }

    /// Installs or exact-replays only the original initial policy DATA.
    ///
    /// The caller holds the actual trusted store and authorizes this mutation.
    ///
    /// # Errors
    ///
    /// Preserves the original typed store error or exact-source conflict.
    pub fn install_initial_policy_head_from_source_v1(
        &mut self,
        source: &VerifiedPublisherPolicySourceV1,
    ) -> Result<(), GitUploadBootstrapErrorV1> {
        match self.current_policy(source.policy().project())? {
            Some(current) if current == *source.policy() => Ok(()),
            Some(_) => Err(GitUploadBootstrapErrorV1::Conflict),
            None => {
                self.publish_policy_from_trusted_controller(
                    source.transaction_id(b"policy"),
                    None,
                    source.policy(),
                )?;
                Ok(())
            }
        }
    }
}

/// Parks the exact proposed transaction and every protected crossing outcome.
///
/// This initial writer only accepts absent state or exact completed ZERO
/// genesis. It cannot reserve, settle, spend, or erase other project debt.
pub struct GitUploadBootstrapAppendV1 {
    transaction: JournalTransaction,
    preflight: Option<Result<(), JournalError>>,
    commit: Option<Result<CommitResult, PublisherPolicyError>>,
    failure: Option<GitUploadBootstrapErrorV1>,
    ended: bool,
    complete: bool,
}

impl GitUploadBootstrapAppendV1 {
    /// Returns the first original crossing or readback cause, when available.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.preflight {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.commit {
            return Some(cause);
        }
        self.failure.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

/// Retains the one covered successor co-commit and its original typed causes.
///
/// Only the closed original-owner attempt prepares this value. It cannot
/// accept caller resource amounts, retry a failed append, or retire debt.
#[doc(hidden)]
pub struct GitUploadEnrolledAccountAppendV1 {
    transaction: JournalTransaction,
    preflight: Option<Result<(), JournalError>>,
    commit: Option<Result<CommitResult, JournalError>>,
    failure: Option<GitUploadBootstrapErrorV1>,
    ended: bool,
    complete: bool,
}

impl GitUploadEnrolledAccountAppendV1 {
    /// Borrows the original crossing cause while keeping every result resident.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(cause)) = &self.preflight {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.commit {
            return Some(cause);
        }
        self.failure.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))
    }

    pub(crate) fn committed_coordinates(&self) -> Option<([u8; 16], u64)> {
        if !self.complete || self.failure().is_some() {
            return None;
        }
        self.commit.as_ref().and_then(|result| result.as_ref().ok())
            .map(|result| (*self.transaction.id(), result.commit_sequence))
    }
}

/// Borrows exact protected bootstrap records and the original signed input.
///
/// The all-zero new family is explicitly non-admitting DATA. It says nothing
/// about pre-existing usage outside this family, enforcement, funding or drain.
pub struct GitUploadBootstrapDataRefV1<'owner> {
    source: &'owner VerifiedPublisherPolicySourceV1,
    capacity: &'owner GitUploadCapacityV1,
    credentials: &'owner PublisherPolicyBootstrapCredentialCustodyV1,
    origin: &'owner [u8],
    account: &'owner [u8],
    head: &'owner [u8],
}

impl GitUploadBootstrapDataRefV1<'_> {
    /// Returns the resident signed policy DATA.
    pub const fn source(&self) -> &VerifiedPublisherPolicySourceV1 {
        self.source
    }

    /// Returns the resident capacity DATA.
    pub const fn capacity(&self) -> &GitUploadCapacityV1 {
        self.capacity
    }

    /// Returns the same original fixed credential holder.
    pub const fn credentials(&self) -> &PublisherPolicyBootstrapCredentialCustodyV1 {
        self.credentials
    }

    /// Returns the exact three protected readback values.
    pub const fn records(&self) -> [&[u8]; 3] {
        [self.origin, self.account, self.head]
    }
}

impl PublisherPolicyStore<'_> {
    // The containing owner has already compared its original local/remote
    // cuts. This preparation accepts those fixed rows, never resource amounts.
    pub(crate) fn prepare_git_upload_enrolled_account(
        &self,
        bootstrap: &GitUploadBootstrapAppendV1,
        source: &VerifiedPublisherPolicySourceV1,
        capacity: &GitUploadCapacityV1,
        credentials: &PublisherPolicyBootstrapCredentialCustodyV1,
        enrollment: &aos_sandbox_model::format::git_upload_enrollment::GitCoverageEnrollmentV1<'_>,
        owners: &[[u8; 140]],
        now: i64,
    ) -> Result<GitUploadEnrolledAccountAppendV1, GitUploadBootstrapErrorV1> {
        let original = self.current_git_upload_bootstrap(
            bootstrap, source, capacity, credentials, now,
        )?;
        let (_, period) = enrollment.ceiling_period();
        if enrollment.project() != source.policy().project()
            || period != capacity.cpu_period_micros()
            || enrollment.ceiling_period().0 != capacity.ceilings()
        {
            return Err(GitUploadBootstrapErrorV1::Conflict);
        }
        let [origin, predecessor, _] = original.records();
        let origin_digest = commitment(ORIGIN_DOMAIN, origin);
        let account = encode_account(
            source.policy().project(), 2, commitment(ACCOUNT_DOMAIN, predecessor),
            origin_digest, ResourceVector::ZERO, ResourceVector::ZERO,
        );
        let account_digest = commitment(ACCOUNT_DOMAIN, &account);
        let companion = super::account_coverage::encode_empty_first_profile(
            &super::account_coverage::EmptyAccountCoverageFieldsV1 {
                project: source.policy().project(),
                generation: 2,
                origin: origin_digest,
                account: account_digest,
                predecessor: ObjectDigest::from_bytes([0; 32]),
                enrollment: ObjectDigest::from_bytes(enrollment.digest()),
                ceiling_authority: capacity_authority_digest(capacity)?,
                cpu_period_micros: period,
            },
            owners,
        )?;
        let decoded = super::account_coverage::AccountCoverageV1::decode(&companion)?;
        let transaction = JournalTransaction::new(
            decoded.transaction()?,
            vec![
                JournalRecord::put(RecordNamespace::PublisherPolicy, decoded.key()?, companion),
                JournalRecord::put(RecordNamespace::PublisherPolicy, account_key(source.policy().project(), 2), account),
                JournalRecord::put(RecordNamespace::PublisherPolicy, account_head_key(source.policy().project()),
                    encode_account_head(source.policy().project(), 2, account_digest)),
            ],
        ).map_err(crate::journal::JournalError::from).map_err(PublisherPolicyError::from)?;
        require_coverage_native_account_transaction(&transaction)?;
        Ok(GitUploadEnrolledAccountAppendV1 {
            transaction,
            preflight: None,
            commit: None,
            failure: None,
            ended: false,
            complete: false,
        })
    }

    // The private clock guard remains with the initializer for this entire
    // call. Preflight is not a reservation; compare the exact original head
    // again immediately before the SAME-writer CAS and park its whole result.
    pub(crate) fn commit_git_upload_enrolled_account(
        &mut self,
        append: &mut GitUploadEnrolledAccountAppendV1,
        bootstrap: &GitUploadBootstrapAppendV1,
        source: &VerifiedPublisherPolicySourceV1,
        capacity: &GitUploadCapacityV1,
        credentials: &PublisherPolicyBootstrapCredentialCustodyV1,
        now: i64,
    ) -> Result<(), ()> {
        if append.ended || append.preflight.is_some() || append.failure().is_some() {
            append.failure.get_or_insert(GitUploadBootstrapErrorV1::Conflict);
            append.ended = true;
            return Err(());
        }
        append.ended = true;
        let returned = (|| {
            self.current_git_upload_bootstrap(bootstrap, source, capacity, credentials, now)?;
            require_coverage_native_account_transaction(&append.transaction)?;
            let records = append.transaction.records();
            if records[..2].iter().any(|record| self.journal.get(
                RecordNamespace::PublisherPolicy, record.key(),
            ).is_some()) {
                return Err(GitUploadBootstrapErrorV1::Conflict);
            }
            let (next_records, next_bytes) = self.bounded_replacement_totals(records)?;
            append.preflight = Some(self.journal.preflight_transactions(
                std::slice::from_ref(&append.transaction),
            ));
            if !matches!(append.preflight.as_ref(), Some(Ok(()))) {
                return Err(GitUploadBootstrapErrorV1::Conflict);
            }
            self.current_git_upload_bootstrap(bootstrap, source, capacity, credentials, now)?;
            self.journal.validate_held_protected_names().map_err(PublisherPolicyError::from)?;
            append.commit = Some(self.journal.commit(&append.transaction));
            if !matches!(append.commit.as_ref(), Some(Ok(_))) {
                return Err(GitUploadBootstrapErrorV1::Conflict);
            }
            self.records = next_records;
            self.materialized_bytes = next_bytes;
            require_exact_records(self.journal, records)?;
            require_original_policy(self.journal, source)?;
            validate_namespace(
                super::super::PublisherReadDataV2::from_state_v2(
                    self.journal.historical_read_view_v1().materialized_state_v1(),
                ),
                self.limits,
            )?;
            Ok(())
        })();
        if let Err(cause) = returned {
            append.failure.get_or_insert(cause);
            return Err(());
        }
        append.complete = true;
        Ok(())
    }

    /// Compares the genuine covered successor, not the old gen1 head wrapper.
    ///
    /// This lends DATA under the existing original credential and policy
    /// checks. It grants no allocation, remote release or account permission.
    ///
    /// # Errors
    /// Refuses an incomplete/failed append, changed original inputs, expired
    /// signed interval, or any different account/companion/current head.
    #[doc(hidden)]
    pub fn current_git_upload_enrolled_account(
        &self,
        append: &GitUploadEnrolledAccountAppendV1,
        bootstrap: &GitUploadBootstrapAppendV1,
        source: &VerifiedPublisherPolicySourceV1,
        capacity: &GitUploadCapacityV1,
        credentials: &PublisherPolicyBootstrapCredentialCustodyV1,
        now: i64,
    ) -> Result<(), GitUploadBootstrapErrorV1> {
        self.journal.ensure_protected_authority().map_err(PublisherPolicyError::from)?;
        require_original_append(bootstrap, source)?;
        if !bootstrap.complete || bootstrap.failure().is_some()
            || !append.complete || append.failure().is_some()
            || now < source.policy().not_before() || now >= source.policy().expires_at()
        {
            return Err(GitUploadBootstrapErrorV1::Conflict);
        }
        let [packet, policy, key, body] = credentials.ready()
            .ok_or(GitUploadBootstrapErrorV1::Conflict)?;
        if packet != source.packet().as_slice() || policy != source.policy().canonical_policy()
            || key != source.verification_key().as_slice() || source.verify_git_capacity(body)? != *capacity
        {
            return Err(GitUploadBootstrapErrorV1::Conflict);
        }
        require_original_policy(self.journal, source)?;
        require_exact_records(self.journal, &bootstrap.transaction.records()[..2])?;
        require_exact_records(self.journal, append.transaction.records())?;
        validate_namespace(
            super::super::PublisherReadDataV2::from_state_v2(
                self.journal.historical_read_view_v1().materialized_state_v1(),
            ),
            self.limits,
        )?;
        Ok(())
    }

    /// Reports only a complete stored-pair candidate, never account authority.
    ///
    /// # Errors
    /// Refuses a one-sided or pre-account denial rather than completing it.
    #[doc(hidden)]
    pub fn existing_git_upload_enrollment_candidate_v1(
        &self,
        project: ProjectId,
    ) -> Result<bool, GitUploadBootstrapErrorV1> {
        let birth = self.journal.get(RecordNamespace::DesiredState, b"z-git-birth-v1");
        let fence = self.journal.get(RecordNamespace::DesiredState, b"z-git-fence-v1");
        let companion = self.journal.get(
            RecordNamespace::PublisherPolicy, &super::account_coverage::first_profile_key(project),
        );
        match (birth, fence, companion) {
            (None, None, None) => Ok(false),
            (Some(_), Some(_), Some(_)) => Ok(true),
            _ => Err(GitUploadBootstrapErrorV1::Conflict),
        }
    }

    /// Compares a genuine stored gen2 successor without fabricating an append.
    ///
    /// The proposal preserves the original signed gen1 bytes as comparison
    /// DATA only. Complete native-prefix replay and current remote/Root owners
    /// remain separate mandatory checks at the installed cold caller.
    ///
    /// # Errors
    /// Refuses changed credentials/policy, a missing or different predecessor,
    /// unbound companion, nonempty account, or unsupported later generation.
    #[doc(hidden)]
    pub fn current_git_upload_stored_enrolled_account_v1(
        &self,
        proposal: &GitUploadBootstrapAppendV1,
        source: &VerifiedPublisherPolicySourceV1,
        capacity: &GitUploadCapacityV1,
        credentials: &PublisherPolicyBootstrapCredentialCustodyV1,
        now: i64,
    ) -> Result<(), GitUploadBootstrapErrorV1> {
        self.journal.ensure_protected_authority().map_err(PublisherPolicyError::from)?;
        require_original_append(proposal, source)?;
        if proposal.failure().is_some()
            || now < source.policy().not_before() || now >= source.policy().expires_at()
        {
            return Err(GitUploadBootstrapErrorV1::Conflict);
        }
        let [packet, policy, key, body] = credentials.ready()
            .ok_or(GitUploadBootstrapErrorV1::Conflict)?;
        if packet != source.packet().as_slice() || policy != source.policy().canonical_policy()
            || key != source.verification_key().as_slice() || source.verify_git_capacity(body)? != *capacity
        {
            return Err(GitUploadBootstrapErrorV1::Conflict);
        }
        require_original_policy(self.journal, source)?;
        require_exact_records(self.journal, &proposal.transaction.records()[..2])?;
        validate_namespace(
            super::super::PublisherReadDataV2::from_state_v2(
                self.journal.historical_read_view_v1().materialized_state_v1(),
            ),
            self.limits,
        )?;

        let companion_key = super::account_coverage::first_profile_key(source.policy().project());
        let companion_bytes = self.journal.get(RecordNamespace::PublisherPolicy, &companion_key)
            .ok_or(GitUploadBootstrapErrorV1::Conflict)?;
        let companion = super::account_coverage::AccountCoverageV1::decode(companion_bytes)?;
        let account_key = account_key(source.policy().project(), 2);
        let head_key = account_head_key(source.policy().project());
        let account = self.journal.get(RecordNamespace::PublisherPolicy, &account_key)
            .ok_or(GitUploadBootstrapErrorV1::Conflict)?;
        let head = self.journal.get(RecordNamespace::PublisherPolicy, &head_key)
            .ok_or(GitUploadBootstrapErrorV1::Conflict)?;
        require_coverage_native_account_parts(&companion.transaction()?, [
            (&companion_key, Some(companion_bytes)), (&account_key, Some(account)),
            (&head_key, Some(head)),
        ])?;
        let predecessor = proposal.transaction.records()[1].value()
            .ok_or(GitUploadBootstrapErrorV1::Conflict)?;
        let origin = proposal.transaction.records()[0].value()
            .ok_or(GitUploadBootstrapErrorV1::Conflict)?;
        let revision = decode_account_contents(account)?;
        if revision.predecessor != commitment(ACCOUNT_DOMAIN, predecessor)
            || revision.origin != commitment(ORIGIN_DOMAIN, origin)
            || companion.ceiling_authority()? != capacity_authority_digest(capacity)?
            || companion.cpu_period_micros()? != capacity.cpu_period_micros()
        {
            return Err(GitUploadBootstrapErrorV1::Conflict);
        }
        Ok(())
    }

    /// Prepares a closed triple from one original full-policy source.
    ///
    /// Preparation is DATA. The caller parks the result before preflight or
    /// commit, retains the original inputs, and separately authenticates the
    /// independent administrative designation.
    ///
    /// # Errors
    ///
    /// Rejects a compiler-derived revision, mismatched capacity or protected
    /// current head, or invalid bounded transaction.
    pub fn prepare_git_upload_bootstrap(
        &self,
        source: &VerifiedPublisherPolicySourceV1,
        capacity: &GitUploadCapacityV1,
        canonical_capacity: &[u8],
    ) -> Result<GitUploadBootstrapAppendV1, GitUploadBootstrapErrorV1> {
        self.journal.ensure_protected_authority().map_err(PublisherPolicyError::from)?;
        if source.policy().compiler_origin().is_some()
            || source.verify_git_capacity(canonical_capacity)? != *capacity
        {
            return Err(GitUploadBootstrapErrorV1::InvalidSource);
        }
        require_original_policy(self.journal, source)?;
        let origin = encode_origin(source, canonical_capacity)?;
        let origin_digest = commitment(ORIGIN_DOMAIN, &origin);
        let account = encode_account(
            source.policy().project(), 1, ObjectDigest::from_bytes([0; 32]),
            origin_digest, ResourceVector::ZERO, ResourceVector::ZERO,
        );
        let head = encode_account_head(
            source.policy().project(), 1, commitment(ACCOUNT_DOMAIN, &account),
        );
        let project = source.policy().project();
        let transaction = JournalTransaction::new(
            source.transaction_id(b"git-upload-bootstrap"),
            vec![
                JournalRecord::put(RecordNamespace::PublisherPolicy, origin_key(project), origin),
                JournalRecord::put(RecordNamespace::PublisherPolicy, account_key(project, 1), account),
                JournalRecord::put(RecordNamespace::PublisherPolicy, account_head_key(project), head),
            ],
        ).map_err(crate::journal::JournalError::from).map_err(PublisherPolicyError::from)?;
        Ok(GitUploadBootstrapAppendV1 {
            transaction,
            preflight: None,
            commit: None,
            failure: None,
            ended: false,
            complete: false,
        })
    }

    /// Preflights the resident triple without releasing the actual store loan.
    ///
    /// # Errors
    ///
    /// Returns only a marker; the original first cause remains in `append`.
    /// Re-entry and failed/partial preflight permanently close this append.
    pub fn preflight_git_upload_bootstrap(
        &mut self,
        append: &mut GitUploadBootstrapAppendV1,
        source: &VerifiedPublisherPolicySourceV1,
    ) -> Result<(), ()> {
        if append.ended || append.preflight.is_some() || append.failure().is_some() {
            if append.failure().is_none() {
                append.failure = Some(GitUploadBootstrapErrorV1::Conflict);
            }
            append.ended = true;
            return Err(());
        }
        // Prearm before any protected validation or preflight effect.
        append.ended = true;
        let result = (|| {
            self.journal.ensure_protected_authority().map_err(PublisherPolicyError::from)?;
            require_original_append(append, source)?;
            require_original_policy(self.journal, source)?;
            let records = append.transaction.records();
            let present = records.iter().filter(|record|
                self.journal.get(RecordNamespace::PublisherPolicy, record.key()).is_some()).count();
            if present == records.len() {
                require_exact_records(self.journal, records)?;
                append.preflight = Some(Ok(()));
                return Ok(());
            }
            if present != 0 {
                return Err(GitUploadBootstrapErrorV1::Conflict);
            }
            self.bounded_replacement_totals(records)?;
            append.preflight = Some(self.journal.preflight_transactions(
                std::slice::from_ref(&append.transaction),
            ));
            if matches!(append.preflight.as_ref(), Some(Err(_))) {
                return Err(GitUploadBootstrapErrorV1::Conflict);
            }
            Ok(())
        })();
        if let Err(cause) = result {
            if append.failure().is_none() {
                append.failure = Some(cause);
            }
            return Err(());
        }
        append.ended = false;
        Ok(())
    }

    /// Executes one resident initial triple, keeping actual outcomes in place.
    ///
    /// # Errors
    ///
    /// An error marker means the first typed cause remains in `append`.
    /// Re-entry, partial state, nonzero/successor debt and mismatch fail closed.
    pub fn initialize_git_upload_bootstrap(
        &mut self,
        append: &mut GitUploadBootstrapAppendV1,
        source: &VerifiedPublisherPolicySourceV1,
    ) -> Result<(), ()> {
        if append.ended || append.failure().is_some()
            || !matches!(append.preflight.as_ref(), Some(Ok(())))
        {
            if append.failure().is_none() {
                append.failure = Some(GitUploadBootstrapErrorV1::Conflict);
            }
            append.ended = true;
            return Err(());
        }
        append.ended = true;
        let result = self.initialize_git_upload_bootstrap_inner(append, source);
        if let Err(cause) = result {
            if append.failure().is_none() {
                append.failure = Some(cause);
            }
            return Err(());
        }
        append.complete = true;
        Ok(())
    }

    fn initialize_git_upload_bootstrap_inner(
        &mut self,
        append: &mut GitUploadBootstrapAppendV1,
        source: &VerifiedPublisherPolicySourceV1,
    ) -> Result<(), GitUploadBootstrapErrorV1> {
        self.journal.ensure_protected_authority().map_err(PublisherPolicyError::from)?;
        require_original_append(append, source)?;
        require_original_policy(self.journal, source)?;
        let records = append.transaction.records();
        let present = records.iter().filter(|record|
            self.journal.get(RecordNamespace::PublisherPolicy, record.key()).is_some()).count();
        if present == records.len() {
            require_exact_records(self.journal, records)?;
            return Ok(());
        }
        if present != 0 || self.journal.records(RecordNamespace::PublisherPolicy).any(|(key, _)|
            key.starts_with(ACCOUNT_PREFIX)
                && key.get(ACCOUNT_PREFIX.len()..ACCOUNT_PREFIX.len() + 16)
                    == Some(source.policy().project().as_bytes().as_slice()))
        {
            return Err(GitUploadBootstrapErrorV1::Conflict);
        }

        let (next_records, next_bytes) = self.bounded_replacement_totals(records)?;
        // Preflight is not a reservation. Keep the exclusive SAME Journal loan
        // and compare policy and all three absent keys again before commit.
        require_original_policy(self.journal, source)?;
        if records.iter().any(|record|
            self.journal.get(RecordNamespace::PublisherPolicy, record.key()).is_some())
        {
            return Err(GitUploadBootstrapErrorV1::Conflict);
        }
        append.commit = Some(self.journal.commit(&append.transaction).map_err(PublisherPolicyError::from));
        match append.commit.as_ref() {
            Some(Ok(_)) => {
                self.records = next_records;
                self.materialized_bytes = next_bytes;
            }
            _ => return Err(GitUploadBootstrapErrorV1::Conflict),
        }

        require_exact_records(self.journal, records)?;
        require_original_policy(self.journal, source)?;
        validate_namespace(
            super::super::PublisherReadDataV2::from_state_v2(
                self.journal.historical_read_view_v1().materialized_state_v1(),
            ),
            self.limits,
        )?;
        Ok(())
    }

    /// Borrows the same completed bootstrap, original credentials and head.
    ///
    /// No account admission or physical currentness is returned. The original
    /// credential recheck and genuine current clock sample precede this call.
    ///
    /// # Errors
    ///
    /// Rejects incomplete append, changed credentials or head, expired signed
    /// interval, or a different/nonzero account generation.
    pub fn current_git_upload_bootstrap<'owner>(
        &'owner self,
        append: &'owner GitUploadBootstrapAppendV1,
        source: &'owner VerifiedPublisherPolicySourceV1,
        capacity: &'owner GitUploadCapacityV1,
        credentials: &'owner PublisherPolicyBootstrapCredentialCustodyV1,
        now: i64,
    ) -> Result<GitUploadBootstrapDataRefV1<'owner>, GitUploadBootstrapErrorV1> {
        self.journal.ensure_protected_authority().map_err(PublisherPolicyError::from)?;
        require_original_append(append, source)?;
        if !append.complete || append.failure().is_some()
            || now < source.policy().not_before() || now >= source.policy().expires_at()
        {
            return Err(GitUploadBootstrapErrorV1::Conflict);
        }
        let [packet, policy, key, body] = credentials.ready()
            .ok_or(GitUploadBootstrapErrorV1::Conflict)?;
        if packet != source.packet().as_slice() || policy != source.policy().canonical_policy()
            || key != source.verification_key().as_slice() || source.verify_git_capacity(body)? != *capacity
        {
            return Err(GitUploadBootstrapErrorV1::Conflict);
        }
        require_original_policy(self.journal, source)?;
        require_exact_records(self.journal, append.transaction.records())?;
        let get = |index: usize| self.journal.get(
            RecordNamespace::PublisherPolicy, append.transaction.records()[index].key(),
        ).ok_or(GitUploadBootstrapErrorV1::Conflict);
        Ok(GitUploadBootstrapDataRefV1 {
            source,
            capacity,
            credentials,
            origin: get(0)?,
            account: get(1)?,
            head: get(2)?,
        })
    }
}

fn require_original_append(
    append: &GitUploadBootstrapAppendV1,
    source: &VerifiedPublisherPolicySourceV1,
) -> Result<(), GitUploadBootstrapErrorV1> {
    let record = append.transaction.records().first()
        .ok_or(GitUploadBootstrapErrorV1::Conflict)?;
    let origin = record.value().ok_or(GitUploadBootstrapErrorV1::Conflict)?;
    if record.key() != origin_key(source.policy().project())
        || origin.get(100..132) != Some(source.verification_key().as_slice())
        || origin.get(132..404) != Some(source.packet().as_slice())
    {
        return Err(GitUploadBootstrapErrorV1::Conflict);
    }
    Ok(())
}

fn require_original_policy(
    journal: &Journal,
    source: &VerifiedPublisherPolicySourceV1,
) -> Result<(), GitUploadBootstrapErrorV1> {
    let revision = journal.get(RecordNamespace::PublisherPolicy,
        &policy_revision_key(source.policy().project(), source.policy().generation()))
        .ok_or(GitUploadBootstrapErrorV1::Conflict)?;
    let head = journal.get(RecordNamespace::PublisherPolicy,
        &policy_current_key(source.policy().project()))
        .ok_or(GitUploadBootstrapErrorV1::Conflict)?;
    if revision != encode_policy_revision(source.policy())?.as_slice()
        || head != encode_policy_head(source.policy()).as_slice()
    {
        return Err(GitUploadBootstrapErrorV1::Conflict);
    }
    Ok(())
}

fn require_exact_records(
    journal: &Journal,
    records: &[JournalRecord],
) -> Result<(), GitUploadBootstrapErrorV1> {
    if records.iter().any(|record|
        journal.get(RecordNamespace::PublisherPolicy, record.key()) != record.value())
    {
        return Err(GitUploadBootstrapErrorV1::Conflict);
    }
    Ok(())
}

// The sole COMMIT observer calls this on the actual original transaction,
// never on a final-map projection. It proves only the closed three-PUT relation;
// the same namespace replay separately authenticates origin and predecessor.
impl PublisherPolicyStore<'_> {
    // Saved DATA comparison only; original native admission stays separate.
    pub(crate) fn require_complete_coverage_read_state_v1(
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Result<(), PublisherPolicyError> {
        require_complete_coverage_read_state_data_v1(state)
    }
}


impl From<aos_sandbox_protocol::publisher_policy::PublisherPolicySchemaErrorV1> for GitUploadBootstrapErrorV1 {
    fn from(error: aos_sandbox_protocol::publisher_policy::PublisherPolicySchemaErrorV1) -> Self {
        Self::Store(error.into())
    }
}

impl From<GitUploadSourceDataErrorV1> for GitUploadBootstrapErrorV1 {
    fn from(error: GitUploadSourceDataErrorV1) -> Self {
        match error {
            GitUploadSourceDataErrorV1::InvalidSource => Self::InvalidSource,
            GitUploadSourceDataErrorV1::Signature(cause) => Self::Signature(cause),
            GitUploadSourceDataErrorV1::Descriptor(cause) => Self::Descriptor(cause),
            GitUploadSourceDataErrorV1::Capacity(cause) => Self::Capacity(cause),
            GitUploadSourceDataErrorV1::Conflict => Self::Conflict,
            GitUploadSourceDataErrorV1::Store(cause) => Self::Store(cause.into()),
        }
    }
}
