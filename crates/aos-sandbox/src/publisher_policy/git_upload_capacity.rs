//! Original signed-policy DATA and protected non-admitting Git bootstrap records.
//!
//! This module shares the sole AOSPSC01 verifier with ordinary publisher startup.
//! A clean new account family is not a complete project usage inventory or permit.

use aos_sandbox_core::model::CacheDomainKind;
use aos_sandbox_core::{
    DecodeLimits, NodeId, ObjectDigest, Operation, PrincipalId, ProjectId,
    ResourceId, ResourceKind, RevocationScopeId, Selector,
};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::publisher_sessions::PublisherSessionScope;
use crate::public_api_session::PublisherPolicyBootstrapCredentialCustodyV1;
use aos_sandbox_core::{
    GitUploadCapacityV1, ObjectDescriptorVerifier, PortableMediaType,
    ResourceAccount, ResourceCeilings, ResourceDimension, ResourceVector,
    decode_git_upload_capacity_v1,
};
use std::collections::BTreeMap;

use super::project_authorization_source_v2::{HEAD_DOMAIN, REVISION_DOMAIN, commitment};
use super::*;

const MAGIC: &[u8; 8] = b"AOSPSC01";
const SIGNING_DOMAIN: &[u8] = b"aos.sandbox.publisher-policy-source.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.publisher-policy-source-transaction.v1\0";
const PACKET_BYTES: usize = 272;
const SIGNED_BYTES: usize = 208;

// The ordinary adapter drops/classifies at the original failure site, before
// its statement/policy locals. Retained startup parks the actual typed cause.
#[derive(Clone, Copy)]
enum SignedSourceErrorCustodyV1 {
    Local,
    Retained,
}

impl SignedSourceErrorCustodyV1 {
    fn failure(self, cause: GitUploadBootstrapErrorV1) -> GitUploadBootstrapErrorV1 {
        match self {
            Self::Local => GitUploadBootstrapErrorV1::InvalidSource,
            Self::Retained => cause,
        }
    }
}

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
    Descriptor(#[source] aos_sandbox_core::ObjectDescriptorVerificationError),
    /// The canonical capacity decoder rejected the input.
    #[error("Git upload bootstrap capacity is invalid")]
    Capacity(#[source] aos_sandbox_core::CanonicalCborError),
    /// The retained state differs from the original initial source.
    #[error("Git upload bootstrap conflicts with protected state")]
    Conflict,
    /// Protected policy or journal work failed.
    #[error("Git upload bootstrap protected state failed")]
    Store(#[from] PublisherPolicyError),
}

/// Retains one verified full-policy signature as DATA, not current authority.
#[derive(Debug)]
pub struct VerifiedPublisherPolicySourceV1 {
    packet: [u8; PACKET_BYTES],
    policy: PreparedPublisherPolicyRevisionV1,
    resource: PublisherResourceBindingV1,
    controller: PublisherControllerHeadV1,
    revocation: PublisherRevocationHeadV1,
    key: [u8; 32],
    scope: PublisherSessionScope,
}

impl VerifiedPublisherPolicySourceV1 {
    /// Verifies the unchanged packet signature, scope and ordinary cache grant.
    ///
    /// # Errors
    ///
    /// Returns the original signature or policy cause, or invalid signed scope.
    pub fn verify(
        packet: [u8; PACKET_BYTES],
        canonical_policy: &[u8],
        key: [u8; 32],
        scope: PublisherSessionScope,
        now: i64,
    ) -> Result<Self, GitUploadBootstrapErrorV1> {
        Self::verify_with_error_custody(
            packet, canonical_policy, key, scope, now, SignedSourceErrorCustodyV1::Retained,
        )
    }

    /// Preserves ordinary local classification and failure-site error drop.
    ///
    /// # Errors
    ///
    /// Returns invalid-source DATA under the unchanged ordinary check order.
    pub fn verify_ordinary(
        packet: [u8; PACKET_BYTES],
        canonical_policy: &[u8],
        key: [u8; 32],
        scope: PublisherSessionScope,
        now: i64,
    ) -> Result<Self, GitUploadBootstrapErrorV1> {
        Self::verify_with_error_custody(
            packet, canonical_policy, key, scope, now, SignedSourceErrorCustodyV1::Local,
        )
    }

    fn verify_with_error_custody(
        packet: [u8; PACKET_BYTES],
        canonical_policy: &[u8],
        key: [u8; 32],
        scope: PublisherSessionScope,
        now: i64,
        custody: SignedSourceErrorCustodyV1,
    ) -> Result<Self, GitUploadBootstrapErrorV1> {
        if &packet[..8] != MAGIC {
            return Err(GitUploadBootstrapErrorV1::InvalidSource);
        }
        let verifying_key =
            VerifyingKey::from_bytes(&key)
                .map_err(|cause| custody.failure(GitUploadBootstrapErrorV1::Signature(cause)))?;
        let signature = Signature::from_slice(&packet[SIGNED_BYTES..])
            .map_err(|cause| custody.failure(GitUploadBootstrapErrorV1::Signature(cause)))?;
        let mut statement = Vec::with_capacity(SIGNING_DOMAIN.len() + SIGNED_BYTES);
        statement.extend_from_slice(SIGNING_DOMAIN);
        statement.extend_from_slice(&packet[..SIGNED_BYTES]);
        verifying_key
            .verify(&statement, &signature)
            .map_err(|cause| custody.failure(GitUploadBootstrapErrorV1::Signature(cause)))?;

        let publisher_principal = PrincipalId::from_bytes(read_array(&packet, 8)?);
        let node = NodeId::from_bytes(read_array(&packet, 24)?);
        let project = ProjectId::from_bytes(read_array(&packet, 40)?);
        let resource_id = ResourceId::from_bytes(read_array(&packet, 56)?);
        let isolation = ObjectDigest::from_bytes(read_array(&packet, 72)?);
        let controller_principal = PrincipalId::from_bytes(read_array(&packet, 104)?);
        let controller_generation = read_u64(&packet, 120)?;
        let revocation_scope = RevocationScopeId::from_bytes(read_array(&packet, 128)?);
        let revocation_generation = read_u64(&packet, 144)?;
        let policy_generation = read_u64(&packet, 152)?;
        let not_before = read_i64(&packet, 160)?;
        let expires_at = read_i64(&packet, 168)?;
        let expected_digest: [u8; 32] = read_array(&packet, 176)?;
        if publisher_principal != scope.principal
            || node != scope.node
            || project != scope.project
            || resource_id != scope.cache_resource
            || controller_principal.as_bytes() == &[0; 16]
            || revocation_scope.as_bytes() == &[0; 16]
            || controller_generation != 1
            || revocation_generation != 1
            || policy_generation != 1
            || now < not_before
            || now >= expires_at
        {
            return Err(GitUploadBootstrapErrorV1::InvalidSource);
        }
        let policy = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
            project,
            policy_generation,
            not_before,
            expires_at,
            canonical_policy,
            DecodeLimits::default(),
        )
        .map_err(|cause| custody.failure(GitUploadBootstrapErrorV1::Store(cause)))?;
        if policy.descriptor().digest().as_bytes() != &expected_digest
            || policy.policy().cache_domain().kind() != CacheDomainKind::Project
            || !policy.policy().effective_grants().iter().any(|grant| {
                grant.resource_kind() == ResourceKind::CachePublish
                    && grant.operations().contains(Operation::Publish)
                    && matches!(
                        grant.selector(),
                        Selector::Resource { resource } if *resource == resource_id
                    )
            })
            || policy.policy().effective_grants().iter().any(|grant| {
                grant.resource_kind() == ResourceKind::CachePublish
                    && grant.operations().contains(Operation::Publish)
                    && !matches!(
                        grant.selector(),
                        Selector::Resource { resource } if *resource == resource_id
                    )
            })
        {
            return Err(GitUploadBootstrapErrorV1::InvalidSource);
        }
        let resource = PublisherResourceBindingV1::new(
            resource_id,
            project,
            policy.policy().cache_domain(),
            isolation,
        )
        .map_err(|cause| custody.failure(GitUploadBootstrapErrorV1::Store(cause)))?;
        Ok(Self {
            packet,
            policy,
            resource,
            controller: PublisherControllerHeadV1 {
                principal: controller_principal,
                generation: controller_generation,
            },
            revocation: PublisherRevocationHeadV1 {
                scope: revocation_scope,
                generation: revocation_generation,
            },
            key,
            scope,
        })
    }


    /// Preserves the existing resource, controller, revocation and policy install order.
    ///
    /// # Errors
    ///
    /// Returns a protected store error or a conflict with the exact signed source.
    pub fn install_initial_policy(
        &self,
        store: &mut PublisherPolicyStore<'_>,
    ) -> Result<(), GitUploadBootstrapErrorV1> {
        self.install_initial_resource(store)?;
        self.install_initial_controller(store)?;
        self.install_initial_revocation(store)?;
        self.install_initial_policy_head(store)
    }

    /// Installs or exact-replays only the original initial resource DATA.
    ///
    /// The caller holds the actual trusted store and authorizes this mutation.
    ///
    /// # Errors
    ///
    /// Preserves the original typed store error or exact-source conflict.
    pub fn install_initial_resource(
        &self,
        store: &mut PublisherPolicyStore<'_>,
    ) -> Result<(), GitUploadBootstrapErrorV1> {
        match store.resource_binding(self.resource.resource())? {
            Some(current) if current == self.resource => {}
            Some(_) => return Err(GitUploadBootstrapErrorV1::Conflict),
            None => {
                store.install_resource_from_trusted_controller(
                    self.transaction_id(b"resource"),
                    &self.resource,
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
    pub fn install_initial_controller(
        &self,
        store: &mut PublisherPolicyStore<'_>,
    ) -> Result<(), GitUploadBootstrapErrorV1> {
        match store.controller_head()? {
            Some(current) if current == self.controller => {}
            Some(_) => return Err(GitUploadBootstrapErrorV1::Conflict),
            None => {
                store.advance_controller_from_trusted_controller(
                    self.transaction_id(b"controller"),
                    None,
                    self.controller,
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
    pub fn install_initial_revocation(
        &self,
        store: &mut PublisherPolicyStore<'_>,
    ) -> Result<(), GitUploadBootstrapErrorV1> {
        match store.revocation_head(self.revocation.scope)? {
            Some(current) if current == self.revocation => {}
            Some(_) => return Err(GitUploadBootstrapErrorV1::Conflict),
            None => {
                store.advance_revocation_from_trusted_controller(
                    self.transaction_id(b"revocation"),
                    None,
                    self.revocation,
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
    pub fn install_initial_policy_head(
        &self,
        store: &mut PublisherPolicyStore<'_>,
    ) -> Result<(), GitUploadBootstrapErrorV1> {
        match store.current_policy(self.policy.project())? {
            Some(current) if current == self.policy => Ok(()),
            Some(_) => Err(GitUploadBootstrapErrorV1::Conflict),
            None => {
                store.publish_policy_from_trusted_controller(
                    self.transaction_id(b"policy"),
                    None,
                    &self.policy,
                )?;
                Ok(())
            }
        }
    }
    /// Returns the exact ordinary prepared policy.
    pub const fn policy(&self) -> &PreparedPublisherPolicyRevisionV1 {
        &self.policy
    }

    /// Returns the original signature-checked registration scope as DATA.
    pub const fn scope(&self) -> PublisherSessionScope {
        self.scope
    }

    /// Returns the distinct immutable cache-publication binding.
    pub const fn resource(&self) -> &PublisherResourceBindingV1 {
        &self.resource
    }

    /// Returns the initial Controller head DATA.
    pub const fn controller(&self) -> PublisherControllerHeadV1 {
        self.controller
    }

    /// Returns the initial revocation head DATA.
    pub const fn revocation(&self) -> PublisherRevocationHeadV1 {
        self.revocation
    }

    /// Decodes the one signed capacity input without treating it as a permit.
    ///
    /// # Errors
    ///
    /// Rejects a missing or duplicate descriptor, object mismatch, malformed
    /// declaration, or Git resource/project mismatch with the full policy.
    pub fn verify_git_capacity(
        &self,
        bytes: &[u8],
    ) -> Result<GitUploadCapacityV1, GitUploadBootstrapErrorV1> {
        let mut descriptors = self.policy.policy().input_commitments().iter().filter(|descriptor| {
            descriptor.media_type().as_str() == PortableMediaType::GitUploadCapacity.as_str()
        });
        let descriptor = descriptors.next()
            .ok_or(GitUploadBootstrapErrorV1::InvalidSource)?;
        if descriptors.next().is_some() {
            return Err(GitUploadBootstrapErrorV1::InvalidSource);
        }
        let mut verifier = ObjectDescriptorVerifier::new(descriptor.clone());
        verifier.update(bytes).map_err(GitUploadBootstrapErrorV1::Descriptor)?;
        verifier.finish().map_err(GitUploadBootstrapErrorV1::Descriptor)?;

        let capacity = decode_git_upload_capacity_v1(bytes)
            .map_err(GitUploadBootstrapErrorV1::Capacity)?;
        if capacity.project() != self.policy.project()
            || capacity.resource() == self.resource.resource()
            || !self.policy.policy().effective_grants().iter().any(|grant|
                grant.resource_kind() == ResourceKind::GitObjectDatabase)
            || self.policy.policy().effective_grants().iter()
                .chain(self.policy.policy().delegable_grants()).any(|grant|
                    grant.resource_kind() == ResourceKind::GitObjectDatabase
                        && !matches!(grant.selector(),
                            Selector::Resource { resource } if *resource == capacity.resource()))
        {
            return Err(GitUploadBootstrapErrorV1::InvalidSource);
        }
        Ok(capacity)
    }

    /// Derives the unchanged ordinary transaction identity.
    pub fn transaction_id(&self, kind: &[u8]) -> [u8; 16] {
        let digest = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(kind)
            .chain_update(self.packet)
            .finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        id
    }
}

fn read_array<const N: usize>(
    packet: &[u8],
    offset: usize,
) -> Result<[u8; N], GitUploadBootstrapErrorV1> {
    packet
        .get(offset..offset + N)
        .ok_or(GitUploadBootstrapErrorV1::InvalidSource)?
        .try_into()
        .map_err(|_| GitUploadBootstrapErrorV1::InvalidSource)
}

fn read_u64(packet: &[u8], offset: usize) -> Result<u64, GitUploadBootstrapErrorV1> {
    Ok(u64::from_be_bytes(read_array(packet, offset)?))
}

fn read_i64(packet: &[u8], offset: usize) -> Result<i64, GitUploadBootstrapErrorV1> {
    Ok(i64::from_be_bytes(read_array(packet, offset)?))
}

const ORIGIN_PREFIX: &[u8] = b"git-upload/bootstrap-origin/";
const ACCOUNT_PREFIX: &[u8] = b"git-upload/account-revision/";
const HEAD_PREFIX: &[u8] = b"git-upload/account-current/";
const ORIGIN_MAGIC: &[u8; 8] = b"AOSGUBO1";
const ACCOUNT_MAGIC: &[u8; 8] = b"AOSGUBA1";
const HEAD_MAGIC: &[u8; 8] = b"AOSGUBH1";
const ORIGIN_DOMAIN: &[u8] = b"aos.sandbox.git-upload.bootstrap-origin.v1\0";
const ACCOUNT_DOMAIN: &[u8] = b"aos.sandbox.git-upload.account-revision.v1\0";
const ORIGIN_FIXED_BYTES: usize = 408;
const ACCOUNT_BYTES: usize = 452;
const HEAD_BYTES: usize = 68;

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
        if source.policy.compiler_origin().is_some()
            || source.verify_git_capacity(canonical_capacity)? != *capacity
        {
            return Err(GitUploadBootstrapErrorV1::InvalidSource);
        }
        require_original_policy(self.journal, source)?;
        let origin = encode_origin(source, canonical_capacity)?;
        let origin_digest = commitment(ORIGIN_DOMAIN, &origin);
        let account = encode_account(
            source.policy.project(), 1, ObjectDigest::from_bytes([0; 32]),
            origin_digest, ResourceVector::ZERO, ResourceVector::ZERO,
        );
        let head = encode_account_head(
            source.policy.project(), 1, commitment(ACCOUNT_DOMAIN, &account),
        );
        let project = source.policy.project();
        let transaction = JournalTransaction::new(
            source.transaction_id(b"git-upload-bootstrap"),
            vec![
                JournalRecord::put(RecordNamespace::PublisherPolicy, origin_key(project), origin),
                JournalRecord::put(RecordNamespace::PublisherPolicy, account_key(project, 1), account),
                JournalRecord::put(RecordNamespace::PublisherPolicy, account_head_key(project), head),
            ],
        ).map_err(PublisherPolicyError::from)?;
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
                    == Some(source.policy.project().as_bytes().as_slice()))
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
        validate_namespace(self.journal, self.limits)?;
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
            || now < source.policy.not_before() || now >= source.policy.expires_at()
        {
            return Err(GitUploadBootstrapErrorV1::Conflict);
        }
        let [packet, policy, key, body] = credentials.ready()
            .ok_or(GitUploadBootstrapErrorV1::Conflict)?;
        if packet != source.packet.as_slice() || policy != source.policy.canonical_policy()
            || key != source.key.as_slice() || source.verify_git_capacity(body)? != *capacity
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
    if record.key() != origin_key(source.policy.project())
        || origin.get(100..132) != Some(source.key.as_slice())
        || origin.get(132..404) != Some(source.packet.as_slice())
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
        &policy_revision_key(source.policy.project(), source.policy.generation()))
        .ok_or(GitUploadBootstrapErrorV1::Conflict)?;
    let head = journal.get(RecordNamespace::PublisherPolicy,
        &policy_current_key(source.policy.project()))
        .ok_or(GitUploadBootstrapErrorV1::Conflict)?;
    if revision != encode_policy_revision(&source.policy)?.as_slice()
        || head != encode_policy_head(&source.policy).as_slice()
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

fn origin_key(project: ProjectId) -> Vec<u8> {
    key(ORIGIN_PREFIX, project.as_bytes(), None)
}

fn account_key(project: ProjectId, generation: u64) -> Vec<u8> {
    key(ACCOUNT_PREFIX, project.as_bytes(), Some(generation))
}

fn account_head_key(project: ProjectId) -> Vec<u8> {
    key(HEAD_PREFIX, project.as_bytes(), None)
}

fn record_header(magic: &[u8; 8], project: ProjectId, generation: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(project.as_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes
}

fn check_record_header(
    bytes: &[u8],
    magic: &[u8; 8],
    minimum: usize,
) -> Result<(ProjectId, u64), PublisherPolicyError> {
    if bytes.len() < minimum || bytes.get(..8) != Some(magic.as_slice())
        || u16::from_be_bytes(array(bytes, 8)?) != 1
        || u16::from_be_bytes(array(bytes, 10)?) != 0
    {
        return Err(PublisherPolicyError::CorruptState);
    }
    let project = ProjectId::from_bytes(array(bytes, 12)?);
    let generation = u64::from_be_bytes(array(bytes, 28)?);
    if project.as_bytes() == &[0; 16] || generation == 0 {
        return Err(PublisherPolicyError::CorruptState);
    }
    Ok((project, generation))
}

fn encode_origin(
    source: &VerifiedPublisherPolicySourceV1,
    body: &[u8],
) -> Result<Vec<u8>, PublisherPolicyError> {
    let mut bytes = record_header(ORIGIN_MAGIC, source.policy.project(), source.policy.generation());
    bytes.extend_from_slice(commitment(HEAD_DOMAIN, &encode_policy_head(&source.policy)).as_bytes());
    bytes.extend_from_slice(commitment(REVISION_DOMAIN, &encode_policy_revision(&source.policy)?).as_bytes());
    bytes.extend_from_slice(&source.key);
    bytes.extend_from_slice(&source.packet);
    let length = u32::try_from(body.len()).map_err(|_| PublisherPolicyError::CorruptState)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(body);
    Ok(bytes)
}

fn encode_account(
    project: ProjectId,
    generation: u64,
    predecessor: ObjectDigest,
    origin: ObjectDigest,
    committed: ResourceVector,
    reserved: ResourceVector,
) -> Vec<u8> {
    let mut bytes = record_header(ACCOUNT_MAGIC, project, generation);
    bytes.extend_from_slice(predecessor.as_bytes());
    bytes.extend_from_slice(origin.as_bytes());
    for vector in [committed, reserved] {
        for dimension in ResourceDimension::ALL {
            bytes.extend_from_slice(&vector.get(dimension).to_be_bytes());
        }
    }
    bytes
}

fn encode_account_head(project: ProjectId, generation: u64, revision: ObjectDigest) -> Vec<u8> {
    let mut bytes = record_header(HEAD_MAGIC, project, generation);
    bytes.extend_from_slice(revision.as_bytes());
    bytes
}

struct HistoricalOrigin {
    capacity: GitUploadCapacityV1,
    digest: ObjectDigest,
}

struct AccountRevision {
    predecessor: ObjectDigest,
    origin: ObjectDigest,
    committed: ResourceVector,
    reserved: ResourceVector,
    digest: ObjectDigest,
}

/// Accumulates only the three closed families inside the sole namespace replay.
#[derive(Default)]
pub(super) struct GitUploadBootstrapReplayV1 {
    origins: BTreeMap<ProjectId, HistoricalOrigin>,
    accounts: BTreeMap<ProjectId, BTreeMap<u64, AccountRevision>>,
    heads: BTreeMap<ProjectId, (u64, ObjectDigest)>,
}

impl GitUploadBootstrapReplayV1 {
    pub(super) fn consume(
        &mut self,
        journal: &Journal,
        record_key: &[u8],
        bytes: &[u8],
    ) -> Result<bool, PublisherPolicyError> {
        if record_key.starts_with(ORIGIN_PREFIX) {
            let (project, generation) = check_record_header(bytes, ORIGIN_MAGIC, ORIGIN_FIXED_BYTES)?;
            let length = u32::from_be_bytes(array(bytes, 404)?) as usize;
            if length == 0 || length > aos_sandbox_core::MAXIMUM_GIT_UPLOAD_CAPACITY_BYTES_V1
                || bytes.len() != ORIGIN_FIXED_BYTES + length || record_key != origin_key(project)
            {
                return Err(PublisherPolicyError::CorruptState);
            }
            let revision_bytes = journal.get(RecordNamespace::PublisherPolicy,
                &policy_revision_key(project, generation)).ok_or(PublisherPolicyError::CorruptState)?;
            if revision_bytes.get(..8) != Some(POLICY_REVISION_MAGIC.as_slice()) {
                return Err(PublisherPolicyError::CorruptState);
            }
            let revision = decode_policy_revision(revision_bytes)?;
            let packet: [u8; PACKET_BYTES] = array(bytes, 132)?;
            let scope = PublisherSessionScope {
                principal: PrincipalId::from_bytes(array(&packet, 8)?),
                node: NodeId::from_bytes(array(&packet, 24)?),
                project,
                cache_resource: ResourceId::from_bytes(array(&packet, 56)?),
            };
            let source = VerifiedPublisherPolicySourceV1::verify(
                packet, revision.canonical_policy(), array(bytes, 100)?, scope, revision.not_before(),
            ).map_err(|_| PublisherPolicyError::CorruptState)?;
            let capacity = source.verify_git_capacity(&bytes[ORIGIN_FIXED_BYTES..])
                .map_err(|_| PublisherPolicyError::CorruptState)?;
            if source.policy != revision || commitment(HEAD_DOMAIN, &encode_policy_head(&revision))
                    != ObjectDigest::from_bytes(array(bytes, 36)?)
                || commitment(REVISION_DOMAIN, revision_bytes) != ObjectDigest::from_bytes(array(bytes, 68)?)
                || self.origins.insert(project, HistoricalOrigin {
                    capacity, digest: commitment(ORIGIN_DOMAIN, bytes),
                }).is_some()
            {
                return Err(PublisherPolicyError::CorruptState);
            }
        } else if record_key.starts_with(ACCOUNT_PREFIX) {
            let (project, generation) = check_record_header(bytes, ACCOUNT_MAGIC, ACCOUNT_BYTES)?;
            if bytes.len() != ACCOUNT_BYTES || record_key != account_key(project, generation) {
                return Err(PublisherPolicyError::CorruptState);
            }
            let mut vectors = [[0; ResourceDimension::COUNT]; 2];
            let mut offset = 100;
            for vector in &mut vectors {
                for amount in vector {
                    *amount = u64::from_be_bytes(array(bytes, offset)?);
                    offset += 8;
                }
            }
            let revision = AccountRevision {
                predecessor: ObjectDigest::from_bytes(array(bytes, 36)?),
                origin: ObjectDigest::from_bytes(array(bytes, 68)?),
                committed: ResourceVector::new(vectors[0]),
                reserved: ResourceVector::new(vectors[1]),
                digest: commitment(ACCOUNT_DOMAIN, bytes),
            };
            if self.accounts.entry(project).or_default().insert(generation, revision).is_some() {
                return Err(PublisherPolicyError::CorruptState);
            }
        } else if record_key.starts_with(HEAD_PREFIX) {
            let (project, generation) = check_record_header(bytes, HEAD_MAGIC, HEAD_BYTES)?;
            if bytes.len() != HEAD_BYTES || record_key != account_head_key(project)
                || self.heads.insert(project, (generation, ObjectDigest::from_bytes(array(bytes, 36)?))).is_some()
            {
                return Err(PublisherPolicyError::CorruptState);
            }
        } else {
            return Ok(false);
        }
        Ok(true)
    }

    pub(super) fn finish(self) -> Result<(), PublisherPolicyError> {
        if self.origins.len() != self.accounts.len() || self.origins.len() != self.heads.len() {
            return Err(PublisherPolicyError::CorruptState);
        }
        for (project, origin) in self.origins {
            let revisions = self.accounts.get(&project).ok_or(PublisherPolicyError::CorruptState)?;
            let mut generation = 0_u64;
            let mut previous = ObjectDigest::from_bytes([0; 32]);
            for (actual, revision) in revisions {
                generation = generation.checked_add(1).ok_or(PublisherPolicyError::CorruptState)?;
                if *actual != generation || revision.predecessor != previous
                    || revision.origin != origin.digest
                    || ResourceAccount::from_usage(
                        ResourceCeilings::bounded(origin.capacity.ceilings()),
                        revision.committed, revision.reserved,
                    ).is_err()
                    || (generation == 1
                        && (revision.committed != ResourceVector::ZERO || revision.reserved != ResourceVector::ZERO))
                {
                    return Err(PublisherPolicyError::CorruptState);
                }
                previous = revision.digest;
            }
            if generation == 0 || self.heads.get(&project) != Some(&(generation, previous)) {
                return Err(PublisherPolicyError::CorruptState);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_account_and_head_records_preserve_all_twenty_two_amounts() {
        let project = ProjectId::from_bytes([1; 16]);
        let committed = ResourceVector::new(std::array::from_fn(|index| index as u64 + 1));
        let reserved = ResourceVector::new(std::array::from_fn(|index| index as u64 + 30));
        let bytes = encode_account(
            project, 2, ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]), committed, reserved,
        );
        let head = encode_account_head(project, 2, commitment(ACCOUNT_DOMAIN, &bytes));

        assert_eq!(bytes.len(), ACCOUNT_BYTES);
        assert_eq!(head.len(), HEAD_BYTES);
        assert_eq!(check_record_header(&bytes, ACCOUNT_MAGIC, ACCOUNT_BYTES).unwrap(), (project, 2));
        for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
            assert_eq!(u64::from_be_bytes(array(&bytes, 100 + index * 8).unwrap()), committed.get(dimension));
            assert_eq!(u64::from_be_bytes(array(&bytes, 276 + index * 8).unwrap()), reserved.get(dimension));
        }
    }

    #[test]
    fn partial_account_family_is_not_replay_complete() {
        let project = ProjectId::from_bytes([1; 16]);
        let mut replay = GitUploadBootstrapReplayV1::default();
        replay.heads.insert(project, (1, ObjectDigest::from_bytes([2; 32])));

        assert!(replay.finish().is_err());
    }

    #[test]
    fn record_header_version_and_reserved_bytes_are_closed() {
        let project = ProjectId::from_bytes([1; 16]);
        let original = encode_account_head(project, 1, ObjectDigest::from_bytes([2; 32]));
        assert!(check_record_header(&original, HEAD_MAGIC, HEAD_BYTES).is_ok());

        for index in [9, 11] {
            let mut changed = original.clone();
            changed[index] = 2;
            assert!(check_record_header(&changed, HEAD_MAGIC, HEAD_BYTES).is_err());
        }
    }
}
