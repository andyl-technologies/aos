//! Protected controller signing for prepared broker authorization plans.
//!
//! The key is loaded only from a fixed systemd credential name. This owner
//! signs the exact domain-separated statement prepared by the controller core;
//! completion independently verifies the result against its pinned policy.

use std::path::Path;

use aos_sandbox_protocol::authorization_artifact::{
    BrokerPlanPreparation, ReturnedSignature, SignedBrokerPlan, SigningAuthority,
};
use aos_sandbox_core::format::{decode_broker_authorization_plan, decode_trust_policy};
use aos_sandbox_core::model::{KeyUsage, SignaturePurpose};
use aos_sandbox_core::{
    BrokerAudience, BrokerAuthorizationPlan, BrokerPlanTrustAnchor, DecodeLimits, MediaType,
    ObjectDigest, PortableMediaType, ProtocolId, RevocationScopeId, descriptor_for_bytes,
    sign_statement,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use aos_sandbox_linux::credential::{
    CredentialOwnerPolicyV1, read_required_public_role_credential_v1,
};
use super::credential_receiving::{
    CredentialMetadataV1, CredentialSourceV1, OrdinaryCredentialSourceV1,
};

const CREDENTIAL_NAME: &str = "broker-plan-signing-key";
const POLICY_CREDENTIAL_NAME: &str = "broker-plan-policy.cbor";
const PUBLIC_KEY_CREDENTIAL_NAME: &str = "broker-plan-public-key";
const REVOCATION_SCOPE_CREDENTIAL_NAME: &str = "broker-revocation-scope";
const MOUNT_POLICY_CREDENTIAL_NAME: &str = "mount-broker-plan-policy.cbor";
const MOUNT_PUBLIC_KEY_CREDENTIAL_NAME: &str = "mount-broker-plan-public-key";
const MOUNT_REVOCATION_SCOPE_CREDENTIAL_NAME: &str = "mount-broker-revocation-scope";
const SEED_BYTES: usize = 32;
const MAXIMUM_POLICY_BYTES: usize = SigningAuthority::maximum_canonical_policy_bytes_v1();

pub(crate) struct ControllerBrokerPlanSignerV1 {
    seed: Zeroizing<[u8; SEED_BYTES]>,
    authority: SigningAuthority,
    mount_authority: SigningAuthority,
    create_revocation_scope: Option<RevocationScopeId>,
    mount_revocation_scope: Option<RevocationScopeId>,
}

/// Retains the real canonical preparation, expanded key and signing message.
/// This local DATA owner cannot dispatch a Storage request.
pub(crate) struct PreparedSnapshotPlanV3 {
    original: aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1,
}

impl PreparedSnapshotPlanV3 {
    pub(crate) fn preparation(&self) -> Result<&BrokerPlanPreparation, ControllerBrokerPlanSignerError> {
        self.original.preparation().ok_or(ControllerBrokerPlanSignerError::Completion)
    }

    pub(crate) fn key_message_loan(
        &self,
    ) -> Result<aos_sandbox_core::PreparedStatementKeyLoanV1<'_>, ControllerBrokerPlanSignerError> {
        self.original.key_message_loan()
            .map_err(|_| ControllerBrokerPlanSignerError::Signature)
    }

    pub(crate) fn complete(
        &mut self,
        signature: &aos_sandbox_core::model::SignatureBytes,
        now_seconds: i64,
    ) -> Result<SignedBrokerPlan, ControllerBrokerPlanSignerError> {
        use aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanCompletionErrorV1;
        self.original.complete_once(signature, now_seconds).map_err(|cause| match cause {
            PreparedBrokerPlanCompletionErrorV1::Consumed => ControllerBrokerPlanSignerError::Completion,
            PreparedBrokerPlanCompletionErrorV1::Authorization(cause) =>
                ControllerBrokerPlanSignerError::SnapshotCompletion(cause),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ControllerBrokerPlanSignerError {
    #[error("controller broker-plan credential is invalid or unreadable")]
    Credential,
    #[error("controller broker-plan signature does not match the prepared statement")]
    Signature,
    #[error("controller broker-plan signature failed policy verification")]
    Completion,
    #[error("Snapshot broker-plan completion failed: {0}")]
    SnapshotCompletion(aos_sandbox_protocol::authorization_artifact::AuthorizationPreparationError),
}

impl ControllerBrokerPlanSignerV1 {
    /// Prepares only the genuine operation-owned Snapshot derivative.
    pub(crate) fn prepare_snapshot_plan_v3(
        &self,
        original: &aos_sandbox::SnapshotDerivedStoragePreparationV3,
    ) -> Result<PreparedSnapshotPlanV3, ControllerBrokerPlanSignerError> {
        let plan = original.plan();
        let [grant] = plan.grants() else {
            return Err(ControllerBrokerPlanSignerError::Completion);
        };
        if plan.audience() != BrokerAudience::Storage || plan.protocol() != ProtocolId::StorageBroker
            || grant.verb() != aos_sandbox_core::BrokerVerb::StorageAtomicSnapshot
            || grant.target() != aos_sandbox_core::BrokerGrantTarget::Assignment
            || grant.maximum_descriptors() != 0
        {
            return Err(ControllerBrokerPlanSignerError::Completion);
        }
        let preparation = BrokerPlanPreparation::new(plan.clone(), self.authority.clone())
            .map_err(|_| ControllerBrokerPlanSignerError::Completion)?;
        let key = SigningKey::from_bytes(&self.seed);
        let original = aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1::new(
            preparation, key,
        ).map_err(|_| ControllerBrokerPlanSignerError::Signature)?;
        Ok(PreparedSnapshotPlanV3 { original })
    }

    /// Prepares the actual Create carrier only beside its genuine Root8/U loan.
    ///
    /// All model/key/message construction is already paid by that same loan.
    /// The exact admitted plan and statement are compared again before the
    /// retained Controller key is expanded. This never reads new credentials.
    pub(crate) fn prepare_create_plan_v1(
        &self,
        original: &aos_sandbox::OriginalCreateStorageUseSigningV1<'_, '_, '_>,
        preparation: BrokerPlanPreparation,
    ) -> Result<aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1,
        Box<dyn std::error::Error + Send + Sync>> {
        let inputs = original.inputs_v1()?;
        let (_, scope) = self.create_plan_inputs_v1()?;
        let statement = preparation.signing_request().statement();
        if preparation.canonical_plan() != inputs.plan
            || preparation.signing_request().canonical_statement() != inputs.statement
            || statement.signer() != self.authority.signer()
            || statement.verification_policy() != self.authority.policy_descriptor() {
            return Err(Box::new(ControllerBrokerPlanSignerError::Completion));
        }
        // Scope belongs to the fixed Controller credential owner. The pure
        // semantic checker has already compared it to Root's entire plan.
        let plan = decode_broker_authorization_plan(inputs.plan, DecodeLimits::default())?;
        if plan.revocation_scope() != scope {
            return Err(Box::new(ControllerBrokerPlanSignerError::Completion));
        }
        let key = SigningKey::from_bytes(&self.seed);
        aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1::new(preparation, key)
            .map_err(Into::into)
    }

    /// Expands the actual Controller key only beside the genuine C23 issuer.
    ///
    /// The Native issuer has paid and normalized this exact Root preparation.
    /// No old U loan or caller-provided unsigned preparation is accepted here.
    pub(crate) fn prepare_original_storage_apply_plan_v1(
        &self,
        issuer: &aos_sandbox::cold_launch_publication::OriginalStorageApplyIssuanceV1,
        admission: &aos_sandbox::normal_root::RootStorageApplyAdmissionOriginalV1<'_>,
        construction: &aos_sandbox::normal_root::RootStorageApplyConstructionTurnV1<'_>,
    ) -> Result<aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1,
        Box<dyn std::error::Error + Send + Sync>> {
        let preparation = issuer.signing_preparation_v1(admission, construction)?;
        self.prepare_original_plan_v1(preparation)
    }

    /// Prepares Network's exact plan inside the accepted Start construction turn.
    ///
    /// The genuine prepared owner checks the same Root admission, fresh lease,
    /// current Start native interval and complete normalized request before
    /// lending its preparation. Its caller funds the key and message first.
    ///
    /// # Errors
    /// Rejects changed or unfinished admission and construction originals,
    /// mismatched fixed signing credentials, or signing-message preparation.
    pub(crate) fn prepare_original_start_resource_plan_v2(
        &self,
        prepared: &aos_sandbox::PreparedStartResourceRequestOriginalV2,
        admission: &aos_sandbox::normal_root::RootStartResourcePrepareAdmissionOriginalV2<'_>,
        construction: &aos_sandbox::normal_root::RootStartResourceConstructionTurnV2<'_>,
        original: &aos_sandbox::OriginalStartHostRootLoanV1<'_, '_>,
        controller: &aos_sandbox::Journal,
    ) -> Result<aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1,
        Box<dyn std::error::Error + Send + Sync>> {
        let preparation = prepared.signing_preparation_v2(
            admission, construction, original, controller,
        )?;
        let (authority, scope) = self.start_resource_plan_inputs_v2(prepared)?;
        self.prepare_original_plan_with_inputs_v2(preparation, authority, scope)
    }

    /// Prepares the companion Guardian plan inside the same paid Host construction.
    ///
    /// # Errors
    /// Refuses an incomplete Host pair, foreign native/Root owner or signing credential mismatch.
    pub(crate) fn prepare_original_start_guardian_plan_v2(
        &self, prepared: &aos_sandbox::PreparedStartResourceRequestOriginalV2,
        admission: &aos_sandbox::normal_root::RootStartResourcePrepareAdmissionOriginalV2<'_>,
        construction: &aos_sandbox::normal_root::RootStartResourceConstructionTurnV2<'_>,
        original: &aos_sandbox::OriginalStartHostRootLoanV1<'_, '_>,
        controller: &aos_sandbox::Journal,
    ) -> Result<aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1,
        Box<dyn std::error::Error + Send + Sync>> {
        let preparation = prepared.guardian_signing_preparation_v2(
            admission, construction, original, controller)?;
        self.prepare_original_plan_v1(preparation)
    }

    /// Expands the fixed key only inside the genuine same-D construction loan.
    ///
    /// That loan has paid the full model, prepared-key and message backing,
    /// independently compared Root's exact plan and statement, and retained the
    /// actual current C17/Source/Root association. No new credential is read.
    ///
    /// # Errors
    /// Returns changed original custody, fixed credential mismatch, or the real
    /// prepared signing-message error. The enclosing native after stays owed.
    pub(crate) fn prepare_original_delete_resource_plan_v2(
        &self,
        original: &mut aos_sandbox::OriginalDeleteResourceSigningV2<'_, '_, '_, '_, '_>,
        controller: &aos_sandbox::Journal,
    ) -> Result<aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1,
        Box<dyn std::error::Error + Send + Sync>> {
        let preparation = original.signing_preparation_v2(controller)?;
        self.prepare_original_plan_v1(preparation)
    }

    /// Expands the existing fixed key only for the actual Maintenance borrower.
    ///
    /// # Errors
    /// Retains current Maintenance/Root refusal, fixed authority mismatch, or
    /// the actual key/message constructor failure. Native posts remain owed.
    pub(crate) fn prepare_original_maintenance_storage_plan_v3(
        &self,
        original: &mut aos_sandbox::ControllerCatalogMaintenanceSigningBorrowV3<'_ , '_>,
    ) -> Result<aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1,
        Box<dyn std::error::Error + Send + Sync>> {
        self.prepare_original_plan_v1(original.signing_preparation_v3()?)
    }

    // Every genuine native owner validates its own admission before entering
    // this private shared credential comparison and key expansion.
    /// Expands the same protected general key only beside the held Stop Root loan.
    ///
    /// The actual Source22 pays the independent canonical reconstruction and
    /// key/message representation before this existing preparation engine runs.
    /// No Root signing credential, arbitrary plan or authority callback is lent.
    ///
    /// # Errors
    /// Refuses changed Source/C/Root custody, incomplete native preparation or
    /// any mismatch with the already retained fixed Controller credentials.
    pub(crate) fn prepare_original_stop_cleanup_plan_v1(
        &self,
        original: &aos_sandbox::normal_root::RootStopCleanupSigningLoanV1<'_, '_, '_>,
        controller: &aos_sandbox::Journal,
    ) -> Result<aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1,
        Box<dyn std::error::Error + Send + Sync>> {
        self.prepare_original_plan_v1(original.signing_preparation_v1(controller)?)
    }

    fn prepare_original_plan_v1(
        &self,
        preparation: &BrokerPlanPreparation,
    ) -> Result<aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1,
        Box<dyn std::error::Error + Send + Sync>> {
        let (authority, scope) = self.create_plan_inputs_v1()?;
        self.prepare_original_plan_with_inputs_v2(preparation, authority, scope)
    }

    fn prepare_original_plan_with_inputs_v2(
        &self,
        preparation: &BrokerPlanPreparation,
        authority: &SigningAuthority,
        scope: RevocationScopeId,
    ) -> Result<aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1,
        Box<dyn std::error::Error + Send + Sync>> {
        let statement = preparation.signing_request().statement();
        let plan = preparation.plan_data_v1();
        if statement.signer() != authority.signer()
            || statement.verification_policy() != authority.policy_descriptor()
            || plan.revocation_scope() != scope {
            return Err(Box::new(ControllerBrokerPlanSignerError::Completion));
        }
        let key = SigningKey::from_bytes(&self.seed);
        aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1::new(
            preparation.clone(), key,
        ).map_err(Into::into)
    }

    /// Returns the broker-plan public key for separate-purpose key isolation.
    pub(crate) fn verifying_key_bytes(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.seed)
            .verifying_key()
            .to_bytes()
    }

    /// Loads the independent public plan-verification anchor for attachment effects.
    ///
    /// The revocation scope is a separate protected Host authority credential,
    /// not a value copied from the plan or request being verified.
    ///
    /// # Errors
    ///
    /// Rejects missing, unsafe, or inconsistent policy, key, or scope bytes.
    pub(crate) fn trust_anchor_from_process_credentials()
    -> Result<BrokerPlanTrustAnchor, ControllerBrokerPlanSignerError> {
        Self::trust_anchor_from_credentials(
            POLICY_CREDENTIAL_NAME,
            PUBLIC_KEY_CREDENTIAL_NAME,
            REVOCATION_SCOPE_CREDENTIAL_NAME,
        )
    }

    /// Loads Mount's independent public policy, key, and revocation scope.
    pub(crate) fn mount_trust_anchor_from_process_credentials()
    -> Result<BrokerPlanTrustAnchor, ControllerBrokerPlanSignerError> {
        Self::trust_anchor_from_credentials(
            MOUNT_POLICY_CREDENTIAL_NAME,
            MOUNT_PUBLIC_KEY_CREDENTIAL_NAME,
            MOUNT_REVOCATION_SCOPE_CREDENTIAL_NAME,
        )
    }

    pub(super) fn trust_anchor_from_process_credentials_with_source(
        source: &mut impl CredentialSourceV1,
    ) -> Result<BrokerPlanTrustAnchor, ControllerBrokerPlanSignerError> {
        Self::trust_anchor_from_credentials_with_source(source,
            POLICY_CREDENTIAL_NAME, PUBLIC_KEY_CREDENTIAL_NAME, REVOCATION_SCOPE_CREDENTIAL_NAME)
    }

    pub(super) fn mount_trust_anchor_from_process_credentials_with_source(
        source: &mut impl CredentialSourceV1,
    ) -> Result<BrokerPlanTrustAnchor, ControllerBrokerPlanSignerError> {
        Self::trust_anchor_from_credentials_with_source(source,
            MOUNT_POLICY_CREDENTIAL_NAME, MOUNT_PUBLIC_KEY_CREDENTIAL_NAME, MOUNT_REVOCATION_SCOPE_CREDENTIAL_NAME)
    }

    /// Reads Mount's validated revocation scope for typed effect-plan construction.
    pub(crate) fn mount_revocation_scope_from_process_credentials()
    -> Result<RevocationScopeId, ControllerBrokerPlanSignerError> {
        Ok(Self::mount_trust_anchor_from_process_credentials()?.revocation_scope())
    }

    fn trust_anchor_from_credentials(
        policy_name: &'static str,
        public_key_name: &'static str,
        revocation_scope_name: &'static str,
    ) -> Result<BrokerPlanTrustAnchor, ControllerBrokerPlanSignerError> {
        Self::trust_anchor_from_credentials_with_source(&mut OrdinaryCredentialSourceV1,
            policy_name, public_key_name, revocation_scope_name)
    }

    fn trust_anchor_from_credentials_with_source(
        source: &mut impl CredentialSourceV1,
        policy_name: &'static str,
        public_key_name: &'static str,
        revocation_scope_name: &'static str,
    ) -> Result<BrokerPlanTrustAnchor, ControllerBrokerPlanSignerError> {
        let directory = source.process_directory()
            .ok_or(ControllerBrokerPlanSignerError::Credential)?;
        if !Path::new(&directory).is_absolute() {
            return Err(ControllerBrokerPlanSignerError::Credential);
        }
        source.directory(&directory);
        let directory = Path::new(&directory);
        let public_key: [u8; SEED_BYTES] =
            read_public_credential_with_source(source, directory, public_key_name, SEED_BYTES)?
                .try_into()
                .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
        let revocation_scope: [u8; 16] =
            read_public_credential_with_source(source, directory, revocation_scope_name, 16)?
                .try_into()
                .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
        let policy_bytes = read_public_credential_with_source(source, directory, policy_name, MAXIMUM_POLICY_BYTES)?;
        let policy = decode_trust_policy(&policy_bytes, DecodeLimits::default())
            .map_err(|cause| {
                source.retain(cause);
                ControllerBrokerPlanSignerError::Credential
            })?;
        if policy.purpose() != SignaturePurpose::BrokerAuthorization {
            return Err(ControllerBrokerPlanSignerError::Credential);
        }
        let fingerprint = ObjectDigest::from_bytes(Sha256::digest(public_key).into());
        let mut matching = policy.allowed_keys().iter().filter(|key| {
            key.usage() == KeyUsage::BrokerAuthorization && key.public_key_sha256() == fingerprint
        });
        let signer = matching
            .next()
            .cloned()
            .ok_or(ControllerBrokerPlanSignerError::Credential)?;
        if matching.next().is_some() {
            return Err(ControllerBrokerPlanSignerError::Credential);
        }
        let media_type = MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
            .map_err(|_| ControllerBrokerPlanSignerError::Credential)?;
        let descriptor = descriptor_for_bytes(media_type, &policy_bytes);
        BrokerPlanTrustAnchor::from_trusted_configuration(
            policy_bytes,
            descriptor,
            policy.trust_scope(),
            signer,
            public_key,
            RevocationScopeId::from_bytes(revocation_scope),
            DecodeLimits::default(),
        )
        .map_err(|cause| {
            source.retain(cause);
            ControllerBrokerPlanSignerError::Credential
        })
    }

    /// Loads an optional fixed credential without following its leaf symlink.
    pub(crate) fn from_process_credentials_optional()
    -> Result<Option<Self>, ControllerBrokerPlanSignerError> {
        Self::from_process_credentials_with_source(&mut OrdinaryCredentialSourceV1)
    }

    pub(super) fn from_process_credentials_with_source(
        source: &mut impl CredentialSourceV1,
    ) -> Result<Option<Self>, ControllerBrokerPlanSignerError> {
        Self::from_process_credentials_inner(source, false)
    }

    // The selected startup pays and retains this additional existing public
    // credential before any Create plan shape or signing preparation is made.
    pub(super) fn from_create_process_credentials_with_source(
        source: &mut impl CredentialSourceV1,
    ) -> Result<Option<Self>, ControllerBrokerPlanSignerError> {
        Self::from_process_credentials_inner(source, true)
    }

    fn from_process_credentials_inner(
        source: &mut impl CredentialSourceV1,
        require_create_scope: bool,
    ) -> Result<Option<Self>, ControllerBrokerPlanSignerError> {
        let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") else {
            return Ok(None);
        };
        source.directory(&directory);
        if !Path::new(&directory).is_absolute() {
            return Err(ControllerBrokerPlanSignerError::Credential);
        }
        let directory = Path::new(&directory);
        let Some(seed_bytes) = source.read(
            directory, CREDENTIAL_NAME, SEED_BYTES, SEED_BYTES,
            CredentialMetadataV1::Protected {
                private: true,
                owner: CredentialOwnerPolicyV1::Any,
            },
        )
        .map_err(|cause| {
            source.retain(cause);
            ControllerBrokerPlanSignerError::Credential
        })?
        else {
            return Ok(None);
        };
        let seed_bytes = Zeroizing::new(seed_bytes);
        let seed = Zeroizing::new(
            seed_bytes
                .as_slice()
                .try_into()
                .map_err(|cause| {
                    source.retain(cause);
                    ControllerBrokerPlanSignerError::Credential
                })?,
        );

        let signing_key = SigningKey::from_bytes(&seed);
        let expected_public_key = signing_key.verifying_key().to_bytes();
        let authority = signing_authority_from_credentials(
            source,
            directory,
            POLICY_CREDENTIAL_NAME,
            PUBLIC_KEY_CREDENTIAL_NAME,
            expected_public_key,
        )?;
        let mount_authority = signing_authority_from_credentials(
            source,
            directory,
            MOUNT_POLICY_CREDENTIAL_NAME,
            MOUNT_PUBLIC_KEY_CREDENTIAL_NAME,
            expected_public_key,
        )?;

        let create_revocation_scope = if require_create_scope {
            Some(read_create_revocation_scope_v1(source, directory)?)
        } else {
            None
        };

        let mount_revocation_scope = if require_create_scope {
            Some(read_plan_revocation_scope_v2(source, directory, PlanScopeKindV2::Mount)?)
        } else {
            None
        };

        Ok(Some(Self {
            seed,
            authority,
            mount_authority,
            create_revocation_scope,
            mount_revocation_scope,
        }))
    }

    /// Borrows the independently configured public inputs for Create plan sizing.
    ///
    /// This supplies unsigned DATA only. Signing remains gated by the genuine
    /// completed U/Root admission and the same retained private signing key.
    pub(crate) fn create_plan_inputs_v1(
        &self,
    ) -> Result<(&SigningAuthority, RevocationScopeId), ControllerBrokerPlanSignerError> {
        let scope = self.create_revocation_scope
            .ok_or(ControllerBrokerPlanSignerError::Credential)?;
        Ok((&self.authority, scope))
    }

    /// Borrows only this genuine prepared resource's configured public inputs.
    ///
    /// # Errors
    /// Refuses a missing retained fixed scope. Mount never falls back to the
    /// Controller policy or scope even when their signing keys happen to match.
    pub(crate) fn start_resource_plan_inputs_v2(
        &self, prepared: &aos_sandbox::PreparedStartResourceRequestOriginalV2,
    ) -> Result<(&SigningAuthority, RevocationScopeId), ControllerBrokerPlanSignerError> {
        use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1 as Purpose;
        match prepared.purpose_data_v2() {
            Purpose::MountNamespace => Ok((&self.mount_authority,
                self.mount_revocation_scope.ok_or(ControllerBrokerPlanSignerError::Credential)?)),
            Purpose::NetworkPrepare | Purpose::StorageGuestRoot | Purpose::HostLaunch => self.create_plan_inputs_v1(),
        }
    }

    /// Signs one immutable broker plan and verifies its completed artifact.
    pub(crate) fn sign_plan(
        &self,
        plan: BrokerAuthorizationPlan,
        now_seconds: i64,
    ) -> Result<SignedBrokerPlan, ControllerBrokerPlanSignerError> {
        self.sign_with_authority(plan, now_seconds, &self.authority)
    }

    /// Signs only Mount-scoped plans under Mount's independent policy.
    pub(crate) fn sign_mount_plan(
        &self,
        plan: BrokerAuthorizationPlan,
        now_seconds: i64,
    ) -> Result<SignedBrokerPlan, ControllerBrokerPlanSignerError> {
        if plan.audience() != BrokerAudience::Mount || plan.protocol() != ProtocolId::MountBroker {
            return Err(ControllerBrokerPlanSignerError::Completion);
        }
        self.sign_with_authority(plan, now_seconds, &self.mount_authority)
    }

    /// Verifies the exact original Mount plan retained in a durable attempt.
    ///
    /// Recovery never signs a replacement under the same operation identity.
    /// Current assignment and ownership authority are checked separately when
    /// the recovered plan is rebound to the protected attempt.
    pub(crate) fn recover_mount_plan(
        &self,
        canonical_plan: &[u8],
        canonical_signature: &[u8],
    ) -> Result<SignedBrokerPlan, ControllerBrokerPlanSignerError> {
        let plan = decode_broker_authorization_plan(canonical_plan, DecodeLimits::default())
            .map_err(|_| ControllerBrokerPlanSignerError::Completion)?;
        if plan.audience() != BrokerAudience::Mount || plan.protocol() != ProtocolId::MountBroker {
            return Err(ControllerBrokerPlanSignerError::Completion);
        }
        let issued = plan.issued_seconds();
        let preparation = BrokerPlanPreparation::new(plan, self.mount_authority.clone())
            .map_err(|_| ControllerBrokerPlanSignerError::Completion)?;
        if preparation.canonical_plan() != canonical_plan {
            return Err(ControllerBrokerPlanSignerError::Completion);
        }
        preparation
            .complete(ReturnedSignature::Envelope(canonical_signature), issued)
            .map_err(|_| ControllerBrokerPlanSignerError::Completion)
    }

    fn sign_with_authority(
        &self,
        plan: BrokerAuthorizationPlan,
        now_seconds: i64,
        authority: &SigningAuthority,
    ) -> Result<SignedBrokerPlan, ControllerBrokerPlanSignerError> {
        let preparation = BrokerPlanPreparation::new(plan, authority.clone())
            .map_err(|_| ControllerBrokerPlanSignerError::Completion)?;
        let signing_key = SigningKey::from_bytes(&self.seed);
        let signature = sign_statement(
            preparation.signing_request().statement().clone(),
            &signing_key,
        )
        .map_err(|_| ControllerBrokerPlanSignerError::Signature)?;
        preparation
            .complete(ReturnedSignature::Bytes(signature.signature()), now_seconds)
            .map_err(|_| ControllerBrokerPlanSignerError::Completion)
    }
}

fn read_create_revocation_scope_v1(
    source: &mut impl CredentialSourceV1,
    directory: &Path,
) -> Result<RevocationScopeId, ControllerBrokerPlanSignerError> {
    read_plan_revocation_scope_v2(source, directory, PlanScopeKindV2::Controller)
}

#[derive(Clone, Copy)]
enum PlanScopeKindV2 { Controller, Mount }

fn read_plan_revocation_scope_v2(
    source: &mut impl CredentialSourceV1,
    directory: &Path,
    purpose: PlanScopeKindV2,
) -> Result<RevocationScopeId, ControllerBrokerPlanSignerError> {
    let name = match purpose {
        PlanScopeKindV2::Controller => REVOCATION_SCOPE_CREDENTIAL_NAME,
        PlanScopeKindV2::Mount => MOUNT_REVOCATION_SCOPE_CREDENTIAL_NAME,
    };
    let bytes = read_public_credential_with_source(source, directory, name, 16)?;
    let bytes: [u8; 16] = bytes.as_slice().try_into().map_err(|cause| {
        source.retain(cause);
        ControllerBrokerPlanSignerError::Credential
    })?;
    Ok(RevocationScopeId::from_bytes(bytes))
}

fn signing_authority_from_credentials(
    source: &mut impl CredentialSourceV1,
    directory: &Path,
    policy_name: &'static str,
    public_key_name: &'static str,
    expected_public_key: [u8; SEED_BYTES],
) -> Result<SigningAuthority, ControllerBrokerPlanSignerError> {
    let public_key: [u8; SEED_BYTES] =
        read_public_credential_with_source(source, directory, public_key_name, SEED_BYTES)?
            .as_slice()
            .try_into()
            .map_err(|cause| {
                source.retain(cause);
                ControllerBrokerPlanSignerError::Credential
            })?;
    if public_key != expected_public_key {
        return Err(ControllerBrokerPlanSignerError::Credential);
    }

    let policy_bytes = read_public_credential_with_source(source, directory, policy_name, MAXIMUM_POLICY_BYTES)?;
    let policy = decode_trust_policy(&policy_bytes, DecodeLimits::default())
        .map_err(|cause| {
            source.retain(cause);
            ControllerBrokerPlanSignerError::Credential
        })?;
    if policy.purpose() != SignaturePurpose::BrokerAuthorization {
        return Err(ControllerBrokerPlanSignerError::Credential);
    }
    let fingerprint = ObjectDigest::from_bytes(Sha256::digest(public_key).into());
    let mut matches = policy.allowed_keys().iter().filter(|key| {
        key.usage() == KeyUsage::BrokerAuthorization && key.public_key_sha256() == fingerprint
    });
    let signer = matches
        .next()
        .cloned()
        .ok_or(ControllerBrokerPlanSignerError::Credential)?;
    if matches.next().is_some() {
        return Err(ControllerBrokerPlanSignerError::Credential);
    }
    let media_type = MediaType::new(PortableMediaType::TrustPolicy.as_str().to_owned())
        .map_err(|cause| {
            source.retain(cause);
            ControllerBrokerPlanSignerError::Credential
        })?;
    let policy_descriptor = descriptor_for_bytes(media_type, &policy_bytes);
    SigningAuthority::new(
        policy_bytes,
        policy_descriptor,
        policy.trust_scope(),
        signer,
        public_key,
        SignaturePurpose::BrokerAuthorization,
        DecodeLimits::default(),
    )
    .map_err(|cause| {
        source.retain(cause);
        ControllerBrokerPlanSignerError::Credential
    })
}

fn read_public_credential(
    directory: &Path,
    name: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ControllerBrokerPlanSignerError> {
    read_required_public_role_credential_v1(directory, name, maximum_bytes)
        .map_err(|_| ControllerBrokerPlanSignerError::Credential)
}

fn read_public_credential_with_source(
    source: &mut impl CredentialSourceV1,
    directory: &Path,
    name: &'static str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ControllerBrokerPlanSignerError> {
    source.read(directory, name, 1, maximum_bytes, CredentialMetadataV1::PublicRegular)
        .map_err(|_| ControllerBrokerPlanSignerError::Credential)?
        .ok_or(ControllerBrokerPlanSignerError::Credential)
}

#[cfg(test)]
mod create_scope_tests {
    use super::*;
    use aos_sandbox_linux::credential::FixedRoleCredentialErrorV1;

    struct ScopeSource {
        bytes: Vec<u8>,
        calls: usize,
        retained: bool,
    }

    impl CredentialSourceV1 for ScopeSource {
        fn read(&mut self, _directory: &Path, name: &'static str,
            minimum: usize, maximum: usize, metadata: CredentialMetadataV1,
        ) -> Result<Option<Vec<u8>>, FixedRoleCredentialErrorV1> {
            assert_eq!(name, REVOCATION_SCOPE_CREDENTIAL_NAME);
            assert_eq!((minimum, maximum), (1, 16));
            assert!(matches!(metadata, CredentialMetadataV1::PublicRegular));
            self.calls += 1;
            Ok(Some(self.bytes.clone()))
        }

        fn retain<E: std::error::Error + Send + Sync + 'static>(&mut self, _cause: E) {
            self.retained = true;
        }
    }

    struct IndependentScopes {
        mount: Option<Vec<u8>>,
        names: Vec<&'static str>,
    }

    impl CredentialSourceV1 for IndependentScopes {
        fn read(&mut self, _directory: &Path, name: &'static str,
            minimum: usize, maximum: usize, metadata: CredentialMetadataV1,
        ) -> Result<Option<Vec<u8>>, FixedRoleCredentialErrorV1> {
            assert_eq!((minimum, maximum), (1, 16));
            assert!(matches!(metadata, CredentialMetadataV1::PublicRegular));
            self.names.push(name);
            Ok(match name {
                REVOCATION_SCOPE_CREDENTIAL_NAME => Some(vec![23; 16]),
                MOUNT_REVOCATION_SCOPE_CREDENTIAL_NAME => self.mount.clone(),
                _ => panic!("unexpected fixed scope credential"),
            })
        }
    }

    #[test]
    fn mount_scope_keeps_its_independent_configured_identity() {
        let mut source = IndependentScopes { mount: Some(vec![41; 16]), names: Vec::new() };
        let directory = Path::new("/credential-fixture");

        let controller = read_create_revocation_scope_v1(&mut source, directory).unwrap();
        let mount = read_plan_revocation_scope_v2(&mut source, directory, PlanScopeKindV2::Mount).unwrap();

        assert_eq!(controller, RevocationScopeId::from_bytes([23; 16]));
        assert_eq!(mount, RevocationScopeId::from_bytes([41; 16]));
        assert_eq!(source.names, [REVOCATION_SCOPE_CREDENTIAL_NAME, MOUNT_REVOCATION_SCOPE_CREDENTIAL_NAME]);
    }

    #[test]
    fn absent_mount_scope_never_falls_back_to_controller_scope() {
        let mut source = IndependentScopes { mount: None, names: Vec::new() };

        assert!(read_plan_revocation_scope_v2(&mut source, Path::new("/credential-fixture"),
            PlanScopeKindV2::Mount).is_err());

        assert_eq!(source.names, [MOUNT_REVOCATION_SCOPE_CREDENTIAL_NAME]);
    }

    #[test]
    fn create_scope_uses_the_exact_configured_public_credential() {
        let mut source = ScopeSource { bytes: vec![23; 16], calls: 0, retained: false };

        let scope = read_create_revocation_scope_v1(&mut source, Path::new("/credential-fixture"))
            .unwrap();

        assert_eq!(scope, RevocationScopeId::from_bytes([23; 16]));
        assert_eq!(source.calls, 1);
        assert!(!source.retained);
    }

    #[test]
    fn short_create_scope_retains_the_actual_conversion_cause() {
        let mut source = ScopeSource { bytes: vec![23; 15], calls: 0, retained: false };

        assert!(read_create_revocation_scope_v1(&mut source, Path::new("/credential-fixture"))
            .is_err());

        assert_eq!(source.calls, 1);
        assert!(source.retained);
    }
}
