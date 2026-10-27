//! Owns passive prerequisite and independent publication comparison DATA.

use super::*;

/// Binds external ancestry, authority, cache, and revocation currentness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPublicationPrerequisitesV1 {
    pub(super) ancestry_head: ObjectDigest,
    pub(super) compiler_authority_head: ObjectDigest,
    pub(super) cache_domain_head: ObjectDigest,
    pub(super) revocation_head: ObjectDigest,
    pub(super) generation: u64,
    pub(super) digest: ObjectDigest,
}

impl PolicyPublicationPrerequisitesV1 {
    /// Constructs an exact protected-current prerequisite tuple.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyCompilerJournalErrorV1::NonCanonicalPublication`] for a
    /// sentinel digest or generation.
    pub fn new(
        ancestry_head: ObjectDigest,
        compiler_authority_head: ObjectDigest,
        cache_domain_head: ObjectDigest,
        revocation_head: ObjectDigest,
        generation: u64,
    ) -> Result<Self, PolicyCompilerJournalErrorV1> {
        if generation == 0
            || [
                ancestry_head,
                compiler_authority_head,
                cache_domain_head,
                revocation_head,
            ]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let mut value = Self {
            ancestry_head,
            compiler_authority_head,
            cache_domain_head,
            revocation_head,
            generation,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        value.digest = prerequisite_digest(&value);
        Ok(value)
    }

    /// Returns the complete prerequisite tuple commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Returns the exact protected hierarchy/ancestry head.
    #[must_use]
    pub const fn ancestry_head(&self) -> ObjectDigest {
        self.ancestry_head
    }

    /// Returns the exact compiler-authority head.
    #[must_use]
    pub const fn compiler_authority_head(&self) -> ObjectDigest {
        self.compiler_authority_head
    }

    /// Returns the exact cache-domain authority head.
    #[must_use]
    pub const fn cache_domain_head(&self) -> ObjectDigest {
        self.cache_domain_head
    }

    /// Returns the exact revocation head.
    #[must_use]
    pub const fn revocation_head(&self) -> ObjectDigest {
        self.revocation_head
    }

    /// Returns the protected prerequisite generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}


// This view carries encoder inputs, not the verified brand or a commit right.
// Q04 needs the three TX-independent bodies before choosing its native TXID.
pub(crate) struct PublicationBodyFieldsV1<'data> {
    pub(crate) project: ProjectId,
    pub(crate) sandbox: SandboxId,
    pub(crate) normalized_input: ObjectDigest,
    pub(crate) candidate: &'data CompiledPolicyCandidateV1,
    pub(crate) prerequisites: &'data PolicyPublicationPrerequisitesV1,
}

// The three independent bodies are retained verbatim until envelope planning.
// This recipe is deliberately unbranded and has no publication/commit method.
/// Retains canonical independent publication bodies without native authority.
pub struct Q04IndependentPublicationRecipeV1 {
    pub(crate) project: ProjectId,
    pub(crate) sandbox: SandboxId,
    pub(crate) normalized_input: ObjectDigest,
    pub(crate) candidate_digest: ObjectDigest,
    pub(crate) prerequisites: PolicyPublicationPrerequisitesV1,
    pub(crate) candidate_key: PolicyCompilerJournalKeyV1,
    pub(crate) diagnostics_key: PolicyCompilerJournalKeyV1,
    pub(crate) current_key: PolicyCompilerJournalKeyV1,
    pub(crate) candidate_body: Vec<u8>,
    pub(crate) diagnostics_body: Vec<u8>,
    pub(crate) current_body: Vec<u8>,
    pub(crate) diagnostics_digest: ObjectDigest,
    pub(crate) before: ObjectDigest,
    pub(crate) recipe: ObjectDigest,
}

impl Q04IndependentPublicationRecipeV1 {
    // Pure shared encoders, with no replay validator, Journal or publication
    // brand. Root separately proves actual vacancy before calling this stage;
    // Controller only compares its reconstructed bytes with the same reply.
    pub(crate) fn encode(
        fields: PublicationBodyFieldsV1<'_>,
        canonical_diagnostics: &[u8],
        candidate_key: PolicyCompilerJournalKeyV1,
        diagnostics_key: PolicyCompilerJournalKeyV1,
    ) -> Result<Self, PolicyCompilerJournalErrorV1> {
        let PublicationBodyFieldsV1 {
            project,
            sandbox,
            normalized_input,
            candidate,
            prerequisites,
        } = fields;
        let candidate_digest = candidate.commitment().digest();
        let diagnostics_body =
            encode_diagnostics_payload(project, sandbox, candidate_digest, canonical_diagnostics)?;
        let diagnostics_digest = digest_bytes(DIAGNOSTICS_DOMAIN, &diagnostics_body);
        let candidate_body = encode_candidate_payload(
            1,
            PublicationBodyFieldsV1 {
                project,
                sandbox,
                normalized_input,
                candidate,
                prerequisites,
            },
            diagnostics_digest,
        )?;
        let current_key = policy_current_key(project, sandbox)?;
        let current_body = encode_current_payload(
            project,
            sandbox,
            1,
            candidate_digest,
            normalized_input,
            diagnostics_digest,
            prerequisites,
        );
        let current_key_length = u32::try_from(current_key.as_bytes().len())
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let before = ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.create-q04.policy-before-cas.v1\0")
                .chain_update(current_key_length.to_be_bytes())
                .chain_update(current_key.as_bytes())
                .chain_update([0])
                .chain_update(1_u64.to_be_bytes())
                .finalize()
                .into(),
        );
        let mut digest = Sha256::new()
            .chain_update(b"aos.sandbox.create-q04.pre-envelope-publication-recipe.v1\0")
            .chain_update(1_u64.to_be_bytes())
            .chain_update([3]);
        for (kind, key, body) in [
            (1_u8, &candidate_key, candidate_body.as_slice()),
            (2, &diagnostics_key, diagnostics_body.as_slice()),
            (4, &current_key, current_body.as_slice()),
        ] {
            let key_length = u32::try_from(key.as_bytes().len())
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
            let body_length = u32::try_from(body.len())
                .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
            digest.update([kind]);
            digest.update(key_length.to_be_bytes());
            digest.update(key.as_bytes());
            digest.update(body_length.to_be_bytes());
            digest.update(body);
        }
        Ok(Self {
            project,
            sandbox,
            normalized_input,
            candidate_digest,
            prerequisites: prerequisites.clone(),
            candidate_key,
            diagnostics_key,
            current_key,
            candidate_body,
            diagnostics_body,
            current_body,
            diagnostics_digest,
            before,
            recipe: ObjectDigest::from_bytes(digest.finalize().into()),
        })
    }

    /// Copies the independent prepublication comparison commitment.
    #[must_use]
    pub const fn before_digest(&self) -> ObjectDigest {
        self.before
    }

    /// Copies the canonical complete recipe commitment.
    #[must_use]
    pub const fn recipe_digest(&self) -> ObjectDigest {
        self.recipe
    }

    /// Derives the original transaction identity from nonzero precut and nonce DATA.
    ///
    /// # Errors
    /// Rejects zero precut, reserved nonce or derived transaction identity.
    pub fn initial_transaction_id(
        &self,
        precut: ObjectDigest,
        reserved_nonce: [u8; 16],
    ) -> Result<[u8; 16], PolicyCompilerJournalErrorV1> {
        if precut.as_bytes() == &[0; 32] || reserved_nonce == [0; 16] {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        let digest = Sha256::new()
            .chain_update(b"aos.sandbox.create-q04.publication-transaction-id.v1\0")
            .chain_update(precut.as_bytes())
            .chain_update(reserved_nonce)
            .chain_update(self.recipe.as_bytes())
            .finalize();
        let mut transaction = [0; 16];
        transaction.copy_from_slice(&digest[..16]);
        if transaction == [0; 16] {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }
        Ok(transaction)
    }
}

/// Encodes independent Candidate, diagnostics and Current comparison bodies.
///
/// # Errors
/// Retains noncanonical input, diagnostics, candidate or prerequisite failures.
pub fn q04_independent_publication_data_v1(
    input: &PolicyCompilerInputV1,
    candidate: &CompiledPolicyCandidateV1,
    prerequisites: &PolicyPublicationPrerequisitesV1,
) -> Result<Q04IndependentPublicationRecipeV1, PolicyCompilerJournalErrorV1> {
    let project = input.project().project();
    let sandbox = input.sandbox();
    let normalized_input = normalized_policy_input_digest_v1(input)
        .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
    let diagnostics = aos_sandbox_protocol::policy_data::canonical_bytes(
        DIAGNOSTICS_DOMAIN,
        candidate.explanation(),
    )
    .map_err(crate::PolicyModelError::from)?;
    if candidate.authority_status() != CandidateAuthorityV1::NonAuthoritativeAncestry {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    let candidate_digest = candidate.commitment().digest();
    let candidate_key = policy_key(
        PolicyCompilerJournalRecordKindV1::Candidate,
        project,
        sandbox,
        candidate_digest,
    )?;
    let diagnostics_key = policy_key(
        PolicyCompilerJournalRecordKindV1::Diagnostics,
        project,
        sandbox,
        candidate_digest,
    )?;
    Q04IndependentPublicationRecipeV1::encode(
        PublicationBodyFieldsV1 {
            project,
            sandbox,
            normalized_input,
            candidate,
            prerequisites,
        },
        &diagnostics,
        candidate_key,
        diagnostics_key,
    )
}
