//! Exact execution target, command, credential, and runtime-argument semantics.

use sha2::{Digest as _, Sha256};

use crate::model::view::Environment;
use crate::{
    AssignmentEpoch, FeatureRef, IncarnationId, NamespaceGeneration, ObjectDigest, RelativePath,
    SandboxId,
};

use super::validation::{
    runtime_argument_evidence_commitment, validate_arguments, validate_environment_overlay,
    visit_effective_environment,
};
use super::{
    EFFECTIVE_ENVIRONMENT_DIGEST_DOMAIN, EXEC_ARGUMENT_FIXED_HEADROOM_BYTES,
    EXEC_ARGUMENT_POINTER_BYTES, InvalidExecutionSpec, MAX_EXECUTION_ENVIRONMENT_NAME_BYTES,
    MAX_EXECUTION_ENVIRONMENT_VALUE_BYTES, MAX_EXECUTION_STRING_BYTES,
};

/// Stores a nonzero payload boot identity observed for one runtime generation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PayloadBootId([u8; 16]);

impl PayloadBootId {
    /// Constructs a payload boot identity from its exact portable bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec::Unspecified`] for the all-zero sentinel.
    pub fn new(bytes: [u8; 16]) -> Result<Self, InvalidExecutionSpec> {
        if bytes == [0; 16] {
            Err(InvalidExecutionSpec::Unspecified)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns the exact portable bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Binds an execution to one signed assignment and observed payload namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionTargetV1 {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    assignment_epoch: AssignmentEpoch,
    assignment_digest: ObjectDigest,
    namespace_generation: NamespaceGeneration,
    payload_boot_id: PayloadBootId,
}

impl ExecutionTargetV1 {
    /// Constructs one exact signed namespace target.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec::Unspecified`] for a zero identity,
    /// epoch, generation, or assignment digest.
    pub fn new(
        sandbox: SandboxId,
        incarnation: IncarnationId,
        assignment_epoch: AssignmentEpoch,
        assignment_digest: ObjectDigest,
        namespace_generation: NamespaceGeneration,
        payload_boot_id: PayloadBootId,
    ) -> Result<Self, InvalidExecutionSpec> {
        if sandbox.as_bytes() == &[0; 16]
            || incarnation.as_bytes() == &[0; 16]
            || assignment_epoch.get() == 0
            || assignment_digest.as_bytes() == &[0; 32]
            || namespace_generation.get() == 0
        {
            return Err(InvalidExecutionSpec::Unspecified);
        }
        Ok(Self {
            sandbox,
            incarnation,
            assignment_epoch,
            assignment_digest,
            namespace_generation,
            payload_boot_id,
        })
    }

    /// Returns the durable sandbox identity.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the exact runtime incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the assignment epoch that fences controller authority.
    #[must_use]
    pub const fn assignment_epoch(&self) -> AssignmentEpoch {
        self.assignment_epoch
    }

    /// Returns the digest of the signed assignment manifest.
    #[must_use]
    pub const fn assignment_digest(&self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the exact signed payload namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> NamespaceGeneration {
        self.namespace_generation
    }

    /// Returns the observed boot identity for the payload generation.
    #[must_use]
    pub const fn payload_boot_id(&self) -> PayloadBootId {
        self.payload_boot_id
    }
}

/// Stores one exec-compatible environment overlay entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionEnvironmentEntry {
    name: String,
    value: Vec<u8>,
}

impl ExecutionEnvironmentEntry {
    /// Constructs one byte-preserving environment assignment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec::InvalidEnvironmentEntry`] when the name
    /// is empty or oversized, contains NUL or `=`, or when the value is
    /// oversized or contains NUL.
    pub fn new(name: String, value: Vec<u8>) -> Result<Self, InvalidExecutionSpec> {
        if name.is_empty()
            || name.len() > MAX_EXECUTION_ENVIRONMENT_NAME_BYTES
            || name.contains(['\0', '='])
            || value.len() > MAX_EXECUTION_ENVIRONMENT_VALUE_BYTES
            || value.contains(&0)
        {
            return Err(InvalidExecutionSpec::InvalidEnvironmentEntry);
        }
        Ok(Self { name, value })
    }

    /// Returns the UTF-8 variable name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the byte-exact variable value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Stores the guest-visible kernel-overflow-safe credential projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionCredentialsV1 {
    user_id: u32,
    primary_group_id: u32,
    supplementary_group_ids: Vec<u32>,
}

impl ExecutionCredentialsV1 {
    /// Constructs one guest identity with a canonical supplementary group set.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec`] for `u32::MAX`, an oversized or
    /// unordered supplementary set, or repetition of the primary group.
    pub fn new(
        user_id: u32,
        primary_group_id: u32,
        supplementary_group_ids: Vec<u32>,
    ) -> Result<Self, InvalidExecutionSpec> {
        if user_id == u32::MAX
            || primary_group_id == u32::MAX
            || supplementary_group_ids.contains(&u32::MAX)
        {
            return Err(InvalidExecutionSpec::OverflowIdentity);
        }
        if supplementary_group_ids.len() > MAX_EXECUTION_SUPPLEMENTARY_GROUPS
            || !strictly_increasing(&supplementary_group_ids)
        {
            return Err(InvalidExecutionSpec::SupplementaryGroupsNotCanonical);
        }
        if supplementary_group_ids.contains(&primary_group_id) {
            return Err(InvalidExecutionSpec::PrimaryGroupRepeated);
        }
        Ok(Self {
            user_id,
            primary_group_id,
            supplementary_group_ids,
        })
    }

    /// Returns the guest user identifier.
    #[must_use]
    pub const fn user_id(&self) -> u32 {
        self.user_id
    }

    /// Returns the guest primary group identifier.
    #[must_use]
    pub const fn primary_group_id(&self) -> u32 {
        self.primary_group_id
    }

    /// Returns supplementary group identifiers in strict ascending order.
    #[must_use]
    pub fn supplementary_group_ids(&self) -> &[u32] {
        &self.supplementary_group_ids
    }
}

/// Stores the complete portable command and credential projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionCommandV1 {
    arguments: Vec<Vec<u8>>,
    environment_overlay: Vec<ExecutionEnvironmentEntry>,
    working_directory: RelativePath,
    credentials: ExecutionCredentialsV1,
}

impl ExecutionCommandV1 {
    /// Constructs one byte-exact command without shell interpretation.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec`] when arguments or overlay entries
    /// contain NUL, exceed portable per-string or aggregate bounds, or when
    /// the overlay is not strictly ordered by variable name.
    pub fn new(
        arguments: Vec<Vec<u8>>,
        environment_overlay: Vec<ExecutionEnvironmentEntry>,
        working_directory: RelativePath,
        credentials: ExecutionCredentialsV1,
    ) -> Result<Self, InvalidExecutionSpec> {
        validate_arguments(&arguments)?;
        validate_environment_overlay(&environment_overlay)?;
        Ok(Self {
            arguments,
            environment_overlay,
            working_directory,
            credentials,
        })
    }

    /// Returns the byte-exact argument vector, including executable at index zero.
    #[must_use]
    pub fn arguments(&self) -> &[Vec<u8>] {
        &self.arguments
    }

    /// Returns the environment overlay in strict variable-name order.
    #[must_use]
    pub fn environment_overlay(&self) -> &[ExecutionEnvironmentEntry] {
        &self.environment_overlay
    }

    /// Returns the normalized path relative to the sandbox root.
    #[must_use]
    pub const fn working_directory(&self) -> &RelativePath {
        &self.working_directory
    }

    /// Returns the guest-visible credential projection.
    #[must_use]
    pub const fn credentials(&self) -> &ExecutionCredentialsV1 {
        &self.credentials
    }
}

/// Commits one observed runtime `ARG_MAX` to an exact profile and target.
///
/// This value proves only internal consistency. It does not authenticate the
/// observer or authorize execution: a protected runtime adapter must establish
/// the profile commitment and target freshness before constructing it. No
/// effectful exec boundary may rely on this source-only value unless that
/// protected adapter has verified it for the exact target immediately before
/// enforcement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionRuntimeArgumentLimitV1 {
    runtime_profile: FeatureRef,
    runtime_profile_commitment: ObjectDigest,
    target: ExecutionTargetV1,
    runtime_limit_bytes: u64,
    evidence_commitment: ObjectDigest,
}

impl ExecutionRuntimeArgumentLimitV1 {
    /// Constructs self-consistent runtime argument-limit evidence.
    ///
    /// The SHA-256 preimage is the ASCII domain
    /// `aos-sandbox-runtime-argument-limit-evidence-v1`, one NUL byte,
    /// `u64be(profile-namespace-length)`, the namespace bytes, `u32be(major)`,
    /// `u32be(minor)`, the 32-byte nonzero profile digest, the complete target
    /// fields in their declared order, and `u64be(observed-ARG_MAX)`. The target
    /// includes namespace generation and payload boot identity.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec`] when the profile is unregistered or is
    /// not a runtime profile, the profile digest is zero, or the observed limit
    /// is zero.
    pub fn new(
        runtime_profile: FeatureRef,
        runtime_profile_commitment: ObjectDigest,
        target: ExecutionTargetV1,
        runtime_limit_bytes: u64,
    ) -> Result<Self, InvalidExecutionSpec> {
        crate::validate_required_features(std::slice::from_ref(&runtime_profile))?;
        if !runtime_profile
            .namespace()
            .starts_with("aos.sandbox.runtime.")
            || runtime_profile_commitment.as_bytes() == &[0; 32]
            || runtime_limit_bytes == 0
        {
            return Err(InvalidExecutionSpec::RuntimeArgumentEvidenceMismatch);
        }

        let evidence_commitment = runtime_argument_evidence_commitment(
            &runtime_profile,
            runtime_profile_commitment,
            &target,
            runtime_limit_bytes,
        );
        Ok(Self {
            runtime_profile,
            runtime_profile_commitment,
            target,
            runtime_limit_bytes,
            evidence_commitment,
        })
    }

    /// Returns the registered runtime enforcement profile.
    #[must_use]
    pub const fn runtime_profile(&self) -> &FeatureRef {
        &self.runtime_profile
    }

    /// Returns the exact runtime-profile commitment supplied by protected evidence.
    #[must_use]
    pub const fn runtime_profile_commitment(&self) -> ObjectDigest {
        self.runtime_profile_commitment
    }

    /// Returns the complete execution target bound into the evidence.
    #[must_use]
    pub const fn target(&self) -> &ExecutionTargetV1 {
        &self.target
    }

    /// Returns the observed runtime `ARG_MAX` in bytes.
    #[must_use]
    pub const fn runtime_limit_bytes(&self) -> u64 {
        self.runtime_limit_bytes
    }

    /// Returns the purpose-domain commitment to all evidence fields.
    #[must_use]
    pub const fn evidence_commitment(&self) -> ObjectDigest {
        self.evidence_commitment
    }
}

/// Commits conservative exec framing against target-bound runtime evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionArgumentEnvelopeV1 {
    runtime_evidence: ExecutionRuntimeArgumentLimitV1,
    accounted_bytes: u64,
    effective_environment_digest: ObjectDigest,
}

impl ExecutionArgumentEnvelopeV1 {
    // Only the canonical decoder may materialize a claim before comparing it
    // with the value rederived by `ExecutionSpecV1::new`.
    pub(crate) fn from_claimed_parts(
        runtime_evidence: ExecutionRuntimeArgumentLimitV1,
        accounted_bytes: u64,
        effective_environment_digest: ObjectDigest,
    ) -> Self {
        Self {
            runtime_evidence,
            accounted_bytes,
            effective_environment_digest,
        }
    }

    /// Derives the exact effective environment and conservative exec byte charge.
    ///
    /// Overlay entries replace same-named base entries. Accounting includes
    /// every argument NUL, every effective environment `=`, every environment
    /// NUL, two terminating pointers, one pointer per string using an
    /// eight-byte portable upper bound, and fixed alignment/auxiliary headroom.
    /// The effective-environment SHA-256 preimage is the ASCII domain
    /// `aos-sandbox-effective-environment-v1`, a NUL byte, each sorted entry as
    /// `u64be(name-length) || name || u64be(value-length) || value`, and the
    /// final `u64be(entry-count)`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidExecutionSpec`] when an effective string exceeds the
    /// conservative per-string ceiling, arithmetic overflows, or the complete
    /// charge exceeds the observed runtime limit.
    pub fn derive(
        runtime_evidence: ExecutionRuntimeArgumentLimitV1,
        base_environment: &Environment,
        command: &ExecutionCommandV1,
    ) -> Result<Self, InvalidExecutionSpec> {
        let mut digest = Sha256::new();
        digest.update(EFFECTIVE_ENVIRONMENT_DIGEST_DOMAIN);
        let mut environment_bytes = 0_usize;
        let mut environment_count = 0_usize;
        visit_effective_environment(base_environment, command, |name, value| {
            let string_bytes = name
                .len()
                .checked_add(1)
                .and_then(|length| length.checked_add(value.len()))
                .ok_or(InvalidExecutionSpec::ArgumentEnvelopeExceeded)?;
            let terminated_bytes = string_bytes
                .checked_add(1)
                .ok_or(InvalidExecutionSpec::ArgumentEnvelopeExceeded)?;
            if terminated_bytes > MAX_EXECUTION_STRING_BYTES || value.contains(&0) {
                return Err(InvalidExecutionSpec::ArgumentEnvelopeExceeded);
            }
            environment_bytes = environment_bytes
                .checked_add(terminated_bytes)
                .ok_or(InvalidExecutionSpec::ArgumentEnvelopeExceeded)?;
            environment_count = environment_count
                .checked_add(1)
                .ok_or(InvalidExecutionSpec::ArgumentEnvelopeExceeded)?;
            digest.update((name.len() as u64).to_be_bytes());
            digest.update(name.as_bytes());
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
            Ok(())
        })?;
        let environment_count_u64 = u64::try_from(environment_count)
            .map_err(|_| InvalidExecutionSpec::ArgumentEnvelopeExceeded)?;
        digest.update(environment_count_u64.to_be_bytes());

        let argument_bytes = command
            .arguments()
            .iter()
            .try_fold(0_usize, |total, argument| {
                total.checked_add(argument.len())?.checked_add(1)
            })
            .ok_or(InvalidExecutionSpec::ArgumentEnvelopeExceeded)?;
        let pointer_count = command
            .arguments()
            .len()
            .checked_add(environment_count)
            .and_then(|count| count.checked_add(2))
            .ok_or(InvalidExecutionSpec::ArgumentEnvelopeExceeded)?;
        let accounted_bytes = argument_bytes
            .checked_add(environment_bytes)
            .and_then(|bytes| {
                pointer_count
                    .checked_mul(EXEC_ARGUMENT_POINTER_BYTES)
                    .and_then(|pointers| bytes.checked_add(pointers))
            })
            .and_then(|bytes| bytes.checked_add(EXEC_ARGUMENT_FIXED_HEADROOM_BYTES))
            .ok_or(InvalidExecutionSpec::ArgumentEnvelopeExceeded)?;
        let accounted_bytes = u64::try_from(accounted_bytes)
            .map_err(|_| InvalidExecutionSpec::ArgumentEnvelopeExceeded)?;
        if accounted_bytes > runtime_evidence.runtime_limit_bytes() {
            return Err(InvalidExecutionSpec::ArgumentEnvelopeExceeded);
        }

        Ok(Self {
            runtime_evidence,
            accounted_bytes,
            effective_environment_digest: ObjectDigest::from_bytes(digest.finalize().into()),
        })
    }

    /// Returns the exact runtime evidence that qualified the envelope calculation.
    #[must_use]
    pub const fn runtime_evidence(&self) -> &ExecutionRuntimeArgumentLimitV1 {
        &self.runtime_evidence
    }

    /// Returns the runtime-qualified maximum exec argument/environment bytes.
    #[must_use]
    pub const fn runtime_limit_bytes(&self) -> u64 {
        self.runtime_evidence.runtime_limit_bytes()
    }

    /// Returns the conservative byte charge used for admission.
    #[must_use]
    pub const fn accounted_bytes(&self) -> u64 {
        self.accounted_bytes
    }

    /// Returns the digest of the exact effective environment after overlay.
    #[must_use]
    pub const fn effective_environment_digest(&self) -> ObjectDigest {
        self.effective_environment_digest
    }
}
