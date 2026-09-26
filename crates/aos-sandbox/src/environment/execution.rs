//! Read-only Nix-store presentation and dormant build/execution admission.
//!
//! The types in this module are portable control records. They contain only
//! exact `/nix/store/...` identities protected by the fixed presentation owner,
//! never arbitrary host paths, file descriptors, daemon sockets, or effects. A
//! build or execution handoff can only be minted while the fixed environment
//! protected owner is mutably borrowed and its current projection has just
//! been replayed.
//!
//! ```text
//! AOSNXJ01 || v1 || phase || project || sandbox || operation || generation ||
//! manifest || request || presentation || policy || attempt || observation ||
//! output-set || receipt || sha256
//! ```

use std::marker::PhantomData;

use aos_sandbox_core::{
    ExecutionAdmissionDraftV1, ExecutionId, ObjectDescriptor, ObjectDigest, ProjectId, ResourceId,
    Revision, SandboxId, decode_execution_spec_v1,
};
use sha2::{Digest as _, Sha256};

use super::protected_journal::{
    EnvironmentJournalOutcomeUnknownV1, PreparedEnvironmentJournalTransactionV1,
    ValidatedEnvironmentPostcommitV1,
};
use super::{
    EnvironmentActivationTransactionV1, EnvironmentGenerationLeaseStatusV1,
    EnvironmentLeaseConsumerV1, EnvironmentManifestDigestV1, EnvironmentSelectorV1,
    LiveAuthorityClockSampleV1,
};

/// Maximum objects admitted in one portable store presentation.
pub const MAXIMUM_NIX_STORE_PRESENTATION_OBJECTS: usize = 65_536;
/// Maximum bytes in one portable Nix store object name.
pub const MAXIMUM_NIX_STORE_OBJECT_NAME_BYTES: usize = 255;
/// Maximum canonical control bytes accepted by one dormant Nix build.
pub const MAXIMUM_NIX_BUILD_CONTROL_BYTES: u64 = 64 * 1024 * 1024;

/// Reports a malformed presentation, build request, or protected admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvironmentExecutionErrorV1 {
    /// A portable field or closed transition is invalid.
    InvalidModel,
    /// The protected current activation does not match the proposed operation.
    CurrentEnvironmentMismatch,
    /// The required execution lease or complete GC-root set is absent.
    RetentionEvidenceMissing,
    /// Canonical execution bytes cannot be decoded or reproduced.
    InvalidExecutionSpecification,
    /// Protected replay or evidence revalidation failed closed.
    ProtectedEvidenceUnavailable,
}

impl std::fmt::Display for EnvironmentExecutionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidModel => "invalid environment execution model",
            Self::CurrentEnvironmentMismatch => "protected current environment mismatch",
            Self::RetentionEvidenceMissing => "environment retention evidence is incomplete",
            Self::InvalidExecutionSpecification => "invalid execution specification",
            Self::ProtectedEvidenceUnavailable => "protected environment evidence is unavailable",
        })
    }
}

impl std::error::Error for EnvironmentExecutionErrorV1 {}

/// Stores one validated absolute Nix store object identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NixStorePathV1(String);

impl NixStorePathV1 {
    pub(super) fn from_protected(path: String) -> Result<Self, EnvironmentExecutionErrorV1> {
        let Some(name) = path.strip_prefix("/nix/store/") else {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        };
        let Some((hash, package_name)) = name.split_once('-') else {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        };
        let valid = name.len() <= MAXIMUM_NIX_STORE_OBJECT_NAME_BYTES
            && hash.len() == 32
            && hash
                .bytes()
                .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
            && !package_name.is_empty()
            && package_name.is_ascii()
            && package_name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'=')
            });
        if !valid {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        Ok(Self(path))
    }

    /// Borrows the exact Nix store object identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Binds one immutable closure descriptor to its portable store basename.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NixStorePresentationEntryV1 {
    object: ObjectDescriptor,
    path: NixStorePathV1,
}

impl NixStorePresentationEntryV1 {
    /// Constructs one nonauthorizing portable presentation entry.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1::InvalidModel`] for a sentinel
    /// descriptor.
    pub(super) fn from_protected(
        object: ObjectDescriptor,
        path: NixStorePathV1,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        if object.digest().as_bytes() == &[0; 32] || object.encoded_size() == 0 {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        Ok(Self { object, path })
    }

    /// Borrows the immutable closure object.
    #[must_use]
    pub const fn object(&self) -> &ObjectDescriptor {
        &self.object
    }

    /// Borrows the actual protected-observed Nix store path identity.
    #[must_use]
    pub const fn path(&self) -> &NixStorePathV1 {
        &self.path
    }
}

/// Selects one implementation-independent read-only store presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NixStorePresentationKindV1 {
    /// Presents only the selected closure through a kernel-enforced read-only view.
    ReadOnlyClosureView = 1,
    /// Presents only the selected closure through a read-only userspace filesystem.
    ReadOnlyUserspaceView = 2,
}

/// Describes an exact read-only projection with protected full store identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyNixStorePresentationV1 {
    project: ProjectId,
    sandbox: SandboxId,
    generation: Revision,
    manifest: EnvironmentManifestDigestV1,
    kind: NixStorePresentationKindV1,
    entries: Vec<NixStorePresentationEntryV1>,
    commitment: ObjectDigest,
}

impl ReadOnlyNixStorePresentationV1 {
    /// Constructs a complete presentation of exactly the selected closure.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1::InvalidModel`] unless entries
    /// are strictly descriptor-ordered, have unique names, stay within the
    /// fixed ceiling, and reproduce the selector's complete closure.
    pub(super) fn from_protected(
        selector: &EnvironmentSelectorV1,
        kind: NixStorePresentationKindV1,
        entries: Vec<NixStorePresentationEntryV1>,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        if entries.is_empty()
            || entries.len() > MAXIMUM_NIX_STORE_PRESENTATION_OBJECTS
            || !entries
                .windows(2)
                .all(|pair| pair[0].object() < pair[1].object())
        {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        let mut paths = entries.iter().map(|entry| entry.path()).collect::<Vec<_>>();
        paths.sort_unstable();
        if paths.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        let presented = entries
            .iter()
            .map(|entry| entry.object())
            .collect::<Vec<_>>();
        let mut closure = selector.closure().iter().collect::<Vec<_>>();
        closure.sort_unstable();
        if presented != closure {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }

        let manifest_record = selector.manifest_record();
        let commitment = presentation_commitment(selector, kind, &entries);
        Ok(Self {
            project: manifest_record.project(),
            sandbox: manifest_record.sandbox(),
            generation: selector.generation(),
            manifest: selector.manifest(),
            kind,
            entries,
            commitment,
        })
    }

    /// Returns the owning project.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the owning sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the exact immutable generation.
    #[must_use]
    pub const fn generation(&self) -> Revision {
        self.generation
    }

    /// Returns the exact generation-manifest commitment.
    #[must_use]
    pub const fn manifest(&self) -> EnvironmentManifestDigestV1 {
        self.manifest
    }

    /// Returns the implementation-independent presentation kind.
    #[must_use]
    pub const fn kind(&self) -> NixStorePresentationKindV1 {
        self.kind
    }

    /// Borrows the complete sorted closure presentation.
    #[must_use]
    pub fn entries(&self) -> &[NixStorePresentationEntryV1] {
        &self.entries
    }

    /// Returns the commitment to the exact portable presentation.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }
}

/// Selects the only two Nix build transports admitted by this contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NixBuildTransportV1 {
    /// Uses a daemon account that is cryptographically and operationally untrusted.
    UntrustedDaemonClient = 1,
    /// Uses a narrowing proxy that exposes only the bounded operation below.
    NarrowingProxy = 2,
}

/// Binds one constrained-build authority to a live boot-time interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NixBuildAuthorityFenceV1 {
    boot: ObjectDigest,
    valid_from_boottime_nanoseconds: u64,
    valid_until_boottime_nanoseconds: u64,
}

impl NixBuildAuthorityFenceV1 {
    pub(super) fn from_protected(
        boot: ObjectDigest,
        valid_from_boottime_nanoseconds: u64,
        valid_until_boottime_nanoseconds: u64,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        if boot.as_bytes() == &[0; 32]
            || valid_from_boottime_nanoseconds == 0
            || valid_until_boottime_nanoseconds <= valid_from_boottime_nanoseconds
            || valid_until_boottime_nanoseconds == u64::MAX
        {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        Ok(Self {
            boot,
            valid_from_boottime_nanoseconds,
            valid_until_boottime_nanoseconds,
        })
    }

    /// Reports whether one injected live sample remains inside the authority.
    #[must_use]
    pub(crate) fn admits(self, sample: LiveAuthorityClockSampleV1) -> bool {
        sample.boot() == self.boot
            && sample.boottime_nanoseconds() >= self.valid_from_boottime_nanoseconds
            && sample.boottime_nanoseconds() < self.valid_until_boottime_nanoseconds
    }

    /// Returns the boot identity bound to the authority.
    #[must_use]
    pub const fn boot(self) -> ObjectDigest {
        self.boot
    }

    /// Returns the exclusive boot-time expiry in nanoseconds.
    #[must_use]
    pub const fn valid_until_boottime_nanoseconds(self) -> u64 {
        self.valid_until_boottime_nanoseconds
    }
}

/// Stores fixed limits for one dormant Nix build invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NixBuildPolicyV1 {
    transport: NixBuildTransportV1,
    maximum_control_bytes: u64,
    maximum_output_objects: u32,
    network_allowed: bool,
}

impl NixBuildPolicyV1 {
    /// Constructs a build policy that can never grant network access.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1::InvalidModel`] for zero or
    /// excessive bounds, or when `network_allowed` is true.
    pub(super) fn from_protected(
        transport: NixBuildTransportV1,
        maximum_control_bytes: u64,
        maximum_output_objects: u32,
        network_allowed: bool,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        if maximum_control_bytes == 0
            || maximum_control_bytes > MAXIMUM_NIX_BUILD_CONTROL_BYTES
            || maximum_output_objects == 0
            || !usize::try_from(maximum_output_objects)
                .is_ok_and(|count| count <= MAXIMUM_NIX_STORE_PRESENTATION_OBJECTS)
            || network_allowed
        {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        Ok(Self {
            transport,
            maximum_control_bytes,
            maximum_output_objects,
            network_allowed,
        })
    }

    /// Returns the constrained transport.
    #[must_use]
    pub const fn transport(self) -> NixBuildTransportV1 {
        self.transport
    }

    /// Returns the control-byte ceiling.
    #[must_use]
    pub const fn maximum_control_bytes(self) -> u64 {
        self.maximum_control_bytes
    }

    /// Returns the output-object ceiling.
    #[must_use]
    pub const fn maximum_output_objects(self) -> u32 {
        self.maximum_output_objects
    }

    /// Reports whether network access is allowed; v1 always returns false.
    #[must_use]
    pub const fn network_allowed(self) -> bool {
        self.network_allowed
    }
}

/// Identifies one bounded Nix build against an immutable generation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NixBuildRequestV1 {
    operation: ResourceId,
    selector: EnvironmentSelectorV1,
    commitment: ObjectDigest,
}

impl NixBuildRequestV1 {
    /// Constructs one nonauthorizing, immutable build request.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1::InvalidModel`] for a sentinel
    /// operation identity.
    pub fn new(
        operation: ResourceId,
        selector: EnvironmentSelectorV1,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        if operation.as_bytes() == &[0; 16] {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        let commitment = build_request_commitment(operation, &selector);
        Ok(Self {
            operation,
            selector,
            commitment,
        })
    }

    /// Returns the durable operation identity.
    #[must_use]
    pub const fn operation(&self) -> ResourceId {
        self.operation
    }

    /// Borrows the exact requested selector.
    #[must_use]
    pub const fn selector(&self) -> &EnvironmentSelectorV1 {
        &self.selector
    }

    /// Returns the exact request commitment.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }
}

/// Selects one closed dormant build phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NixBuildPhaseV1 {
    /// Protected current environment was checked before an effect.
    Prepared = 1,
    /// The exact effect may have started and requires observation before retry.
    Indeterminate = 2,
    /// Exact output descriptors were observed and retained.
    Completed = 3,
    /// The build was definitively rejected before producing outputs.
    Rejected = 4,
}

/// Retains one bounded Nix build state for fixed-owner ambiguity recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NixBuildStateV1 {
    request: NixBuildRequestV1,
    presentation: ObjectDigest,
    policy: ObjectDigest,
    attempt: Revision,
    phase: NixBuildPhaseV1,
    outputs: Vec<ObjectDescriptor>,
    terminal_receipt: Option<ObjectDigest>,
}

impl NixBuildStateV1 {
    /// Constructs the initial pre-effect state.
    #[must_use]
    pub(super) fn prepared(
        request: NixBuildRequestV1,
        presentation: ObjectDigest,
        policy: ObjectDigest,
    ) -> Self {
        Self {
            request,
            presentation,
            policy,
            attempt: Revision::new(1),
            phase: NixBuildPhaseV1::Prepared,
            outputs: Vec::new(),
            terminal_receipt: None,
        }
    }

    /// Moves a prepared attempt into outcome-unknown recovery.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1::InvalidModel`] unless this is a
    /// prepared state.
    pub fn mark_indeterminate(mut self) -> Result<Self, EnvironmentExecutionErrorV1> {
        if self.phase != NixBuildPhaseV1::Prepared {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        self.phase = NixBuildPhaseV1::Indeterminate;
        Ok(self)
    }

    /// Resolves a prepared or indeterminate attempt from exact observation.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1::InvalidModel`] for a terminal
    /// state, mismatched request, sentinel receipt, unsorted outputs, or bounds.
    pub(super) fn resolve(
        mut self,
        observation: NixBuildObservationV1,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        if !matches!(
            self.phase,
            NixBuildPhaseV1::Prepared | NixBuildPhaseV1::Indeterminate
        ) || observation.request != self.request.commitment()
            || observation.receipt.as_bytes() == &[0; 32]
            || observation.outputs.len() > MAXIMUM_NIX_STORE_PRESENTATION_OBJECTS
            || !observation.outputs.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        self.phase = if observation.accepted {
            NixBuildPhaseV1::Completed
        } else {
            NixBuildPhaseV1::Rejected
        };
        self.outputs = observation.outputs;
        self.terminal_receipt = Some(observation.receipt);
        Ok(self)
    }

    /// Borrows the immutable request.
    #[must_use]
    pub const fn request(&self) -> &NixBuildRequestV1 {
        &self.request
    }

    /// Returns the exact protected presentation commitment.
    #[must_use]
    pub const fn presentation_commitment(&self) -> ObjectDigest {
        self.presentation
    }

    /// Returns the exact fixed capability-policy commitment.
    #[must_use]
    pub const fn policy_commitment(&self) -> ObjectDigest {
        self.policy
    }

    /// Returns the attempt revision.
    #[must_use]
    pub const fn attempt(&self) -> Revision {
        self.attempt
    }

    /// Returns the closed state phase.
    #[must_use]
    pub const fn phase(&self) -> NixBuildPhaseV1 {
        self.phase
    }

    /// Borrows exact terminal outputs, when present.
    #[must_use]
    pub fn outputs(&self) -> &[ObjectDescriptor] {
        &self.outputs
    }

    /// Returns the terminal observation receipt, when present.
    #[must_use]
    pub const fn terminal_receipt(&self) -> Option<ObjectDigest> {
        self.terminal_receipt
    }
}

/// Reports an exact build effect observation without granting retry authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NixBuildObservationV1 {
    request: ObjectDigest,
    accepted: bool,
    outputs: Vec<ObjectDescriptor>,
    receipt: ObjectDigest,
}

impl NixBuildObservationV1 {
    pub(super) fn from_protected(
        request: ObjectDigest,
        accepted: bool,
        outputs: Vec<ObjectDescriptor>,
        receipt: ObjectDigest,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        if request.as_bytes() == &[0; 32]
            || receipt.as_bytes() == &[0; 32]
            || (!accepted && !outputs.is_empty())
            || (accepted && outputs.is_empty())
            || outputs
                .iter()
                .any(|output| output.digest().as_bytes() == &[0; 32] || output.encoded_size() == 0)
        {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        Ok(Self {
            request,
            accepted,
            outputs,
            receipt,
        })
    }
}

/// Stores one canonical pre-effect or terminal build transaction member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NixBuildJournalRecordV1 {
    state: NixBuildStateV1,
    observation: Option<ObjectDigest>,
    outputs: ObjectDigest,
}

impl NixBuildJournalRecordV1 {
    pub(super) fn prepared(
        request: NixBuildRequestV1,
        presentation: ObjectDigest,
        policy: ObjectDigest,
    ) -> Self {
        Self {
            state: NixBuildStateV1::prepared(request, presentation, policy),
            observation: None,
            outputs: output_set_commitment(&[]),
        }
    }

    pub(super) fn terminal(
        prepared: &Self,
        observation: NixBuildObservationV1,
        observation_commitment: ObjectDigest,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        if prepared.observation.is_some() || prepared.state.phase() != NixBuildPhaseV1::Prepared {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        let outputs = output_set_commitment(&observation.outputs);
        Ok(Self {
            state: prepared.state.clone().resolve(observation)?,
            observation: Some(observation_commitment),
            outputs,
        })
    }

    pub(super) const fn state(&self) -> &NixBuildStateV1 {
        &self.state
    }

    pub(super) const fn observation(&self) -> Option<ObjectDigest> {
        self.observation
    }

    pub(super) const fn outputs_commitment(&self) -> ObjectDigest {
        self.outputs
    }
}

pub(crate) fn encode_nix_build_journal_record_v1(record: &NixBuildJournalRecordV1) -> Vec<u8> {
    let state = record.state();
    let selector = state.request().selector();
    let manifest = selector.manifest_record();
    let observation = record
        .observation()
        .unwrap_or(ObjectDigest::from_bytes([0; 32]));
    let outputs = record.outputs_commitment();
    let receipt = state
        .terminal_receipt()
        .unwrap_or(ObjectDigest::from_bytes([0; 32]));
    let mut body = Vec::with_capacity(304);
    body.extend_from_slice(b"AOSNXJ01");
    body.push(1);
    body.push(state.phase() as u8);
    body.extend_from_slice(&[0; 6]);
    body.extend_from_slice(manifest.project().as_bytes());
    body.extend_from_slice(manifest.sandbox().as_bytes());
    body.extend_from_slice(state.request().operation().as_bytes());
    body.extend_from_slice(&selector.generation().get().to_be_bytes());
    body.extend_from_slice(selector.manifest().digest().as_bytes());
    body.extend_from_slice(state.request().commitment().as_bytes());
    body.extend_from_slice(state.presentation_commitment().as_bytes());
    body.extend_from_slice(state.policy_commitment().as_bytes());
    body.extend_from_slice(&state.attempt().get().to_be_bytes());
    body.extend_from_slice(observation.as_bytes());
    body.extend_from_slice(outputs.as_bytes());
    body.extend_from_slice(receipt.as_bytes());
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.environment.nix-build-journal.v1\0")
        .chain_update(&body)
        .finalize();
    body.extend_from_slice(&digest);
    body
}

pub(crate) fn decode_nix_build_journal_record_v1(
    bytes: &[u8],
    selector: &EnvironmentSelectorV1,
) -> Result<NixBuildJournalRecordV1, EnvironmentExecutionErrorV1> {
    if bytes.len() != 336 {
        return Err(EnvironmentExecutionErrorV1::InvalidModel);
    }
    let (body, stored) = bytes.split_at(304);
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.environment.nix-build-journal.v1\0")
        .chain_update(body)
        .finalize();
    if stored != digest.as_slice()
        || &body[..8] != b"AOSNXJ01"
        || body[8] != 1
        || body[10..16] != [0; 6]
        || &body[16..32] != selector.manifest_record().project().as_bytes()
        || &body[32..48] != selector.manifest_record().sandbox().as_bytes()
        || u64::from_be_bytes(array_8(&body[64..72])?) != selector.generation().get()
        || &body[72..104] != selector.manifest().digest().as_bytes()
    {
        return Err(EnvironmentExecutionErrorV1::InvalidModel);
    }
    let operation = ResourceId::from_bytes(
        body[48..64]
            .try_into()
            .map_err(|_| EnvironmentExecutionErrorV1::InvalidModel)?,
    );
    let request = NixBuildRequestV1::new(operation, selector.clone())?;
    if &body[104..136] != request.commitment().as_bytes() {
        return Err(EnvironmentExecutionErrorV1::InvalidModel);
    }
    let mut state = NixBuildStateV1::prepared(
        request,
        ObjectDigest::from_bytes(array_32(&body[136..168])?),
        ObjectDigest::from_bytes(array_32(&body[168..200])?),
    );
    state.attempt = Revision::new(u64::from_be_bytes(array_8(&body[200..208])?));
    let observation = ObjectDigest::from_bytes(array_32(&body[208..240])?);
    let outputs = ObjectDigest::from_bytes(array_32(&body[240..272])?);
    let receipt = ObjectDigest::from_bytes(array_32(&body[272..304])?);
    if state.attempt().get() != 1
        || state.presentation_commitment().as_bytes() == &[0; 32]
        || state.policy_commitment().as_bytes() == &[0; 32]
    {
        return Err(EnvironmentExecutionErrorV1::InvalidModel);
    }
    match body[9] {
        1 if observation.as_bytes() == &[0; 32]
            && outputs == output_set_commitment(&[])
            && receipt.as_bytes() == &[0; 32] => {}
        3 | 4
            if observation.as_bytes() != &[0; 32]
                && receipt.as_bytes() != &[0; 32]
                && ((body[9] == 3 && outputs != output_set_commitment(&[]))
                    || (body[9] == 4 && outputs == output_set_commitment(&[]))) =>
        {
            state.phase = if body[9] == 3 {
                NixBuildPhaseV1::Completed
            } else {
                NixBuildPhaseV1::Rejected
            };
            state.terminal_receipt = Some(receipt);
            // Terminal journal replay proves the output-set commitment. Exact
            // descriptors remain in the protected observation owner.
        }
        _ => return Err(EnvironmentExecutionErrorV1::InvalidModel),
    }
    let record = NixBuildJournalRecordV1 {
        state,
        observation: (observation.as_bytes() != &[0; 32]).then_some(observation),
        outputs,
    };
    if encode_nix_build_journal_record_v1(&record) != bytes {
        return Err(EnvironmentExecutionErrorV1::InvalidModel);
    }
    Ok(record)
}

/// Carries lifetime-bound permission to hand one exact build to a future effect owner.
#[must_use]
pub struct NixBuildEffectHandoffV1<'current> {
    state: NixBuildStateV1,
    policy: NixBuildPolicyV1,
    authority_fence: NixBuildAuthorityFenceV1,
    client_boundary: super::NixClientBoundaryV1,
    presentation: ReadOnlyNixStorePresentationV1,
    journal_authority: ValidatedEnvironmentPostcommitV1<'current>,
}

impl<'current> NixBuildEffectHandoffV1<'current> {
    pub(super) fn new(
        state: NixBuildStateV1,
        policy: NixBuildPolicyV1,
        authority_fence: NixBuildAuthorityFenceV1,
        client_boundary: super::NixClientBoundaryV1,
        presentation: ReadOnlyNixStorePresentationV1,
        journal_authority: ValidatedEnvironmentPostcommitV1<'current>,
    ) -> Self {
        Self {
            state,
            policy,
            authority_fence,
            client_boundary,
            presentation,
            journal_authority,
        }
    }

    /// Borrows the exact pre-effect state.
    #[must_use]
    pub const fn state(&self) -> &NixBuildStateV1 {
        &self.state
    }

    /// Borrows the exact read-only input presentation.
    #[must_use]
    pub const fn presentation(&self) -> &ReadOnlyNixStorePresentationV1 {
        &self.presentation
    }

    /// Returns the fixed-owner build policy.
    #[must_use]
    pub const fn policy(&self) -> NixBuildPolicyV1 {
        self.policy
    }

    /// Returns the boot-scoped monotonic authority fence.
    #[must_use]
    pub const fn authority_fence(&self) -> NixBuildAuthorityFenceV1 {
        self.authority_fence
    }

    /// Returns the exact endpoint, trust domain, settings, and closed operation boundary.
    #[must_use]
    pub const fn client_boundary(&self) -> super::NixClientBoundaryV1 {
        self.client_boundary
    }

    /// Returns the exact committed pre-effect transaction commitment.
    #[must_use]
    pub const fn transaction_commitment(&self) -> ObjectDigest {
        self.journal_authority.transaction_digest()
    }

    /// Consumes the handoff into ambiguity-retaining recovery state.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1`] if the state is not prepared.
    pub fn into_indeterminate(self) -> Result<NixBuildStateV1, EnvironmentExecutionErrorV1> {
        self.state.mark_indeterminate()
    }
}

/// Distinguishes a durable build handoff from an ambiguous pre-effect commit.
#[must_use]
pub enum NixBuildPrepareOutcomeV1<'current> {
    /// Exact readback and current revalidation authorize the dormant effect.
    Prepared(NixBuildEffectHandoffV1<'current>),
    /// Durability is unknown and the exact recovery token is retained.
    OutcomeUnknown(EnvironmentJournalOutcomeUnknownV1),
}

/// Classifies exact protected recovery of a pre-effect build transaction.
#[must_use]
pub enum NixBuildPrepareRecoveryV1<'current> {
    /// Reopen proved the exact committed successor and reminted the handoff.
    Prepared(NixBuildEffectHandoffV1<'current>),
    /// Reopen proved the exact predecessor and retained the only safe retry.
    Retry(PreparedEnvironmentJournalTransactionV1),
    /// Reopen found mixed or substituted state and retained ambiguity.
    Diverged(EnvironmentJournalOutcomeUnknownV1),
}

/// Distinguishes exact terminal build publication from ambiguous durability.
#[must_use]
pub enum NixBuildSettlementOutcomeV1 {
    /// The protected terminal successor was read back exactly.
    Applied(NixBuildStateV1),
    /// Terminal durability is unknown and its exact token is retained.
    OutcomeUnknown(NixBuildSettlementUnknownV1),
}

/// Retains the exact terminal record and its ambiguity token as one unit.
#[must_use]
pub struct NixBuildSettlementUnknownV1 {
    terminal: NixBuildJournalRecordV1,
    pending: EnvironmentJournalOutcomeUnknownV1,
}

impl NixBuildSettlementUnknownV1 {
    pub(super) fn new(
        terminal: NixBuildJournalRecordV1,
        pending: EnvironmentJournalOutcomeUnknownV1,
    ) -> Self {
        Self { terminal, pending }
    }

    pub(super) fn into_parts(
        self,
    ) -> (NixBuildJournalRecordV1, EnvironmentJournalOutcomeUnknownV1) {
        (self.terminal, self.pending)
    }
}

/// Classifies exact protected recovery of a terminal build publication.
#[must_use]
pub enum NixBuildSettlementRecoveryV1 {
    /// Reopen proved the exact terminal successor.
    Applied(NixBuildStateV1),
    /// Reopen proved the predecessor and retained the sole retry plan.
    Retry(NixBuildSettlementRetryV1),
    /// Reopen found mixed or substituted state and retained ambiguity.
    Diverged(NixBuildSettlementUnknownV1),
}

/// Retains the exact terminal record and sole retry transaction as one unit.
#[must_use]
pub struct NixBuildSettlementRetryV1 {
    terminal: NixBuildJournalRecordV1,
    prepared: PreparedEnvironmentJournalTransactionV1,
}

impl NixBuildSettlementRetryV1 {
    pub(super) fn new(
        terminal: NixBuildJournalRecordV1,
        prepared: PreparedEnvironmentJournalTransactionV1,
    ) -> Self {
        Self { terminal, prepared }
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        NixBuildJournalRecordV1,
        PreparedEnvironmentJournalTransactionV1,
    ) {
        (self.terminal, self.prepared)
    }
}

/// Defines the future effect boundary for a constrained Nix build.
///
/// Implementations must not expose a trusted daemon socket. This trait is
/// deliberately not implemented or invoked by this source-only tranche.
pub trait DormantNixBuildEffectV1 {
    /// Effect-specific failure that does not classify durable outcome.
    type Error;

    /// Observes or applies one lifetime-bound exact build request.
    ///
    /// The outcome must preserve either the exact observation or an
    /// indeterminate state; it cannot classify an implementation error as a
    /// safe retry.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1`] if the one-shot handoff cannot
    /// be converted into ambiguity-retaining state.
    fn apply(
        &mut self,
        handoff: NixBuildEffectHandoffV1<'_>,
    ) -> Result<NixBuildEffectOutcomeV1<Self::Error>, EnvironmentExecutionErrorV1>;
}

/// Defines the dormant same-session consumer of protected execution admission.
///
/// The fixed environment owner invokes this boundary before releasing either
/// its journal borrow or the fixed presentation-owner borrow. No implementation
/// is installed by this source-only tranche.
pub trait DormantEnvironmentRuntimeAdmissionConsumerV1 {
    /// Consumer-specific success value.
    type Output;
    /// Consumer-specific failure that does not weaken protected admission.
    type Error;

    /// Consumes one lifetime-bound admission during the fixed-owner session.
    fn consume(
        &mut self,
        admission: EnvironmentExecutionAdmissionV1<'_>,
    ) -> Result<Self::Output, Self::Error>;
}

/// Retains an effect result without falsely reporting it after authority changed.
#[must_use]
pub enum EnvironmentRuntimeAdmissionOutcomeV1<O, E> {
    /// Both fixed owners remained current after the consumer returned.
    Completed(Result<O, E>),
    /// The consumer returned, but post-effect currentness could not be proved.
    OutcomeUnknown {
        /// The returned value is retained only as diagnostic evidence, not success.
        effect_result: Result<O, E>,
        /// Identifies the failed post-effect authority check.
        currentness_error: EnvironmentExecutionErrorV1,
    },
}

/// Retains either an exact build observation or outcome-unknown recovery.
#[must_use]
pub enum NixBuildEffectOutcomeV1<E> {
    /// The effect returned and now requires sealed protected observation.
    ObservationRequired {
        /// Indeterminate state retained for protected observation.
        state: NixBuildStateV1,
    },
    /// The effect outcome is unknown and the state cannot be treated as retryable.
    OutcomeUnknown {
        /// Indeterminate state retained for protected recovery.
        state: NixBuildStateV1,
        /// Effect-specific diagnostic.
        error: E,
    },
}

impl<E> NixBuildEffectOutcomeV1<E> {
    /// Requires fixed protected observation after an effect returned.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1`] unless the retained state was
    /// prepared and can move to indeterminate recovery.
    pub fn observation_required(
        handoff: NixBuildEffectHandoffV1<'_>,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        Ok(Self::ObservationRequired {
            state: handoff.state.mark_indeterminate()?,
        })
    }

    /// Constructs an ambiguous outcome by consuming the one-shot handoff.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1`] unless the retained state was
    /// prepared and can move to indeterminate recovery.
    pub fn outcome_unknown(
        handoff: NixBuildEffectHandoffV1<'_>,
        error: E,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        Ok(Self::OutcomeUnknown {
            state: handoff.state.mark_indeterminate()?,
            error,
        })
    }
}

/// Carries an exact execution draft validated against current protected environment state.
#[must_use]
pub struct EnvironmentExecutionAdmissionV1<'current> {
    draft: ExecutionAdmissionDraftV1,
    activation: EnvironmentActivationTransactionV1,
    presentation: ReadOnlyNixStorePresentationV1,
    _current: PhantomData<&'current mut ()>,
}

impl<'current> EnvironmentExecutionAdmissionV1<'current> {
    pub(super) fn new(
        draft: ExecutionAdmissionDraftV1,
        activation: EnvironmentActivationTransactionV1,
        presentation: ReadOnlyNixStorePresentationV1,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        let specification = decode_execution_spec_v1(
            draft.specification_bytes(),
            aos_sandbox_core::DecodeLimits::default(),
        )
        .map_err(|_| EnvironmentExecutionErrorV1::InvalidExecutionSpecification)?;
        let current = activation
            .current()
            .filter(|selector| activation.observed() == Some(*selector))
            .ok_or(EnvironmentExecutionErrorV1::CurrentEnvironmentMismatch)?;
        if activation.phase() != super::EnvironmentActivationPhaseV1::Observed
            && activation.phase() != super::EnvironmentActivationPhaseV1::Released
            || specification.target().sandbox() != activation.sandbox()
            || specification.environment_generation() != current.generation()
            || specification.environment_descriptor()
                != current.manifest_record().environment_descriptor()
            || specification.base_environment() != current.manifest_record().environment()
            || presentation.project() != activation.project()
            || presentation.sandbox() != activation.sandbox()
            || presentation.generation() != current.generation()
            || presentation.manifest() != current.manifest()
        {
            return Err(EnvironmentExecutionErrorV1::CurrentEnvironmentMismatch);
        }
        let execution = specification.execution();
        let has_lease = activation.leases().iter().any(|lease| {
            lease.consumer() == EnvironmentLeaseConsumerV1::Execution(execution)
                && lease.generation() == current.generation()
                && lease.status() == EnvironmentGenerationLeaseStatusV1::Active
        });
        let rooted = current.closure().iter().all(|descriptor| {
            activation.gc_roots().iter().any(|root| {
                root.generation() == current.generation() && root.descriptor() == descriptor
            })
        });
        if !has_lease || !rooted {
            return Err(EnvironmentExecutionErrorV1::RetentionEvidenceMissing);
        }
        Ok(Self {
            draft,
            activation,
            presentation,
            _current: PhantomData,
        })
    }

    /// Returns the exact execution identity.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.draft.execution()
    }

    /// Borrows the protected-current activation reproduced at admission.
    #[must_use]
    pub const fn activation(&self) -> &EnvironmentActivationTransactionV1 {
        &self.activation
    }

    /// Borrows the exact read-only store projection.
    #[must_use]
    pub const fn presentation(&self) -> &ReadOnlyNixStorePresentationV1 {
        &self.presentation
    }

    /// Releases the draft only to a crate-internal runtime owner integration.
    #[must_use]
    pub(crate) fn into_draft(self) -> ExecutionAdmissionDraftV1 {
        self.draft
    }
}

pub(super) fn selector_matches_presentation(
    selector: &EnvironmentSelectorV1,
    presentation: &ReadOnlyNixStorePresentationV1,
) -> bool {
    let manifest = selector.manifest_record();
    presentation.project() == manifest.project()
        && presentation.sandbox() == manifest.sandbox()
        && presentation.generation() == selector.generation()
        && presentation.manifest() == selector.manifest()
}

fn presentation_commitment(
    selector: &EnvironmentSelectorV1,
    kind: NixStorePresentationKindV1,
    entries: &[NixStorePresentationEntryV1],
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.environment.nix-store-presentation.v1\0")
        .chain_update(selector.manifest_record().project().as_bytes())
        .chain_update(selector.manifest_record().sandbox().as_bytes())
        .chain_update(selector.generation().get().to_be_bytes())
        .chain_update(selector.manifest().digest().as_bytes())
        .chain_update([kind as u8])
        .chain_update((entries.len() as u64).to_be_bytes());
    for entry in entries {
        hasher = hasher
            .chain_update((entry.object().media_type().as_str().len() as u64).to_be_bytes())
            .chain_update(entry.object().media_type().as_str().as_bytes())
            .chain_update(entry.object().digest().as_bytes())
            .chain_update(entry.object().encoded_size().to_be_bytes())
            .chain_update((entry.path().as_str().len() as u16).to_be_bytes())
            .chain_update(entry.path().as_str().as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn build_request_commitment(
    operation: ResourceId,
    selector: &EnvironmentSelectorV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.environment.nix-build-request.v1\0")
            .chain_update(operation.as_bytes())
            .chain_update(selector.manifest_record().project().as_bytes())
            .chain_update(selector.manifest_record().sandbox().as_bytes())
            .chain_update(selector.generation().get().to_be_bytes())
            .chain_update(selector.manifest().digest().as_bytes())
            .finalize()
            .into(),
    )
}

fn output_set_commitment(outputs: &[ObjectDescriptor]) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.environment.nix-build-outputs.v1\0")
        .chain_update((outputs.len() as u64).to_be_bytes());
    for output in outputs {
        hasher = hasher
            .chain_update((output.media_type().as_str().len() as u16).to_be_bytes())
            .chain_update(output.media_type().as_str().as_bytes())
            .chain_update(output.digest().as_bytes())
            .chain_update(output.encoded_size().to_be_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn array_8(bytes: &[u8]) -> Result<[u8; 8], EnvironmentExecutionErrorV1> {
    bytes
        .try_into()
        .map_err(|_| EnvironmentExecutionErrorV1::InvalidModel)
}

fn array_32(bytes: &[u8]) -> Result<[u8; 32], EnvironmentExecutionErrorV1> {
    bytes
        .try_into()
        .map_err(|_| EnvironmentExecutionErrorV1::InvalidModel)
}
