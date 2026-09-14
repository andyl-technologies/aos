//! Non-authorizing control envelopes for standard Git protocol v2.
//!
//! Upload reads only a named immutable export generation. Receive binds one
//! live incarnation, exact current and successor repository revisions, complete
//! pre/post ref maps and object databases, sealed quarantine, validation policy,
//! and one atomic compare-and-swap commitment.

use aos_sandbox_core::model::CacheDomainKind;
use aos_sandbox_core::{
    AssignmentEpoch, DesiredGeneration, IncarnationId, NamespaceGeneration, ObjectDigest,
    PrincipalId, ResourceId, Revision,
};
use sha2::{Digest as _, Sha256};

use super::model::{
    git_ref_map_digest_v1, GitAdvertisedRefV1, GitAncestryReportV1, GitAtomicCasDigestV1,
    GitChannelBindingDigestV1, GitDescriptorRoleV1, GitDescriptorV1, GitExportGenerationV1,
    GitGraphCompletenessV1, GitModelError, GitObjectDatabaseDigestV1, GitObjectFormatV1,
    GitObjectGraphEvidenceV1, GitObjectIdV1, GitQuarantineDigestV1, GitRefMapDigestV1,
    GitRefNameV1, GitRepositoryV1, GitValidationPolicyDigestV1, GitWholeObjectDatabaseV1,
};

/// Maximum ref compare-and-swap transitions in one receive.
pub const MAXIMUM_GIT_REF_TRANSITIONS: usize = 65_536;
/// Maximum capabilities in the closed protocol-v2 profile.
pub const MAXIMUM_GIT_PROTOCOL_V2_CAPABILITIES: usize = 11;
/// Maximum canonical bytes in one dormant Git control record.
pub const MAXIMUM_GIT_CONTROL_RECORD_BYTES: usize = 160 * 1024 * 1024;

/// Commits the exact closed protocol-v2 service and capability set.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitProtocolV2CapabilitiesDigestV1(ObjectDigest);

impl GitProtocolV2CapabilitiesDigestV1 {
    /// Returns the underlying SHA-256 commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }

    pub(super) fn from_stored(value: ObjectDigest) -> Result<Self, GitModelError> {
        if value.as_bytes() == &[0; 32] {
            Err(GitModelError::CorruptEncoding)
        } else {
            Ok(Self(value))
        }
    }
}

/// Selects the standard stateless Git service spoken by an exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GitProtocolV2ServiceV1 {
    /// Standard upload-pack service over an immutable export.
    UploadPack = 1,
    /// Standard receive-pack service into a sealed quarantine.
    ReceivePack = 2,
}

/// Selects one advertised capability from the closed Git protocol-v2 surface.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum GitProtocolV2CapabilityV1 {
    /// Server implementation identifier.
    Agent = 1,
    /// Explicit repository object format.
    ObjectFormat = 2,
    /// Authenticated transport session identity.
    SessionId = 3,
    /// Protocol-v2 ref discovery.
    LsRefs = 4,
    /// Protocol-v2 fetch command.
    Fetch = 5,
    /// Bounded server-option forwarding.
    ServerOption = 6,
    /// Version-two receive status report.
    ReportStatusV2 = 7,
    /// Ref deletion requests.
    DeleteRefs = 8,
    /// Atomic multi-ref update.
    Atomic = 9,
    /// Bounded push options.
    PushOptions = 10,
    /// Side-band multiplexing.
    SideBand64k = 11,
}

/// Binds a closed standard Git service to an exact capability advertisement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitProtocolV2ProfileV1 {
    service: GitProtocolV2ServiceV1,
    format: GitObjectFormatV1,
    capabilities: Vec<GitProtocolV2CapabilityV1>,
    digest: GitProtocolV2CapabilitiesDigestV1,
}

impl GitProtocolV2ProfileV1 {
    /// Constructs one canonical closed protocol-v2 profile.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for unordered, duplicate,
    /// excessive, service-inapplicable, or incomplete capabilities.
    pub fn new(
        service: GitProtocolV2ServiceV1,
        format: GitObjectFormatV1,
        capabilities: Vec<GitProtocolV2CapabilityV1>,
    ) -> Result<Self, GitModelError> {
        if capabilities.len() > MAXIMUM_GIT_PROTOCOL_V2_CAPABILITIES
            || !capabilities.windows(2).all(|pair| pair[0] < pair[1])
            || capabilities
                .iter()
                .any(|capability| !capability_is_valid_for(service, *capability))
            || !required_capabilities_are_present(service, &capabilities)
        {
            return Err(GitModelError::InvalidModel);
        }

        let count = u8::try_from(capabilities.len()).map_err(|_| GitModelError::InvalidModel)?;
        let mut hasher = Sha256::new()
            .chain_update(b"aos.sandbox.git.protocol-v2-capabilities.v1\0")
            .chain_update([service as u8, format as u8, count]);
        for capability in &capabilities {
            hasher = hasher.chain_update([*capability as u8]);
        }
        let digest =
            GitProtocolV2CapabilitiesDigestV1(ObjectDigest::from_bytes(hasher.finalize().into()));
        Ok(Self {
            service,
            format,
            capabilities,
            digest,
        })
    }

    /// Returns the exact standard Git service.
    #[must_use]
    pub const fn service(&self) -> GitProtocolV2ServiceV1 {
        self.service
    }

    /// Returns the repository object format.
    #[must_use]
    pub const fn format(&self) -> GitObjectFormatV1 {
        self.format
    }

    /// Borrows the canonical capability set.
    #[must_use]
    pub fn capabilities(&self) -> &[GitProtocolV2CapabilityV1] {
        &self.capabilities
    }

    /// Returns the exact service/capability commitment.
    #[must_use]
    pub const fn digest(&self) -> GitProtocolV2CapabilitiesDigestV1 {
        self.digest
    }
}

fn capability_is_valid_for(
    service: GitProtocolV2ServiceV1,
    capability: GitProtocolV2CapabilityV1,
) -> bool {
    match service {
        GitProtocolV2ServiceV1::UploadPack => matches!(
            capability,
            GitProtocolV2CapabilityV1::Agent
                | GitProtocolV2CapabilityV1::ObjectFormat
                | GitProtocolV2CapabilityV1::SessionId
                | GitProtocolV2CapabilityV1::LsRefs
                | GitProtocolV2CapabilityV1::Fetch
                | GitProtocolV2CapabilityV1::ServerOption
                | GitProtocolV2CapabilityV1::SideBand64k
        ),
        GitProtocolV2ServiceV1::ReceivePack => matches!(
            capability,
            GitProtocolV2CapabilityV1::Agent
                | GitProtocolV2CapabilityV1::ObjectFormat
                | GitProtocolV2CapabilityV1::SessionId
                | GitProtocolV2CapabilityV1::ReportStatusV2
                | GitProtocolV2CapabilityV1::DeleteRefs
                | GitProtocolV2CapabilityV1::Atomic
                | GitProtocolV2CapabilityV1::PushOptions
                | GitProtocolV2CapabilityV1::SideBand64k
        ),
    }
}

fn required_capabilities_are_present(
    service: GitProtocolV2ServiceV1,
    capabilities: &[GitProtocolV2CapabilityV1],
) -> bool {
    let contains = |capability| capabilities.binary_search(&capability).is_ok();
    contains(GitProtocolV2CapabilityV1::ObjectFormat)
        && match service {
            GitProtocolV2ServiceV1::UploadPack => {
                contains(GitProtocolV2CapabilityV1::LsRefs)
                    && contains(GitProtocolV2CapabilityV1::Fetch)
            }
            GitProtocolV2ServiceV1::ReceivePack => {
                contains(GitProtocolV2CapabilityV1::ReportStatusV2)
                    && contains(GitProtocolV2CapabilityV1::Atomic)
            }
        }
}

/// Fences receive-pack to one exact live runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitReceiveFenceV1 {
    desired_generation: DesiredGeneration,
    incarnation: IncarnationId,
    assignment_epoch: AssignmentEpoch,
    namespace_generation: NamespaceGeneration,
}

impl GitReceiveFenceV1 {
    /// Constructs an exact desired/incarnation/assignment/namespace fence.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for any zero or MAX counter or
    /// sentinel incarnation.
    pub fn new(
        desired_generation: DesiredGeneration,
        incarnation: IncarnationId,
        assignment_epoch: AssignmentEpoch,
        namespace_generation: NamespaceGeneration,
    ) -> Result<Self, GitModelError> {
        if desired_generation.get() == 0
            || desired_generation.get() == u64::MAX
            || incarnation.as_bytes() == &[0; 16]
            || assignment_epoch.get() == 0
            || assignment_epoch.get() == u64::MAX
            || namespace_generation.get() == 0
            || namespace_generation.get() == u64::MAX
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            desired_generation,
            incarnation,
            assignment_epoch,
            namespace_generation,
        })
    }
    /// Returns desired generation.
    #[must_use]
    pub const fn desired_generation(self) -> DesiredGeneration {
        self.desired_generation
    }
    /// Returns incarnation identity.
    #[must_use]
    pub const fn incarnation(self) -> IncarnationId {
        self.incarnation
    }
    /// Returns assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(self) -> AssignmentEpoch {
        self.assignment_epoch
    }
    /// Returns namespace generation.
    #[must_use]
    pub const fn namespace_generation(self) -> NamespaceGeneration {
        self.namespace_generation
    }
}

/// Describes one exact ref creation, update, or deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitRefTransitionV1 {
    name: GitRefNameV1,
    expected: Option<GitObjectIdV1>,
    proposed: Option<GitObjectIdV1>,
    ancestry: Option<GitAncestryReportV1>,
}

impl GitRefTransitionV1 {
    /// Constructs one non-no-op compare-and-swap transition.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError`] when both sides are absent, identical, or use
    /// different object formats.
    pub fn new(
        name: GitRefNameV1,
        expected: Option<GitObjectIdV1>,
        proposed: Option<GitObjectIdV1>,
        ancestry: Option<GitAncestryReportV1>,
    ) -> Result<Self, GitModelError> {
        let updates_existing_ref = expected.is_some() && proposed.is_some();
        if expected == proposed
            || expected
                .zip(proposed)
                .is_some_and(|(old, new)| old.format() != new.format())
            || updates_existing_ref != ancestry.is_some()
        {
            return Err(GitModelError::NoOpReceive);
        }
        Ok(Self {
            name,
            expected,
            proposed,
            ancestry,
        })
    }
    /// Borrows ref name.
    #[must_use]
    pub const fn name(&self) -> &GitRefNameV1 {
        &self.name
    }
    /// Returns expected old target, or absence for creation.
    #[must_use]
    pub const fn expected(&self) -> Option<GitObjectIdV1> {
        self.expected
    }
    /// Returns proposed target, or absence for deletion.
    #[must_use]
    pub const fn proposed(&self) -> Option<GitObjectIdV1> {
        self.proposed
    }

    /// Returns the required fast-forward ancestry proof for an update.
    #[must_use]
    pub const fn ancestry(&self) -> Option<&GitAncestryReportV1> {
        self.ancestry.as_ref()
    }
}

/// Selects one immutable-export upload-pack request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitUploadPlanV1 {
    exchange: ResourceId,
    export: GitExportGenerationV1,
    protocol: GitProtocolV2ProfileV1,
    principal: PrincipalId,
    channel_binding: GitChannelBindingDigestV1,
    expires_at_unix_seconds: u64,
    maximum_input_bytes: u64,
    maximum_output_bytes: u64,
}

impl GitUploadPlanV1 {
    /// Constructs an upload bound only to a complete immutable export.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError::InvalidModel`] for sentinel/MAX fields.
    pub fn new(
        exchange: ResourceId,
        export: GitExportGenerationV1,
        protocol: GitProtocolV2ProfileV1,
        principal: PrincipalId,
        channel_binding: GitChannelBindingDigestV1,
        expires_at_unix_seconds: u64,
        maximum_input_bytes: u64,
        maximum_output_bytes: u64,
    ) -> Result<Self, GitModelError> {
        if exchange.as_bytes() == &[0; 16]
            || principal.as_bytes() == &[0; 16]
            || expires_at_unix_seconds == 0
            || expires_at_unix_seconds == u64::MAX
            || maximum_input_bytes == 0
            || maximum_input_bytes == u64::MAX
            || maximum_output_bytes == 0
            || maximum_output_bytes == u64::MAX
            || protocol.service() != GitProtocolV2ServiceV1::UploadPack
            || protocol.format() != export.graph().format()
            || upload_control_size(&export)
                .is_none_or(|size| size > MAXIMUM_GIT_CONTROL_RECORD_BYTES)
        {
            return Err(GitModelError::InvalidModel);
        }
        Ok(Self {
            exchange,
            export,
            protocol,
            principal,
            channel_binding,
            expires_at_unix_seconds,
            maximum_input_bytes,
            maximum_output_bytes,
        })
    }
    /// Returns exchange identity.
    #[must_use]
    pub const fn exchange(&self) -> ResourceId {
        self.exchange
    }
    /// Borrows exact immutable export generation.
    #[must_use]
    pub const fn export(&self) -> &GitExportGenerationV1 {
        &self.export
    }
    /// Borrows the exact upload-pack protocol-v2 surface.
    #[must_use]
    pub const fn protocol(&self) -> &GitProtocolV2ProfileV1 {
        &self.protocol
    }
    /// Returns authenticated principal.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }
    /// Returns channel binding commitment.
    #[must_use]
    pub const fn channel_binding(&self) -> GitChannelBindingDigestV1 {
        self.channel_binding
    }
    /// Returns expiry.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
    /// Returns input byte ceiling.
    #[must_use]
    pub const fn maximum_input_bytes(&self) -> u64 {
        self.maximum_input_bytes
    }
    /// Returns output byte ceiling.
    #[must_use]
    pub const fn maximum_output_bytes(&self) -> u64 {
        self.maximum_output_bytes
    }
}

/// Selects one quarantined receive-pack atomic mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitReceivePlanV1 {
    exchange: ResourceId,
    repository: GitRepositoryV1,
    protocol: GitProtocolV2ProfileV1,
    successor_revision: Revision,
    principal: PrincipalId,
    channel_binding: GitChannelBindingDigestV1,
    fence: GitReceiveFenceV1,
    expires_at_unix_seconds: u64,
    maximum_input_bytes: u64,
    maximum_output_bytes: u64,
    current_refs: Vec<GitAdvertisedRefV1>,
    successor_refs: Vec<GitAdvertisedRefV1>,
    transitions: Vec<GitRefTransitionV1>,
    pre_ref_map: GitRefMapDigestV1,
    post_ref_map: GitRefMapDigestV1,
    pre_database: GitWholeObjectDatabaseV1,
    post_database: GitWholeObjectDatabaseV1,
    quarantine: GitDescriptorV1,
    quarantine_digest: GitQuarantineDigestV1,
    validation_policy: GitValidationPolicyDigestV1,
    atomic_cas: GitAtomicCasDigestV1,
}

impl GitReceivePlanV1 {
    /// Constructs a complete checked current-to-successor repository mutation.
    ///
    /// Current refs and transitions must be strictly ordered. Every expected
    /// target must match the current map. The derived successor map, ref/ODB
    /// commitments, quarantine evidence, and atomic CAS are retained exactly.
    ///
    /// # Errors
    ///
    /// Returns [`GitModelError`] for conflicts, no-op/MAX revisions, excessive
    /// counts, format mismatch, incomplete quarantine, or descriptor mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        exchange: ResourceId,
        repository: GitRepositoryV1,
        protocol: GitProtocolV2ProfileV1,
        principal: PrincipalId,
        channel_binding: GitChannelBindingDigestV1,
        fence: GitReceiveFenceV1,
        expires_at_unix_seconds: u64,
        maximum_input_bytes: u64,
        maximum_output_bytes: u64,
        current_refs: Vec<GitAdvertisedRefV1>,
        transitions: Vec<GitRefTransitionV1>,
        pre_database: GitWholeObjectDatabaseV1,
        post_database: GitWholeObjectDatabaseV1,
        quarantine: GitDescriptorV1,
        validation_policy: GitValidationPolicyDigestV1,
    ) -> Result<Self, GitModelError> {
        if exchange.as_bytes() == &[0; 16]
            || principal.as_bytes() == &[0; 16]
            || expires_at_unix_seconds == 0
            || expires_at_unix_seconds == u64::MAX
            || maximum_input_bytes == 0
            || maximum_input_bytes == u64::MAX
            || maximum_output_bytes == 0
            || maximum_output_bytes == u64::MAX
            || transitions.is_empty()
            || transitions.len() > MAXIMUM_GIT_REF_TRANSITIONS
            || quarantine.role() != GitDescriptorRoleV1::ReceiveQuarantine
            || post_database.graph().completeness()
                != GitGraphCompletenessV1::ValidatedQuarantineClosure
            || post_database.graph().format() != repository.format()
            || pre_database.graph().format() != repository.format()
            || post_database.validator().policy() != validation_policy
            || pre_database.audience() != post_database.audience()
            || !audience_matches_repository(pre_database.audience(), &repository)
            || !audience_matches_repository(post_database.audience(), &repository)
            || transitions.iter().any(|transition| {
                transition
                    .expected()
                    .zip(transition.proposed())
                    .is_some_and(|(old, new)| {
                        transition.ancestry().is_none_or(|report| {
                            report.trust() != post_database.validator().trust()
                                || report.reference() != transition.name()
                                || report.old() != old
                                || report.new() != new
                                || report.object_database()
                                    != post_database.graph().object_database()
                        })
                    })
            })
            || (transitions
                .iter()
                .any(|transition| transition.proposed().is_none())
                && protocol
                    .capabilities()
                    .binary_search(&GitProtocolV2CapabilityV1::DeleteRefs)
                    .is_err())
            || protocol.service() != GitProtocolV2ServiceV1::ReceivePack
            || protocol.format() != repository.format()
            || receive_control_size(&current_refs, &transitions, &pre_database, &post_database)
                .is_none_or(|size| size > MAXIMUM_GIT_CONTROL_RECORD_BYTES)
        {
            return Err(GitModelError::InvalidModel);
        }
        let successor_revision = repository
            .revision()
            .checked_next()
            .map_err(|_| GitModelError::InvalidModel)?;
        if successor_revision.get() == u64::MAX
            || !transitions
                .windows(2)
                .all(|pair| pair[0].name() < pair[1].name())
        {
            return Err(GitModelError::InvalidModel);
        }
        let pre_ref_map = git_ref_map_digest_v1(repository.format(), &current_refs)?;
        let successor_refs = apply_transitions(repository.format(), &current_refs, &transitions)?;
        let post_ref_map = git_ref_map_digest_v1(repository.format(), &successor_refs)?;
        if !successor_refs.iter().all(|entry| {
            post_database
                .graph()
                .roots()
                .binary_search(&entry.object())
                .is_ok()
        }) {
            return Err(GitModelError::InvalidObjectGraph);
        }
        if pre_ref_map == post_ref_map
            && pre_database.graph().object_database() == post_database.graph().object_database()
        {
            return Err(GitModelError::NoOpReceive);
        }
        let quarantine_digest = quarantine_digest(&quarantine, &post_database, validation_policy);
        let atomic_cas = atomic_cas_digest(
            &repository,
            fence,
            successor_revision,
            pre_ref_map,
            post_ref_map,
            pre_database.graph().object_database(),
            post_database.graph().object_database(),
            pre_database.audience_commitment(),
            post_database.audience_commitment(),
            quarantine_digest,
            validation_policy,
        );
        Ok(Self {
            exchange,
            repository,
            protocol,
            successor_revision,
            principal,
            channel_binding,
            fence,
            expires_at_unix_seconds,
            maximum_input_bytes,
            maximum_output_bytes,
            current_refs,
            successor_refs,
            transitions,
            pre_ref_map,
            post_ref_map,
            pre_database,
            post_database,
            quarantine,
            quarantine_digest,
            validation_policy,
            atomic_cas,
        })
    }
    /// Returns exchange identity.
    #[must_use]
    pub const fn exchange(&self) -> ResourceId {
        self.exchange
    }
    /// Borrows current repository identity and revision.
    #[must_use]
    pub const fn repository(&self) -> &GitRepositoryV1 {
        &self.repository
    }
    /// Borrows the exact receive-pack protocol-v2 surface.
    #[must_use]
    pub const fn protocol(&self) -> &GitProtocolV2ProfileV1 {
        &self.protocol
    }
    /// Returns checked successor revision.
    #[must_use]
    pub const fn successor_revision(&self) -> Revision {
        self.successor_revision
    }
    /// Returns principal.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }
    /// Returns channel binding.
    #[must_use]
    pub const fn channel_binding(&self) -> GitChannelBindingDigestV1 {
        self.channel_binding
    }
    /// Returns live runtime fence.
    #[must_use]
    pub const fn fence(&self) -> GitReceiveFenceV1 {
        self.fence
    }
    /// Returns expiry.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
    /// Returns input ceiling.
    #[must_use]
    pub const fn maximum_input_bytes(&self) -> u64 {
        self.maximum_input_bytes
    }
    /// Returns output ceiling.
    #[must_use]
    pub const fn maximum_output_bytes(&self) -> u64 {
        self.maximum_output_bytes
    }
    /// Returns exact current ref map.
    #[must_use]
    pub fn current_refs(&self) -> &[GitAdvertisedRefV1] {
        &self.current_refs
    }
    /// Returns derived successor ref map.
    #[must_use]
    pub fn successor_refs(&self) -> &[GitAdvertisedRefV1] {
        &self.successor_refs
    }
    /// Returns exact ordered CAS transitions.
    #[must_use]
    pub fn transitions(&self) -> &[GitRefTransitionV1] {
        &self.transitions
    }
    /// Returns pre-ref commitment.
    #[must_use]
    pub const fn pre_ref_map(&self) -> GitRefMapDigestV1 {
        self.pre_ref_map
    }
    /// Returns post-ref commitment.
    #[must_use]
    pub const fn post_ref_map(&self) -> GitRefMapDigestV1 {
        self.post_ref_map
    }
    /// Returns pre-ODB commitment.
    #[must_use]
    pub const fn pre_object_database(&self) -> GitObjectDatabaseDigestV1 {
        self.pre_database.graph().object_database()
    }

    /// Borrows complete pre-receive logical, physical, validation, and audience evidence.
    #[must_use]
    pub const fn pre_database(&self) -> &GitWholeObjectDatabaseV1 {
        &self.pre_database
    }
    /// Returns the checked post-ODB commitment.
    #[must_use]
    pub const fn post_object_database(&self) -> GitObjectDatabaseDigestV1 {
        self.post_database.graph().object_database()
    }
    /// Borrows validated post-ODB graph.
    #[must_use]
    pub const fn post_graph(&self) -> &GitObjectGraphEvidenceV1 {
        self.post_database.graph()
    }
    /// Borrows complete post-receive logical, physical, and audience evidence.
    #[must_use]
    pub const fn post_database(&self) -> &GitWholeObjectDatabaseV1 {
        &self.post_database
    }
    /// Borrows sealed quarantine descriptor.
    #[must_use]
    pub const fn quarantine(&self) -> &GitDescriptorV1 {
        &self.quarantine
    }
    /// Returns quarantine commitment.
    #[must_use]
    pub const fn quarantine_digest(&self) -> GitQuarantineDigestV1 {
        self.quarantine_digest
    }
    /// Returns validation-policy commitment.
    #[must_use]
    pub const fn validation_policy(&self) -> GitValidationPolicyDigestV1 {
        self.validation_policy
    }
    /// Returns exact atomic CAS commitment.
    #[must_use]
    pub const fn atomic_cas(&self) -> GitAtomicCasDigestV1 {
        self.atomic_cas
    }
}

fn audience_matches_repository(
    audience: &super::GitReadAudienceV1,
    repository: &GitRepositoryV1,
) -> bool {
    match audience.disclosure().kind() {
        CacheDomainKind::Private => {
            audience.disclosure().domain_id().as_bytes() == repository.sandbox().as_bytes()
        }
        CacheDomainKind::Project => {
            audience.disclosure().domain_id().as_bytes() == repository.project().as_bytes()
        }
        CacheDomainKind::TrustDomain | CacheDomainKind::Public => false,
    }
}

fn upload_control_size(export: &GitExportGenerationV1) -> Option<usize> {
    let refs = encoded_ref_bytes(export.refs())?;
    4_096_usize
        .checked_add(refs)?
        .checked_add(export.graph().roots().len().checked_mul(32)?)
        .and_then(|value| {
            value.checked_add(
                export
                    .bare_export()
                    .descriptor()
                    .media_type()
                    .as_str()
                    .len(),
            )
        })
        .and_then(|value| {
            value.checked_add(
                export
                    .database()
                    .validator()
                    .report()
                    .descriptor()
                    .media_type()
                    .as_str()
                    .len(),
            )
        })
}

fn receive_control_size(
    refs: &[GitAdvertisedRefV1],
    transitions: &[GitRefTransitionV1],
    pre_database: &GitWholeObjectDatabaseV1,
    post_database: &GitWholeObjectDatabaseV1,
) -> Option<usize> {
    let refs = encoded_ref_bytes(refs)?;
    let transitions = transitions.iter().try_fold(0_usize, |total, transition| {
        total
            .checked_add(172)?
            .checked_add(transition.name().as_bytes().len())
    })?;
    4_096_usize
        .checked_add(refs)?
        .checked_add(transitions)?
        .checked_add(pre_database.graph().roots().len().checked_mul(32)?)
        .checked_add(post_database.graph().roots().len().checked_mul(32)?)
        .and_then(|value| {
            value.checked_add(
                pre_database
                    .validator()
                    .report()
                    .descriptor()
                    .media_type()
                    .as_str()
                    .len(),
            )
        })
        .and_then(|value| {
            value.checked_add(
                post_database
                    .validator()
                    .report()
                    .descriptor()
                    .media_type()
                    .as_str()
                    .len(),
            )
        })
}

fn encoded_ref_bytes(refs: &[GitAdvertisedRefV1]) -> Option<usize> {
    refs.iter().try_fold(4_usize, |total, entry| {
        total
            .checked_add(34)?
            .checked_add(entry.name().as_bytes().len())
    })
}

/// Selects exactly one standard Git protocol-v2 service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitExchangePlanV1 {
    /// Immutable upload-pack read.
    Upload(GitUploadPlanV1),
    /// Quarantined receive-pack mutation.
    Receive(GitReceivePlanV1),
}

fn quarantine_digest(
    quarantine: &GitDescriptorV1,
    post_database: &GitWholeObjectDatabaseV1,
    validation: GitValidationPolicyDigestV1,
) -> GitQuarantineDigestV1 {
    let post_graph = post_database.graph();
    let media = quarantine.descriptor().media_type().as_str().as_bytes();
    let media_length = media.len().to_be_bytes();
    let mut bytes = [0_u8; 522];
    bytes[0] = quarantine.role() as u8;
    bytes[1..3].copy_from_slice(&media_length[media_length.len() - 2..]);
    let mut offset = 3;
    bytes[offset..offset + media.len()].copy_from_slice(media);
    offset += media.len();
    bytes[offset..offset + 32].copy_from_slice(quarantine.descriptor().digest().as_bytes());
    offset += 32;
    bytes[offset..offset + 8]
        .copy_from_slice(&quarantine.descriptor().encoded_size().to_be_bytes());
    offset += 8;
    bytes[offset..offset + 32].copy_from_slice(post_graph.object_database().digest().as_bytes());
    offset += 32;
    bytes[offset..offset + 32].copy_from_slice(post_graph.graph_proof().digest().as_bytes());
    offset += 32;
    bytes[offset..offset + 8]
        .copy_from_slice(&post_database.physical().loose_object_count().to_be_bytes());
    offset += 8;
    bytes[offset..offset + 8].copy_from_slice(&post_database.physical().pack_count().to_be_bytes());
    offset += 8;
    bytes[offset..offset + 32]
        .copy_from_slice(post_database.physical().pack_indexes().digest().as_bytes());
    offset += 32;
    bytes[offset..offset + 32]
        .copy_from_slice(post_database.physical().inventory().digest().as_bytes());
    offset += 32;
    bytes[offset..offset + 32]
        .copy_from_slice(post_database.audience_commitment().digest().as_bytes());
    offset += 32;
    bytes[offset..offset + 32].copy_from_slice(
        post_database
            .validator()
            .report()
            .descriptor()
            .digest()
            .as_bytes(),
    );
    offset += 32;
    bytes[offset..offset + 8].copy_from_slice(
        &post_database
            .validator()
            .report()
            .descriptor()
            .encoded_size()
            .to_be_bytes(),
    );
    offset += 8;
    bytes[offset..offset + 32].copy_from_slice(validation.digest().as_bytes());
    offset += 32;
    bytes[offset..offset + 32]
        .copy_from_slice(post_database.validator().trust().digest().as_bytes());
    offset += 32;
    GitQuarantineDigestV1::commit(&bytes[..offset])
}

fn apply_transitions(
    format: GitObjectFormatV1,
    current: &[GitAdvertisedRefV1],
    transitions: &[GitRefTransitionV1],
) -> Result<Vec<GitAdvertisedRefV1>, GitModelError> {
    let creations = transitions
        .iter()
        .filter(|transition| transition.expected().is_none() && transition.proposed().is_some())
        .count();
    let capacity = current
        .len()
        .checked_add(creations)
        .ok_or(GitModelError::InvalidModel)?;
    let mut successor = Vec::new();
    successor
        .try_reserve_exact(capacity)
        .map_err(|_| GitModelError::Allocation)?;
    let mut current_index = 0;
    let mut transition_index = 0;
    while current_index < current.len() || transition_index < transitions.len() {
        match (
            current.get(current_index),
            transitions.get(transition_index),
        ) {
            (Some(existing), Some(transition)) if existing.name() < transition.name() => {
                successor.push(existing.clone());
                current_index += 1;
            }
            (Some(existing), Some(transition)) if existing.name() == transition.name() => {
                if transition.expected() != Some(existing.object()) {
                    return Err(GitModelError::InvalidModel);
                }
                if let Some(proposed) = transition.proposed() {
                    if proposed.format() != format {
                        return Err(GitModelError::InvalidModel);
                    }
                    successor.push(GitAdvertisedRefV1::new(transition.name().clone(), proposed));
                }
                current_index += 1;
                transition_index += 1;
            }
            (_, Some(transition)) => {
                let Some(proposed) = transition.proposed() else {
                    return Err(GitModelError::InvalidModel);
                };
                if transition.expected().is_some() || proposed.format() != format {
                    return Err(GitModelError::InvalidModel);
                }
                successor.push(GitAdvertisedRefV1::new(transition.name().clone(), proposed));
                transition_index += 1;
            }
            (Some(existing), None) => {
                successor.push(existing.clone());
                current_index += 1;
            }
            (None, None) => break,
        }
    }
    Ok(successor)
}

fn atomic_cas_digest(
    repository: &GitRepositoryV1,
    fence: GitReceiveFenceV1,
    successor: Revision,
    pre_refs: GitRefMapDigestV1,
    post_refs: GitRefMapDigestV1,
    pre_odb: GitObjectDatabaseDigestV1,
    post_odb: GitObjectDatabaseDigestV1,
    pre_audience: super::GitAudienceDigestV1,
    post_audience: super::GitAudienceDigestV1,
    quarantine: GitQuarantineDigestV1,
    validation: GitValidationPolicyDigestV1,
) -> GitAtomicCasDigestV1 {
    let mut bytes = [0_u8; 377];
    let mut offset = 0;
    for value in [
        repository.repository().as_bytes(),
        repository.project().as_bytes(),
        repository.sandbox().as_bytes(),
        repository.workspace().as_bytes(),
    ] {
        bytes[offset..offset + 16].copy_from_slice(value);
        offset += 16;
    }
    bytes[offset] = repository.format() as u8;
    offset += 1;
    for value in [
        repository.revision().get(),
        successor.get(),
        fence.desired_generation().get(),
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        offset += 8;
    }
    bytes[offset..offset + 16].copy_from_slice(fence.incarnation().as_bytes());
    offset += 16;
    for value in [
        fence.assignment_epoch().get(),
        fence.namespace_generation().get(),
    ] {
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        offset += 8;
    }
    for value in [
        pre_refs.digest(),
        post_refs.digest(),
        pre_odb.digest(),
        post_odb.digest(),
        pre_audience.digest(),
        post_audience.digest(),
        quarantine.digest(),
        validation.digest(),
    ] {
        bytes[offset..offset + 32].copy_from_slice(value.as_bytes());
        offset += 32;
    }
    debug_assert_eq!(offset, bytes.len());
    GitAtomicCasDigestV1::commit(&bytes)
}
