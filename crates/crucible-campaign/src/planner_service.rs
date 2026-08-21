//! Pure planner component request, service, and checked-client contracts.
//!
//! The component request carries the exact immutable invocation basis by value
//! plus a bounded, content-addressed interpretation bundle. The pure engine
//! receives no store, clock, executor, campaign-ref, or host-placement
//! capability. Its output is authenticated by a supervised adapter before the
//! coordinator independently validates and admits it.

use std::collections::{BTreeMap, BTreeSet};

use crucible_cas::content_store::ContentId;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::{
    BranchRequest, CampaignCodecError, CampaignHash, CampaignPlanningView, CampaignPolicy,
    CampaignSnapshotId, ContinuationProjection, ContinuationState, ObjectEnvelope,
    PlannerAuthorityKey, PlannerEngine, PlannerInvocation, PlannerProposalDisposition,
    PlannerState, PlannerStepProposal, PlannerSubmission, PlanningScanPosition, PlanningUsage,
    PolicyArtifact, Proposal, RetainedPlannerRequestId,
};

mod closed;
pub use closed::*;

const PLANNER_REQUEST_SCHEMA_VERSION: u32 = 1;
const PLANNER_RESPONSE_SCHEMA_VERSION: u32 = 1;
/// Maximum canonical request or response size at the planner wire boundary.
pub const MAX_PLANNER_COMPONENT_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum canonical request body retained by the initial coordinator store.
///
/// This narrower admission bound leaves deterministic room for content-envelope
/// framing without changing the version-1 component wire contract.
pub const MAX_RETAINED_PLANNER_REQUEST_BYTES: usize = 32 * 1024 * 1024;
const MAX_PLANNING_BUNDLE_OBJECTS: usize = 65_536;
const RETAINED_PLANNER_REQUEST_FIXED_CHILDREN: usize = 7;
/// Planner-engine capability for exact continuation and candidate offers.
pub const CANONICAL_FRONTIER_OFFERS_CAPABILITY: &str = "canonical-frontier-offers-v1";
/// Maximum bundle-object count accepted by the initial coordinator store.
pub const MAX_RETAINED_PLANNER_REQUEST_BUNDLE_OBJECTS: usize =
    MAX_PLANNING_BUNDLE_OBJECTS - RETAINED_PLANNER_REQUEST_FIXED_CHILDREN;
const _: () = assert!(MAX_RETAINED_PLANNER_REQUEST_BYTES < MAX_PLANNER_COMPONENT_MESSAGE_BYTES);

/// Bounded content-addressed interpretation objects supplied to a pure planner.
///
/// A canonical-frontier engine receives each served branch request, its exact
/// continuation projection, and one invocation-bound proposal offer for the
/// least Ready position on that page. Other engine capabilities may define
/// additional reachable interpretation records without changing this envelope
/// container's version-1 grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignPlanningBundle {
    objects: BTreeMap<ContentId, Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlannerCandidateInput {
    pub(crate) continuation: ContinuationProjection,
    pub(crate) offer: Option<Proposal>,
}

impl CampaignPlanningBundle {
    /// Builds a canonical bundle from strict campaign object envelopes.
    ///
    /// Objects are ordered by content identity on the wire. Duplicate
    /// identities and an oversized aggregate fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the bundle contains more than
    /// 65,536 objects, repeats an identity, or exceeds the 64-MiB component
    /// message bound.
    pub fn new(objects: Vec<ObjectEnvelope>) -> Result<Self, CampaignCodecError> {
        if objects.len() > MAX_PLANNING_BUNDLE_OBJECTS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "planner-input-bundle-object-count",
            });
        }

        let mut canonical = BTreeMap::new();
        let mut retained_bytes = 0_usize;
        for object in objects {
            insert_planning_bundle_object(
                &mut canonical,
                &mut retained_bytes,
                object,
                MAX_PLANNER_COMPONENT_MESSAGE_BYTES,
            )?;
        }
        let bundle = Self { objects: canonical };
        codec::ensure_encoded_size(
            &bundle,
            MAX_PLANNER_COMPONENT_MESSAGE_BYTES,
            "planner-input-bundle-encoded-bytes",
        )?;
        Ok(bundle)
    }

    /// Returns the number of immutable objects in the bundle.
    #[must_use]
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Returns whether the bundle contains no interpretation objects.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Returns object identities in canonical order.
    pub fn object_ids(&self) -> impl Iterator<Item = ContentId> + '_ {
        self.objects.keys().copied()
    }

    /// Loads one strict record-specific envelope by content identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if retained bytes no longer decode to the
    /// requested identity. Values built or decoded through this type satisfy
    /// the invariant, so an error indicates an internal contract violation.
    pub fn object(&self, id: ContentId) -> Result<Option<ObjectEnvelope>, CampaignCodecError> {
        self.objects
            .get(&id)
            .map(|bytes| {
                let object = ObjectEnvelope::from_canonical_bytes(bytes)?;
                if object.content_id() != id {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "planner input bundle object identity mismatch",
                    });
                }
                Ok(object)
            })
            .transpose()
    }

    pub(crate) fn candidate_inputs(
        &self,
        request: &PlannerRequest,
    ) -> Result<BTreeMap<PlanningScanPosition, PlannerCandidateInput>, CampaignCodecError> {
        if !request
            .engine
            .capabilities()
            .contains(CANONICAL_FRONTIER_OFFERS_CAPABILITY)
        {
            return Ok(BTreeMap::new());
        }

        let invocation = request.invocation_id()?;
        let mut continuations = BTreeMap::new();
        let mut offers = BTreeMap::new();
        for id in self.object_ids() {
            let object = self.object(id)?.ok_or(CampaignCodecError::InvalidValue {
                reason: "planner input bundle object disappeared during validation",
            })?;
            match object.record_kind() {
                crate::CampaignRecordKind::ContinuationProjection => {
                    let projection = ContinuationProjection::from_canonical_bytes(object.body())?;
                    let position =
                        PlanningScanPosition::new(projection.branch_point(), projection.request());
                    if continuations.insert(position, projection).is_some() {
                        return Err(CampaignCodecError::InvalidValue {
                            reason: "planner input bundle repeats a continuation projection",
                        });
                    }
                }
                crate::CampaignRecordKind::Proposal => {
                    let proposal = Proposal::from_canonical_bytes(object.body())?;
                    if proposal.planner_invocation() != Some(invocation) {
                        return Err(CampaignCodecError::InvalidValue {
                            reason: "planner candidate offer names another invocation",
                        });
                    }
                    let position =
                        PlanningScanPosition::new(proposal.branch_point(), proposal.request());
                    if offers.insert(position, proposal).is_some() {
                        return Err(CampaignCodecError::InvalidValue {
                            reason: "planner input bundle repeats a candidate offer",
                        });
                    }
                }
                _ => {}
            }
        }

        let expected_offer = continuations.iter().find_map(|(position, projection)| {
            (projection.state() == ContinuationState::Ready).then_some(*position)
        });
        if offers.len() != usize::from(expected_offer.is_some())
            || offers.keys().next().copied() != expected_offer
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner candidate offer is not the least Ready continuation",
            });
        }

        let mut inputs = BTreeMap::new();
        for position in request.invocation.scan_page().positions() {
            let continuation =
                continuations
                    .remove(position)
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "planner input bundle omits a continuation projection",
                    })?;
            let offer = offers.remove(position);
            if let Some(offer) = &offer {
                let source = self.object(position.source().content_id())?.ok_or(
                    CampaignCodecError::InvalidValue {
                        reason: "planner candidate offer omits its branch request",
                    },
                )?;
                let branch_request = BranchRequest::from_canonical_bytes(source.body())?;
                if offer.domain() != branch_request.domain()
                    || offer.policy() != request.invocation.policy()
                    || offer.guidance_basis() != request.invocation.input_view()
                    || offer.ordinal() > branch_request.budget().maximum_proposals()
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "planner candidate offer disagrees with its invocation basis",
                    });
                }
            }
            inputs.insert(
                *position,
                PlannerCandidateInput {
                    continuation,
                    offer,
                },
            );
        }
        if !continuations.is_empty() || !offers.is_empty() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner input bundle contains an unserved candidate projection",
            });
        }
        Ok(inputs)
    }

    fn validate_for(&self, request: &PlannerRequest) -> Result<(), CampaignCodecError> {
        let invocation = &request.invocation;
        let page = invocation.scan_page();
        let budget = invocation.budget();
        if page.input_objects() > u64::from(budget.input_objects())
            || page.input_bytes() > budget.input_bytes()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner scan page exceeds the invocation input budget",
            });
        }

        let direct_objects = [
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PlannerEngine,
                BTreeSet::new(),
                codec::encode(&request.engine),
            )?,
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PolicyArtifact,
                crate::object::content_children(request.policy_artifact.content_children())?,
                codec::encode(&request.policy_artifact),
            )?,
            ObjectEnvelope::for_policy(&request.policy)?,
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PlannerState,
                crate::object::content_children([(
                    "engine",
                    request.planner_state.engine().content_id(),
                )])?,
                codec::encode(&request.planner_state),
            )?,
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PlanningView,
                crate::object::content_children(request.input_view.content_children())?,
                codec::encode(&request.input_view),
            )?,
        ];
        let direct_ids = direct_objects
            .iter()
            .map(ObjectEnvelope::content_id)
            .collect::<BTreeSet<_>>();
        if direct_ids
            .iter()
            .any(|content| self.objects.contains_key(content))
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner input bundle duplicates a by-value basis object",
            });
        }
        let candidate_inputs = self.candidate_inputs(request)?;
        let mut pending = direct_objects
            .iter()
            .flat_map(|object| object.children())
            .map(|child| child.id())
            .filter(|child| self.objects.contains_key(child))
            .collect::<Vec<_>>();
        pending.reserve(page.positions().len());
        let mut request_bytes = 0_u64;
        for position in page.positions() {
            let content = position.source().content_id();
            let object = self
                .object(content)?
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "planner input bundle omits a served branch request",
                })?;
            if object.record_kind() != crate::CampaignRecordKind::BranchRequest {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "planner scan position does not name a branch request",
                });
            }
            let branch_request = BranchRequest::from_canonical_bytes(object.body())?;
            if branch_request.branch_point() != position.branch_point()
                || branch_request.id()? != position.source()
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "planner scan position disagrees with its branch request",
                });
            }
            request_bytes = request_bytes
                .checked_add(u64::try_from(object.body().len()).map_err(|_| {
                    CampaignCodecError::LimitExceeded {
                        limit: "planner-scan-input-byte-count",
                    }
                })?)
                .ok_or(CampaignCodecError::LimitExceeded {
                    limit: "planner-scan-input-byte-count",
                })?;
            pending.push(content);
            if let Some(input) = candidate_inputs.get(position) {
                pending.push(input.continuation.id()?.content_id());
                if let Some(offer) = &input.offer {
                    pending.push(offer.id()?.content_id());
                }
            }
        }
        if request_bytes != page.input_bytes() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner scan page input bytes disagree with served requests",
            });
        }

        let mut reachable = BTreeSet::new();
        while let Some(content) = pending.pop() {
            if !reachable.insert(content) {
                continue;
            }
            let object = self
                .object(content)?
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "planner input bundle reachability changed during validation",
                })?;
            pending.extend(
                object
                    .children()
                    .iter()
                    .map(|child| child.id())
                    .filter(|child| self.objects.contains_key(child)),
            );
        }
        if reachable.len() != self.objects.len() {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner input bundle contains an unrelated object",
            });
        }
        Ok(())
    }
}

fn insert_planning_bundle_object(
    objects: &mut BTreeMap<ContentId, Vec<u8>>,
    retained_bytes: &mut usize,
    object: ObjectEnvelope,
    byte_limit: usize,
) -> Result<(), CampaignCodecError> {
    let id = object.content_id();
    if objects.contains_key(&id) {
        return Err(CampaignCodecError::InvalidValue {
            reason: "planner input bundle contains a duplicate object",
        });
    }
    let bytes = object.canonical_bytes();
    let next_bytes =
        retained_bytes
            .checked_add(bytes.len())
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "planner-input-bundle-encoded-bytes",
            })?;
    if next_bytes > byte_limit {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "planner-input-bundle-encoded-bytes",
        });
    }
    objects.insert(id, bytes);
    *retained_bytes = next_bytes;
    Ok(())
}

impl Canonical for CampaignPlanningBundle {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.u64(self.objects.len() as u64);
        for (id, bytes) in &self.objects {
            id.encode(encoder);
            bytes.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let entries = decoder.sequence_bounded(
            MAX_PLANNING_BUNDLE_OBJECTS,
            "planner-input-bundle-object-count",
            |decoder| {
                let id = ContentId::decode(decoder)?;
                let bytes = decoder.sequence_bounded(
                    MAX_PLANNER_COMPONENT_MESSAGE_BYTES,
                    "planner-input-bundle-object-bytes",
                    u8::decode,
                )?;
                let object = ObjectEnvelope::from_canonical_bytes(&bytes)?;
                if object.content_id() != id {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "planner input bundle object identity mismatch",
                    });
                }
                Ok((id, bytes))
            },
        )?;
        let mut objects = BTreeMap::new();
        for (id, bytes) in entries {
            if objects.insert(id, bytes).is_some() {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "planner input bundle contains a duplicate object",
                });
            }
        }
        let bundle = Self { objects };
        codec::ensure_encoded_size(
            &bundle,
            MAX_PLANNER_COMPONENT_MESSAGE_BYTES,
            "planner-input-bundle-encoded-bytes",
        )?;
        Ok(bundle)
    }
}

/// Complete bounded input to one pure planner transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerRequest {
    schema_version: u32,
    expected_snapshot: CampaignSnapshotId,
    invocation: PlannerInvocation,
    engine: PlannerEngine,
    policy_artifact: PolicyArtifact,
    policy: CampaignPolicy,
    planner_state: PlannerState,
    input_view: CampaignPlanningView,
    input_bundle: CampaignPlanningBundle,
}

impl PlannerRequest {
    /// Builds and cross-validates one complete pure-planner input.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when a by-value object's derived identity
    /// disagrees with the invocation, the served page and input bundle differ,
    /// or the total request exceeds 64 MiB.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        expected_snapshot: CampaignSnapshotId,
        invocation: PlannerInvocation,
        engine: PlannerEngine,
        policy_artifact: PolicyArtifact,
        policy: CampaignPolicy,
        planner_state: PlannerState,
        input_view: CampaignPlanningView,
        input_bundle: CampaignPlanningBundle,
    ) -> Result<Self, CampaignCodecError> {
        if engine.id()? != invocation.engine()
            || policy_artifact.id()? != invocation.policy_artifact()
            || policy.id()? != invocation.policy()
            || planner_state.id()? != invocation.planner_state()
            || input_view.id()? != invocation.input_view()
            || policy_artifact.engine() != invocation.engine()
            || planner_state.engine() != invocation.engine()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner request by-value basis disagrees with invocation identities",
            });
        }
        let request = Self {
            schema_version: PLANNER_REQUEST_SCHEMA_VERSION,
            expected_snapshot,
            invocation,
            engine,
            policy_artifact,
            policy,
            planner_state,
            input_view,
            input_bundle,
        };
        request.input_bundle.validate_for(&request)?;
        codec::ensure_encoded_size(
            &request,
            MAX_PLANNER_COMPONENT_MESSAGE_BYTES,
            "planner-request-encoded-bytes",
        )?;
        Ok(request)
    }

    /// Returns the coordinator snapshot precondition.
    #[must_use]
    pub const fn expected_snapshot(&self) -> CampaignSnapshotId {
        self.expected_snapshot
    }

    /// Returns the exact content-derived invocation identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if envelope construction unexpectedly
    /// fails for the already validated invocation.
    pub fn invocation_id(&self) -> Result<crate::PlannerInvocationId, CampaignCodecError> {
        self.invocation.id()
    }

    /// Returns the immutable invocation basis.
    #[must_use]
    pub const fn invocation(&self) -> &PlannerInvocation {
        &self.invocation
    }

    /// Returns the exact planner engine descriptor.
    #[must_use]
    pub const fn engine(&self) -> &PlannerEngine {
        &self.engine
    }

    /// Returns the reproducible policy artifact descriptor.
    #[must_use]
    pub const fn policy_artifact(&self) -> &PolicyArtifact {
        &self.policy_artifact
    }

    /// Returns the active campaign policy revision.
    #[must_use]
    pub const fn policy(&self) -> &CampaignPolicy {
        &self.policy
    }

    /// Returns the portable pre-invocation planner state.
    #[must_use]
    pub const fn planner_state(&self) -> &PlannerState {
        &self.planner_state
    }

    /// Returns the complete immutable semantic planning view.
    #[must_use]
    pub const fn input_view(&self) -> &CampaignPlanningView {
        &self.input_view
    }

    /// Returns served request objects and their interpretation dependencies.
    #[must_use]
    pub const fn input_bundle(&self) -> &CampaignPlanningBundle {
        &self.input_bundle
    }

    /// Returns the domain-separated digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        planner_request_digest(self)
    }

    /// Returns the exact content-derived retained-request identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if content-envelope construction fails.
    pub fn id(&self) -> Result<RetainedPlannerRequestId, CampaignCodecError> {
        let bytes = self.canonical_bytes();
        ensure_retained_planner_request_shape(self.input_bundle.len(), bytes.len())?;
        RetainedPlannerRequestId::from_content_id(
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::RetainedPlannerRequest,
                crate::object::content_children(self.content_children()?)?,
                bytes,
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Result<Vec<(String, ContentId)>, CampaignCodecError> {
        let mut children = vec![
            (
                "expected-snapshot".to_owned(),
                self.expected_snapshot.content_id(),
            ),
            ("invocation".to_owned(), self.invocation.id()?.content_id()),
            ("engine".to_owned(), self.invocation.engine().content_id()),
            (
                "policy-artifact".to_owned(),
                self.invocation.policy_artifact().content_id(),
            ),
            ("policy".to_owned(), self.invocation.policy().content_id()),
            (
                "planner-state".to_owned(),
                self.invocation.planner_state().content_id(),
            ),
            (
                "input-view".to_owned(),
                self.invocation.input_view().content_id(),
            ),
        ];
        children.extend(
            self.input_bundle
                .object_ids()
                .enumerate()
                .map(|(index, id)| (format!("input-bundle.{index:04x}"), id)),
        );
        Ok(children)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes a strict bounded planner request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical,
    /// cross-object-inconsistent, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_PLANNER_COMPONENT_MESSAGE_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "planner-request-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Validates a submission's snapshot, invocation, page, and usage basis.
    ///
    /// This structural check deliberately does not verify component authority;
    /// [`PlannerClient`] additionally verifies the authentication tag with its
    /// configured [`PlannerAuthorityKey`].
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the submission answers another
    /// request or exceeds the exact invocation contract.
    pub fn validate_submission_basis(
        &self,
        submission: &PlannerSubmission,
    ) -> Result<(), CampaignCodecError> {
        if submission.expected_snapshot() != self.expected_snapshot {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner response snapshot basis mismatch",
            });
        }
        validate_planner_output(self, submission.proposal(), submission.measured_usage())
    }
}

impl Canonical for PlannerRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.expected_snapshot.encode(encoder);
        self.invocation.encode(encoder);
        self.engine.encode(encoder);
        self.policy_artifact.encode(encoder);
        self.policy.encode(encoder);
        self.planner_state.encode(encoder);
        self.input_view.encode(encoder);
        self.input_bundle.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != PLANNER_REQUEST_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported planner request schema version",
            });
        }
        Self::new(
            CampaignSnapshotId::decode(decoder)?,
            PlannerInvocation::decode(decoder)?,
            PlannerEngine::decode(decoder)?,
            PolicyArtifact::decode(decoder)?,
            CampaignPolicy::decode(decoder)?,
            PlannerState::decode(decoder)?,
            CampaignPlanningView::decode(decoder)?,
            CampaignPlanningBundle::decode(decoder)?,
        )
    }
}

/// Pure semantic engine output before supervised metering and authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerEngineOutput {
    proposal: PlannerStepProposal,
}

impl PlannerEngineOutput {
    /// Builds one pure semantic engine output.
    #[must_use]
    pub const fn new(proposal: PlannerStepProposal) -> Self {
        Self { proposal }
    }

    /// Returns the proposed semantic planner transition.
    #[must_use]
    pub const fn proposal(&self) -> &PlannerStepProposal {
        &self.proposal
    }
}

/// Request-bound authenticated output from one planner component evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerResponse {
    schema_version: u32,
    request_digest: CampaignHash,
    submission: PlannerSubmission,
    authentication_tag: CampaignHash,
}

impl PlannerResponse {
    /// Binds an authenticated submission to every canonical request byte.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the submission does not match the
    /// request basis or the response exceeds 64 MiB.
    pub fn authorize(
        authority: &PlannerAuthorityKey,
        request: &PlannerRequest,
        submission: PlannerSubmission,
    ) -> Result<Self, CampaignCodecError> {
        request.validate_submission_basis(&submission)?;
        let request_digest = planner_request_digest(request);
        let authentication_tag = authority.authenticate_component_basis(
            "crucible.campaign.planner-response.v1",
            &planner_response_basis(request_digest, &submission),
        );
        let response = Self {
            schema_version: PLANNER_RESPONSE_SCHEMA_VERSION,
            request_digest,
            submission,
            authentication_tag,
        };
        codec::ensure_encoded_size(
            &response,
            MAX_PLANNER_COMPONENT_MESSAGE_BYTES,
            "planner-response-encoded-bytes",
        )?;
        Ok(response)
    }

    /// Returns the domain-separated digest of the complete canonical request.
    #[must_use]
    pub const fn request_digest(&self) -> CampaignHash {
        self.request_digest
    }

    /// Returns the authenticated planner submission.
    #[must_use]
    pub const fn submission(&self) -> &PlannerSubmission {
        &self.submission
    }

    /// Verifies the complete response wrapper with trusted planner authority.
    #[must_use]
    pub fn verify(&self, authority: &PlannerAuthorityKey) -> bool {
        authority.verify_component_basis(
            "crucible.campaign.planner-response.v1",
            &planner_response_basis(self.request_digest, &self.submission),
            self.authentication_tag,
        )
    }

    /// Validates exact request binding and the structural submission basis.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when this response belongs to another
    /// request or its submission does not match the request basis.
    pub fn validate_for(&self, request: &PlannerRequest) -> Result<(), CampaignCodecError> {
        if self.request_digest != planner_request_digest(request) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner response request digest mismatch",
            });
        }
        request.validate_submission_basis(&self.submission)
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes a strict bounded request-bound planner response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, or
    /// oversized input. Exact request and authority checks remain required.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_PLANNER_COMPONENT_MESSAGE_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "planner-response-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }
}

impl Canonical for PlannerResponse {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.request_digest.encode(encoder);
        self.submission.encode(encoder);
        self.authentication_tag.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != PLANNER_RESPONSE_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported planner response schema version",
            });
        }
        let response = Self {
            schema_version: PLANNER_RESPONSE_SCHEMA_VERSION,
            request_digest: CampaignHash::decode(decoder)?,
            submission: PlannerSubmission::decode(decoder)?,
            authentication_tag: CampaignHash::decode(decoder)?,
        };
        codec::ensure_encoded_size(
            &response,
            MAX_PLANNER_COMPONENT_MESSAGE_BYTES,
            "planner-response-encoded-bytes",
        )?;
        Ok(response)
    }
}

/// Closed pure planner implementation without coordinator or host I/O authority.
pub trait PurePlannerEngine {
    /// Engine-specific deterministic evaluation failure.
    type Error;

    /// Evaluates one complete immutable planning request.
    ///
    /// # Errors
    ///
    /// Returns the engine-specific error when deterministic evaluation cannot
    /// produce a bounded result.
    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerEngineOutput, Self::Error>;
}

/// One supervised evaluation result with adapter-measured fuel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisedPlannerExecution<E> {
    result: Result<PlannerEngineOutput, E>,
    measured_fuel: u64,
}

impl<E> SupervisedPlannerExecution<E> {
    /// Binds an engine result to the supervisor's fuel measurement.
    #[must_use]
    pub const fn new(result: Result<PlannerEngineOutput, E>, measured_fuel: u64) -> Self {
        Self {
            result,
            measured_fuel,
        }
    }

    /// Separates the engine result from its measured fuel.
    pub fn into_parts(self) -> (Result<PlannerEngineOutput, E>, u64) {
        (self.result, self.measured_fuel)
    }
}

/// Killable supervisor for one bounded pure planner evaluation.
///
/// The supervisor, not the pure engine, owns the authoritative fuel
/// observation. A production implementation must enforce the request fuel
/// budget and a finite wall-clock deadline, observe cancellation, and terminate
/// an evaluation that exceeds any bound. This trait deliberately owns the
/// execution call instead of wrapping an uninterruptible in-process closure.
pub trait PlannerExecutionSupervisor<E: PurePlannerEngine> {
    /// Supervisor-specific execution or measurement failure.
    type Error;

    /// Executes one evaluation and returns its result with measured fuel.
    ///
    /// The returned fuel covers the complete operation, including an operation
    /// that returns an engine error. Implementations must not derive fuel from
    /// planner-provided claims.
    ///
    /// # Errors
    ///
    /// Returns the supervisor-specific error when the operation cannot be run,
    /// bounded, terminated, or measured authoritatively.
    fn execute(
        &mut self,
        engine: &mut E,
        request: &PlannerRequest,
    ) -> Result<SupervisedPlannerExecution<E::Error>, Self::Error>;
}

/// Implementor-facing authenticated planner component service.
pub trait PlannerService {
    /// Component-specific transport or evaluation failure.
    type Error;

    /// Evaluates and authenticates one planner request.
    ///
    /// # Errors
    ///
    /// Returns the component-specific error when no authenticated submission
    /// can be produced. Semantic planner output remains untrusted until the
    /// checked client and coordinator validate it.
    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerResponse, Self::Error>;
}

/// Supervised authority adapter over one pure planner engine.
pub struct AuthorizedPlannerService<E, M> {
    engine: E,
    supervisor: M,
    authority: PlannerAuthorityKey,
}

impl<E, M> AuthorizedPlannerService<E, M> {
    /// Binds a pure engine and supervised meter to planner authority.
    #[must_use]
    pub const fn new(engine: E, supervisor: M, authority: PlannerAuthorityKey) -> Self {
        Self {
            engine,
            supervisor,
            authority,
        }
    }

    /// Returns the engine and meter after component shutdown.
    #[must_use]
    pub fn into_parts(self) -> (E, M) {
        (self.engine, self.supervisor)
    }
}

impl<E: PurePlannerEngine, M: PlannerExecutionSupervisor<E>> PlannerService
    for AuthorizedPlannerService<E, M>
{
    type Error = AuthorizedPlannerServiceError<E::Error, M::Error>;

    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerResponse, Self::Error> {
        let execution = self
            .supervisor
            .execute(&mut self.engine, request)
            .map_err(AuthorizedPlannerServiceError::Supervisor)?;
        let (output, fuel) = execution.into_parts();
        let output = output.map_err(AuthorizedPlannerServiceError::Engine)?;
        let measured = measured_planning_usage(request, output.proposal(), fuel)
            .map_err(AuthorizedPlannerServiceError::InvalidOutput)?;
        validate_planner_output(request, output.proposal(), measured)
            .map_err(AuthorizedPlannerServiceError::InvalidOutput)?;
        let submission = PlannerSubmission::authorize(
            &self.authority,
            request.expected_snapshot(),
            output.proposal,
            measured,
        )
        .map_err(AuthorizedPlannerServiceError::InvalidOutput)?;
        PlannerResponse::authorize(&self.authority, request, submission)
            .map_err(AuthorizedPlannerServiceError::InvalidOutput)
    }
}

/// Failure from a supervised planner authority adapter.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthorizedPlannerServiceError<E, M> {
    /// The pure engine failed before producing output.
    #[error("pure planner engine failed: {0}")]
    Engine(E),
    /// The supervisor could not bound or measure the engine evaluation.
    #[error("planner execution supervisor failed: {0}")]
    Supervisor(M),
    /// The engine produced output outside the exact request contract.
    #[error(transparent)]
    InvalidOutput(CampaignCodecError),
}

/// Coordinator-facing checked client over one direct or RPC planner service.
pub struct PlannerClient<S> {
    service: S,
    authority: PlannerAuthorityKey,
}

impl<S> PlannerClient<S> {
    /// Wraps one component service with its exact verification authority.
    #[must_use]
    pub const fn new(service: S, authority: PlannerAuthorityKey) -> Self {
        Self { service, authority }
    }

    /// Returns the wrapped service after coordinator ownership ends.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.service
    }

    pub(crate) const fn authority(&self) -> &PlannerAuthorityKey {
        &self.authority
    }
}

impl<S: PlannerService> PlannerClient<S> {
    /// Evaluates a request and validates response authority and exact basis.
    ///
    /// # Errors
    ///
    /// Returns [`PlannerClientError::Service`] when the component cannot
    /// produce a submission, or [`PlannerClientError::InvalidResponse`] when
    /// the response is unauthenticated or does not match the exact request.
    pub fn plan(
        &mut self,
        request: &PlannerRequest,
    ) -> Result<PlannerResponse, PlannerClientError<S::Error>> {
        let response = self
            .service
            .plan(request)
            .map_err(PlannerClientError::Service)?;
        if !response.verify(&self.authority) || !response.submission().verify(&self.authority) {
            return Err(PlannerClientError::InvalidResponse(
                CampaignCodecError::InvalidValue {
                    reason: "planner response authentication failed",
                },
            ));
        }
        response
            .validate_for(request)
            .map_err(PlannerClientError::InvalidResponse)?;
        Ok(response)
    }
}

/// Failure from the coordinator-facing checked planner client.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlannerClientError<E> {
    /// The direct or RPC planner component failed to produce a response.
    #[error("planner service failed: {0}")]
    Service(E),
    /// The component returned an unauthenticated or cross-request response.
    #[error(transparent)]
    InvalidResponse(CampaignCodecError),
}

fn validate_planner_output(
    request: &PlannerRequest,
    proposal: &PlannerStepProposal,
    measured: PlanningUsage,
) -> Result<(), CampaignCodecError> {
    let invocation = request.invocation();
    let budget = invocation.budget();
    if proposal.invocation() != request.invocation_id()?
        || proposal.next_state().engine() != invocation.engine()
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "planner response invocation or next-state engine mismatch",
        });
    }

    let claimed = proposal.usage_claim();
    if claimed.branch_requests > u64::from(budget.branch_requests())
        || claimed.proposals > u64::from(budget.proposals())
        || claimed.input_objects > u64::from(budget.input_objects())
        || claimed.input_bytes > budget.input_bytes()
        || claimed.fuel > budget.fuel()
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "planner response usage claim exceeds budget",
        });
    }

    let (branch_requests, proposals) = match proposal.disposition() {
        PlannerProposalDisposition::Issue {
            branch_requests,
            proposals,
            ..
        } => (branch_requests.len(), proposals.len()),
        PlannerProposalDisposition::ContinueScan { .. } | PlannerProposalDisposition::NoWork => {
            (0, 0)
        }
    };
    if measured.branch_requests != usize_to_u64(branch_requests)?
        || measured.proposals != usize_to_u64(proposals)?
        || measured.branch_requests > u64::from(budget.branch_requests())
        || measured.proposals > u64::from(budget.proposals())
        || measured.input_objects != invocation.scan_page().input_objects()
        || measured.input_bytes != invocation.scan_page().input_bytes()
        || measured.fuel > budget.fuel()
    {
        return Err(CampaignCodecError::InvalidValue {
            reason: "planner measured usage disagrees with request or output",
        });
    }

    match proposal.disposition() {
        PlannerProposalDisposition::ContinueScan { cursor }
            if !invocation.scan_page().complete()
                && cursor.input_view() == invocation.input_view()
                && cursor.after() == invocation.scan_page().last() =>
        {
            Ok(())
        }
        PlannerProposalDisposition::Issue { .. } | PlannerProposalDisposition::NoWork
            if invocation.scan_page().complete() =>
        {
            Ok(())
        }
        PlannerProposalDisposition::ContinueScan { .. }
        | PlannerProposalDisposition::Issue { .. }
        | PlannerProposalDisposition::NoWork => Err(CampaignCodecError::InvalidValue {
            reason: "planner response disposition disagrees with served scan page",
        }),
    }
}

fn measured_planning_usage(
    request: &PlannerRequest,
    proposal: &PlannerStepProposal,
    fuel: u64,
) -> Result<PlanningUsage, CampaignCodecError> {
    let (branch_requests, proposals) = match proposal.disposition() {
        PlannerProposalDisposition::Issue {
            branch_requests,
            proposals,
            ..
        } => (branch_requests.len(), proposals.len()),
        PlannerProposalDisposition::ContinueScan { .. } | PlannerProposalDisposition::NoWork => {
            (0, 0)
        }
    };
    Ok(PlanningUsage {
        branch_requests: usize_to_u64(branch_requests)?,
        proposals: usize_to_u64(proposals)?,
        input_objects: request.invocation().scan_page().input_objects(),
        input_bytes: request.invocation().scan_page().input_bytes(),
        fuel,
    })
}

fn usize_to_u64(value: usize) -> Result<u64, CampaignCodecError> {
    u64::try_from(value).map_err(|_| CampaignCodecError::LimitExceeded {
        limit: "planner-output-count",
    })
}

fn planner_request_digest(request: &PlannerRequest) -> CampaignHash {
    CampaignHash::derive(
        "crucible.campaign.planner-request-digest.v1",
        &request.canonical_bytes(),
    )
}

fn ensure_retained_planner_request_shape(
    bundle_objects: usize,
    encoded_bytes: usize,
) -> Result<(), CampaignCodecError> {
    if bundle_objects > MAX_RETAINED_PLANNER_REQUEST_BUNDLE_OBJECTS {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "retained-planner-request-bundle-object-count",
        });
    }
    if encoded_bytes > MAX_RETAINED_PLANNER_REQUEST_BYTES {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "retained-planner-request-encoded-bytes",
        });
    }
    Ok(())
}

fn planner_response_basis(request_digest: CampaignHash, submission: &PlannerSubmission) -> Vec<u8> {
    let mut encoder = Encoder::new();
    PLANNER_RESPONSE_SCHEMA_VERSION.encode(&mut encoder);
    request_digest.encode(&mut encoder);
    submission.encode(&mut encoder);
    encoder.finish()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::convert::Infallible;

    use crucible_cas::content_store::{ContentId, ObjectKind};

    use super::*;
    use crate::{
        CampaignHash, CampaignMode, CampaignSeed, CandidateGeneratorAlgorithm,
        CandidateGeneratorSpec, ChoicePolicy, ExplorerPolicy, FairnessPolicy, GuidanceEvidence,
        PlanningBudget, PlanningScanPage, ProgressiveWideningPolicy, PuctPolicy, RetentionPolicy,
        ScenarioDefId,
    };

    #[test]
    fn retained_request_profile_has_distinct_wire_and_child_bounds() {
        assert_eq!(MAX_RETAINED_PLANNER_REQUEST_BUNDLE_OBJECTS, 65_529);
        assert!(ensure_retained_planner_request_shape(65_529, 32 * 1024 * 1024).is_ok());
        assert!(matches!(
            ensure_retained_planner_request_shape(65_530, 1),
            Err(CampaignCodecError::LimitExceeded {
                limit: "retained-planner-request-bundle-object-count"
            })
        ));
        assert!(matches!(
            ensure_retained_planner_request_shape(0, 32 * 1024 * 1024 + 1),
            Err(CampaignCodecError::LimitExceeded {
                limit: "retained-planner-request-encoded-bytes"
            })
        ));
    }

    #[derive(Clone, Copy)]
    struct FixedExecutionSupervisor(u64);

    impl<E: PurePlannerEngine> PlannerExecutionSupervisor<E> for FixedExecutionSupervisor {
        type Error = Infallible;

        fn execute(
            &mut self,
            engine: &mut E,
            request: &PlannerRequest,
        ) -> Result<SupervisedPlannerExecution<E::Error>, Self::Error> {
            Ok(SupervisedPlannerExecution::new(
                engine.plan(request),
                self.0,
            ))
        }
    }

    #[test]
    fn planner_request_is_strict_bounded_and_has_a_golden_vector() {
        let request = request(0x21);
        let bytes = request.canonical_bytes();
        assert_eq!(
            PlannerRequest::from_canonical_bytes(&bytes).expect("planner request"),
            request
        );
        assert_eq!(
            encode_hex(blake3::hash(&bytes).as_bytes()),
            "448d0678beaeb238107a6c4584cda2b5604150556a4b0eac42a720faf372ec66"
        );
        let retained = ObjectEnvelope::for_record(
            crate::CampaignRecordKind::RetainedPlannerRequest,
            crate::object::content_children(
                request
                    .content_children()
                    .expect("retained request children"),
            )
            .expect("canonical retained request children"),
            bytes.clone(),
        )
        .expect("retained request envelope");
        assert_eq!(
            request.id().expect("retained request id").content_id(),
            retained.content_id()
        );
        assert_eq!(
            ObjectEnvelope::from_canonical_bytes(&retained.canonical_bytes())
                .expect("retained request decode"),
            retained
        );

        let output = no_work_output(&request);
        let authority = PlannerAuthorityKey::from_bytes([0x22; 32]).expect("authority");
        let submission = PlannerSubmission::authorize(
            &authority,
            request.expected_snapshot(),
            output.proposal().clone(),
            measured_planning_usage(&request, output.proposal(), 1).expect("measured usage"),
        )
        .expect("submission");
        let response =
            PlannerResponse::authorize(&authority, &request, submission).expect("response");
        let response_bytes = response.canonical_bytes();
        assert_eq!(
            PlannerResponse::from_canonical_bytes(&response_bytes).expect("planner response"),
            response
        );
        assert_eq!(
            encode_hex(blake3::hash(&response_bytes).as_bytes()),
            "bb3ac28fa1b156ec9953ff20d249c80bf18928643d35219ffc535c62423e5da7"
        );

        let mut wrong_version = bytes.clone();
        wrong_version[..4].copy_from_slice(&2_u32.to_be_bytes());
        assert_eq!(
            PlannerRequest::from_canonical_bytes(&wrong_version),
            Err(CampaignCodecError::InvalidValue {
                reason: "unsupported planner request schema version"
            })
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            PlannerRequest::from_canonical_bytes(&trailing),
            Err(CampaignCodecError::TrailingBytes)
        );
    }

    #[test]
    fn checked_direct_planner_rejects_cross_request_replay() {
        #[derive(Clone)]
        struct FixedEngine {
            output: PlannerEngineOutput,
        }

        impl PurePlannerEngine for FixedEngine {
            type Error = Infallible;

            fn plan(
                &mut self,
                _request: &PlannerRequest,
            ) -> Result<PlannerEngineOutput, Self::Error> {
                Ok(self.output.clone())
            }
        }

        let first = request(0x31);
        let second = request(0x32);
        let authority = PlannerAuthorityKey::from_bytes([0x41; 32]).expect("authority");
        let service = AuthorizedPlannerService::new(
            FixedEngine {
                output: no_work_output(&first),
            },
            FixedExecutionSupervisor(1),
            authority.clone(),
        );
        let mut client = PlannerClient::new(service, authority);
        let response = client.plan(&first).expect("checked planner response");
        assert_eq!(
            response.submission().proposal(),
            no_work_output(&first).proposal()
        );

        assert!(matches!(
            client.plan(&second),
            Err(PlannerClientError::Service(
                AuthorizedPlannerServiceError::InvalidOutput(CampaignCodecError::InvalidValue {
                    reason: "planner response invocation or next-state engine mismatch"
                })
            ))
        ));
    }

    #[test]
    fn supervised_meter_not_engine_claim_owns_fuel_authority() {
        #[derive(Clone)]
        struct FixedEngine(PlannerEngineOutput);

        impl PurePlannerEngine for FixedEngine {
            type Error = Infallible;

            fn plan(
                &mut self,
                _request: &PlannerRequest,
            ) -> Result<PlannerEngineOutput, Self::Error> {
                Ok(self.0.clone())
            }
        }

        let request = request(0x33);
        let authority = PlannerAuthorityKey::from_bytes([0x43; 32]).expect("authority");
        let service = AuthorizedPlannerService::new(
            FixedEngine(no_work_output(&request)),
            FixedExecutionSupervisor(request.invocation().budget().fuel() + 1),
            authority.clone(),
        );
        let mut client = PlannerClient::new(service, authority);
        assert!(matches!(
            client.plan(&request),
            Err(PlannerClientError::Service(
                AuthorizedPlannerServiceError::InvalidOutput(CampaignCodecError::InvalidValue {
                    reason: "planner measured usage disagrees with request or output"
                })
            ))
        ));
    }

    #[test]
    fn planning_bundle_rejects_objects_unrelated_to_the_request_basis() {
        let request = request(0x51);
        let unrelated =
            PlannerEngine::new("unrelated", 1, 1, BTreeSet::new()).expect("unrelated engine");
        let envelope = ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlannerEngine,
            BTreeSet::new(),
            codec::encode(&unrelated),
        )
        .expect("unrelated envelope");
        let bundle = CampaignPlanningBundle::new(vec![envelope]).expect("structural bundle");
        assert_eq!(
            PlannerRequest::new(
                request.expected_snapshot(),
                request.invocation().clone(),
                request.engine().clone(),
                request.policy_artifact().clone(),
                request.policy().clone(),
                request.planner_state().clone(),
                *request.input_view(),
                bundle,
            ),
            Err(CampaignCodecError::InvalidValue {
                reason: "planner input bundle contains an unrelated object"
            })
        );
    }

    #[test]
    fn planning_bundle_stops_retaining_at_the_aggregate_byte_bound() {
        let first = ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlannerEngine,
            BTreeSet::new(),
            vec![0x11],
        )
        .expect("first envelope");
        let second = ObjectEnvelope::for_record(
            crate::CampaignRecordKind::PlannerEngine,
            BTreeSet::new(),
            vec![0x22],
        )
        .expect("second envelope");
        let first_bytes = first.canonical_bytes().len();
        let byte_limit = first_bytes + second.canonical_bytes().len() - 1;
        let mut objects = BTreeMap::new();
        let mut retained_bytes = 0;

        insert_planning_bundle_object(&mut objects, &mut retained_bytes, first, byte_limit)
            .expect("first object");
        assert_eq!(
            insert_planning_bundle_object(&mut objects, &mut retained_bytes, second, byte_limit,),
            Err(CampaignCodecError::LimitExceeded {
                limit: "planner-input-bundle-encoded-bytes"
            })
        );
        assert_eq!(objects.len(), 1);
        assert_eq!(retained_bytes, first_bytes);
    }

    #[test]
    fn planner_response_digest_binds_same_invocation_bundle_bytes() {
        let first = request(0x52);
        let generator = generator();
        let envelope = ObjectEnvelope::for_record(
            crate::CampaignRecordKind::CandidateGeneratorSpec,
            crate::object::content_children(generator.content_children())
                .expect("generator children"),
            generator.canonical_bytes(),
        )
        .expect("generator envelope");
        let second = PlannerRequest::new(
            first.expected_snapshot(),
            first.invocation().clone(),
            first.engine().clone(),
            first.policy_artifact().clone(),
            first.policy().clone(),
            first.planner_state().clone(),
            *first.input_view(),
            CampaignPlanningBundle::new(vec![envelope]).expect("generator bundle"),
        )
        .expect("same invocation with explicit dependency");
        assert_eq!(first.invocation_id(), second.invocation_id());
        assert_ne!(first.canonical_bytes(), second.canonical_bytes());

        let authority = PlannerAuthorityKey::from_bytes([0x42; 32]).expect("authority");
        let output = no_work_output(&first);
        let submission = PlannerSubmission::authorize(
            &authority,
            first.expected_snapshot(),
            output.proposal().clone(),
            measured_planning_usage(&first, output.proposal(), 1).expect("measured usage"),
        )
        .expect("submission");
        let cached =
            PlannerResponse::authorize(&authority, &first, submission).expect("first response");
        assert_eq!(
            cached.validate_for(&second),
            Err(CampaignCodecError::InvalidValue {
                reason: "planner response request digest mismatch"
            })
        );

        let transplanted = PlannerResponse {
            schema_version: PLANNER_RESPONSE_SCHEMA_VERSION,
            request_digest: planner_request_digest(&second),
            submission: cached.submission.clone(),
            authentication_tag: cached.authentication_tag,
        };
        assert!(transplanted.validate_for(&second).is_ok());
        assert!(!transplanted.verify(&authority));
    }

    fn request(byte: u8) -> PlannerRequest {
        let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("engine");
        let engine_id = engine.id().expect("engine id");
        let policy_artifact = PolicyArtifact::new(
            engine_id,
            1,
            content(ObjectKind::Trace, byte.wrapping_add(1)),
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .expect("policy artifact");
        let policy = policy(byte);
        let state =
            PlannerState::new(engine_id, "closed-state", 1, vec![byte; 8]).expect("planner state");
        let view = CampaignPlanningView::new(
            content(ObjectKind::MerkleNode, byte.wrapping_add(2)),
            content(ObjectKind::MerkleNode, byte.wrapping_add(3)),
            content(ObjectKind::MerkleNode, byte.wrapping_add(4)),
            content(ObjectKind::MerkleNode, byte.wrapping_add(5)),
            content(ObjectKind::MerkleNode, byte.wrapping_add(6)),
            content(ObjectKind::MerkleNode, byte.wrapping_add(7)),
            content(ObjectKind::MerkleNode, byte.wrapping_add(8)),
        )
        .expect("planning view");
        let page = PlanningScanPage::new(None, 1, Vec::new(), true, 0).expect("empty EOF page");
        let invocation = PlannerInvocation::new(
            engine_id,
            policy_artifact.id().expect("artifact id"),
            policy.id().expect("policy id"),
            state.id().expect("state id"),
            view.id().expect("view id"),
            page,
            PlanningBudget::new(4, 4, 4, 4096, 1024).expect("budget"),
        )
        .expect("invocation");
        PlannerRequest::new(
            CampaignSnapshotId::from_content_id(content(
                ObjectKind::CampaignSnapshot,
                byte.wrapping_add(9),
            ))
            .expect("snapshot id"),
            invocation,
            engine,
            policy_artifact,
            policy,
            state,
            view,
            CampaignPlanningBundle::new(Vec::new()).expect("empty bundle"),
        )
        .expect("planner request")
    }

    fn no_work_output(request: &PlannerRequest) -> PlannerEngineOutput {
        let usage = PlanningUsage {
            branch_requests: 0,
            proposals: 0,
            input_objects: 0,
            input_bytes: 0,
            fuel: 1,
        };
        PlannerEngineOutput::new(
            PlannerStepProposal::new(
                request.invocation_id().expect("invocation id"),
                PlannerState::new(
                    request.invocation().engine(),
                    "closed-state",
                    1,
                    vec![0x77; 8],
                )
                .expect("next state"),
                usage,
                GuidanceEvidence::new(BTreeMap::new()).expect("evidence"),
                PlannerProposalDisposition::NoWork,
            )
            .expect("proposal"),
        )
    }

    fn policy(byte: u8) -> CampaignPolicy {
        let generator = generator();
        CampaignPolicy::new(
            ScenarioDefId::from_hash(CampaignHash::derive(
                "crucible.test.planner-scenario.v1",
                &[byte],
            )),
            CampaignSeed::from_bytes([byte; 32]),
            CampaignMode::Strict,
            ExplorerPolicy::TreeSearch {
                puct: PuctPolicy::new(1_000_000, 0, 0),
                widening: Some(
                    ProgressiveWideningPolicy::new(
                        crate::ExactRational::new(1, 1).expect("k"),
                        crate::ExactRational::new(1, 2).expect("alpha"),
                        1,
                        4,
                        1,
                    )
                    .expect("widening"),
                ),
            },
            BTreeMap::from([(
                String::from("test.choice"),
                ChoicePolicy::new("test.choice", generator.id().expect("generator id"), true)
                    .expect("choice policy"),
            )]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(1, 1).expect("fairness"),
            RetentionPolicy::new(false, 1, false, false),
            false,
        )
        .expect("policy")
    }

    fn generator() -> CandidateGeneratorSpec {
        CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All).expect("generator")
    }

    fn content(kind: ObjectKind, byte: u8) -> ContentId {
        let schema_version = if kind == ObjectKind::CampaignSnapshot {
            2
        } else {
            1
        };
        ContentId::for_bytes(kind, schema_version, &[byte; 32])
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }
}
