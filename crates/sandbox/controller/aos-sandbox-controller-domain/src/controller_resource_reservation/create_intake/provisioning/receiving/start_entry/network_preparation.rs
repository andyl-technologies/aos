//! Retains exact Network content, the admitted plan and the original sealed file.
//!
//! Full manifest/Spec inputs are borrowed only from the actual completed intake.
//! New Start C pays content construction, Root comparison, native sealing and
//! signing representation before entry. No raw file, signed-plan bytes or
//! caller-selected amount can manufacture this prepared original.

use super::*;
use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1 as Purpose;
use aos_sandbox_model::{ResourceDimension as D, RevocationScopeId};
use aos_linux_descriptors::credential::SealedReadOnlyCredential;
use aos_linux_descriptors::credential::SealedReadOnlyCredentialCreateOriginalsV1;
use aos_linux_descriptors::credential::SealedReadOnlyCredentialCreateClosedV1;
use aos_sandbox_protocol::authorization_artifact::{BrokerPlanPreparation, SignedBrokerPlan,
    SigningAuthority, start_resource_plan::{StartResourcePlanPreparationDataV1,
        prepare_admitted_start_network_plan_v2}};
use aos_sandbox_protocol::semantics::network::{NetworkSemanticsError,
    preparation_content::{NetworkPreparationContentV2, NetworkPreparationContentReferenceV2}};
use crate::normal_root::{RootStartResourcePrepareAdmissionOriginalV2,
    RootStartResourceConstructionTurnV2, RootHostLaunchClientOriginalV1};

mod host;

use host::{HostPreparedOriginalV2, NormalizedStartResourceV2};

type Cause = Box<dyn Error + Send + Sync>;
const CONTENT_NAME: &str = "aos-network-preparation-v2";

/// Reports refusal while exact models and native causes remain in the owner.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the original Start Network preparation is incomplete or refused")]
#[doc(hidden)]
pub struct PreparedStartResourceRequestClosedV2;

#[derive(Clone, Copy)]
enum First { Host, Publication, Reentry, ContentFunding, Content, Reference, Body, MountBody, StorageArguments, StorageBody, ContentAfter,
    ModelFunding, Inputs, Normalization, Seal, Signed, ConstructionAfter }

/// Owns the exact admitted Network63 request and its original sealed content.
#[doc(hidden)]
#[must_use = "retain complete content, signatures and native sealing originals"]
pub struct PreparedStartResourceRequestOriginalV2 {
    purpose: Purpose,
    host: HostPreparedOriginalV2,
    publication: super::host_publication::StartHostPublicationConstructionOriginalV2,
    mount_body: Option<Result<Vec<u8>, Cause>>,
    storage_arguments: Option<Result<aos_sandbox_protocol::semantics::storage_guest_root::CanonicalStorageGuestRootArgumentsV1, Cause>>,
    storage_body: Option<Result<Vec<u8>, Cause>>,
    specification_bytes: Option<usize>,
    parent: Option<aos_sandbox_model::OperationId>,
    content_funding: Option<Result<(), ResourceReservationErrorV1>>,
    content: Option<Result<Vec<u8>, NetworkSemanticsError>>,
    reference: Option<Result<NetworkPreparationContentReferenceV2, NetworkSemanticsError>>,
    body: Option<Result<Vec<u8>, NetworkSemanticsError>>,
    content_after: Option<Result<(), ResourceReservationErrorV1>>,
    root_commitment: Option<[u8; 32]>,
    construction_turn: Option<u64>,
    model_funding: Option<Result<(), ResourceReservationErrorV1>>,
    model_resident: Option<ResourceVector>,
    input: Option<Result<(), ResourceReservationErrorV1>>,
    normalization: Option<Result<NormalizedStartResourceV2, Cause>>,
    sealing: SealedReadOnlyCredentialCreateOriginalsV1,
    seal: Option<Result<(), SealedReadOnlyCredentialCreateClosedV1>>,
    signed_check: Option<Result<(), ResourceReservationErrorV1>>,
    signed: Option<SignedBrokerPlan>,
    construction_after: Option<Result<(), ResourceReservationErrorV1>>,
    first: Option<First>,
    original_selected: bool,
}

impl PreparedStartResourceRequestOriginalV2 {
    /// Creates only inert inline destinations before the actual native debit.
    #[must_use]
    pub fn new() -> Self {
        Self {purpose: Purpose::NetworkPrepare, host: HostPreparedOriginalV2::new(), publication: super::host_publication::StartHostPublicationConstructionOriginalV2::new(), mount_body: None, storage_arguments: None, storage_body: None, specification_bytes: None, parent: None, content_funding: None, content: None, reference: None,
            body: None, content_after: None, root_commitment: None, construction_turn: None,
            model_funding: None, model_resident: None, input: None, normalization: None,
            sealing: SealedReadOnlyCredentialCreateOriginalsV1::new(), seal: None,
            signed_check: None, signed: None, construction_after: None, first: None,
            original_selected: false}
    }

    /// Creates only an inert Mount62 request destination.
    #[doc(hidden)]
    #[must_use]
    pub fn mount_namespace_v2() -> Self {
        let mut owner = Self::new();
        owner.purpose = Purpose::MountNamespace;
        owner
    }

    /// Creates only inert destinations for publication into the held workspace.
    #[doc(hidden)]
    #[must_use]
    pub fn storage_guest_root_v2() -> Self {
        let mut owner = Self::new();
        owner.purpose = Purpose::StorageGuestRoot;
        owner
    }

    /// Creates inert paired Host destinations without issuing a grant.
    #[doc(hidden)]
    #[must_use]
    pub fn host_launch_v2() -> Self {
        let mut owner = Self::new();
        owner.purpose = Purpose::HostLaunch;
        owner
    }

    pub(crate) fn storage_request_receiving_demand_v2() -> Result<ResourceVector, ResourceReservationErrorV1> {
        use aos_sandbox_protocol::semantics::storage_guest_root::CanonicalStorageGuestRootArgumentsV1;
        let body = CanonicalStorageGuestRootArgumentsV1::deadline_free_request_receiving_bytes_v2()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let carriers = size_of::<Result<CanonicalStorageGuestRootArgumentsV1, Cause>>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(size_of::<Result<Vec<u8>, Cause>>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(size_of::<aos_sandbox_protocol::ProtocolValidationError>().checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(body))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, carriers))
    }

    /// Returns the immutable request purpose, without granting an interval.
    #[doc(hidden)]
    #[must_use]
    pub fn purpose_data_v2(&self) -> Purpose { self.purpose }

    pub(crate) fn mount_request_receiving_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if self.purpose != Purpose::MountNamespace { return Err(ResourceReservationErrorV1::Conflict); }
        aos_sandbox_protocol::authorization_artifact::start_resource_plan::start_mount_request_receiving_demand_v2(
            self.specification_bytes.ok_or(ResourceReservationErrorV1::Conflict)?)
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    fn descriptor_complete_v2(&self) -> bool {
        match self.purpose {
            Purpose::NetworkPrepare => matches!(self.seal, Some(Ok(()))),
            Purpose::MountNamespace | Purpose::StorageGuestRoot | Purpose::HostLaunch => matches!(self.normalization, Some(Ok(_))),
            _ => false,
        }
    }

    pub(crate) fn content_receiving_demand_v2(
        original: &OriginalStartHostRootLoanV1<'_, '_>,
        controller: &Journal,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let (manifest, specification) = original.start_assignment_v2(controller)?;
        Self::content_receiving_data_v2(manifest, specification)
    }

    fn content_receiving_data_v2(
        manifest: &aos_sandbox_model::CanonicalAssignmentManifestV1,
        specification: &crate::sandbox_spec_state::DurableSandboxSpecV1,
    ) -> Result<ResourceVector, ResourceReservationErrorV1> {
        aos_sandbox_protocol::authorization_artifact::start_resource_plan::start_network_content_receiving_demand_v2(
            manifest.canonical_bytes().len(), specification.canonical_bytes().len(),
            specification.spec().network_profile().endpoint_ids().len(),
        ).ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Builds exact content and its deadline-free request from the same intake.
    ///
    /// This runs before opening Root, while the new Start's actual native C
    /// interval is live. Only the existing canonical encoder/body factory runs;
    /// no external Spec, endpoint selector, descriptor or file is accepted.
    ///
    /// # Errors
    /// Retains original binding/funding, framing, encoding and reference failure.
    #[doc(hidden)]
    pub fn prepare_content_once_v2(&mut self, original: &mut OriginalStartHostRootLoanV1<'_, '_>,
        controller: &Journal,
    ) -> Result<(), PreparedStartResourceRequestClosedV2> {
        if self.parent.is_some() || self.first.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(CLOSED);
        }
        self.parent = Some(original.parent_operation_v1());
        self.content_funding = Some((|| {
            let demand = match self.purpose {
                Purpose::NetworkPrepare => Self::content_receiving_demand_v2(original, controller)?,
                Purpose::MountNamespace => {
                    let (_, specification) = original.start_assignment_v2(controller)?;
                    aos_sandbox_protocol::authorization_artifact::start_resource_plan::
                        start_mount_request_receiving_demand_v2(specification.canonical_bytes().len())
                        .ok_or(ResourceReservationErrorV1::Conflict)?
                }
                Purpose::StorageGuestRoot => Self::storage_request_receiving_demand_v2()?,
                _ => return Err(ResourceReservationErrorV1::Conflict),
            };
            let returned = original.require_complete_v1(controller, demand);
            self.original_selected = returned.is_err() && original.failure_v1().is_some();
            returned
        })());
        if !matches!(self.content_funding, Some(Ok(()))) { self.first = Some(First::ContentFunding); return Err(CLOSED); }
        let (manifest, specification) = match original.start_assignment_v2(controller) {
            Ok(material) => material,
            Err(cause) => {
                self.input = Some(Err(cause));
                self.first = Some(First::Inputs);
                return Err(CLOSED);
            }
        };
        self.input = Some(Ok(()));
        self.specification_bytes = Some(specification.canonical_bytes().len());
        if self.purpose == Purpose::StorageGuestRoot {
            self.storage_arguments = Some((|| -> Result<_, Cause> {
                let (workspace, creation) = original.creation_workspace_selectors_v2(controller)?;
                Ok(aos_sandbox_protocol::semantics::storage_guest_root::CanonicalStorageGuestRootArgumentsV1::
                    from_protected_assignment(manifest.broker_assignment()?,
                        original.parent_operation_v1().into_bytes(), workspace, creation)?)
            })());
            let Some(Ok(arguments)) = self.storage_arguments.as_ref() else {
                self.first = Some(First::StorageArguments);
                return Err(CLOSED);
            };
            self.storage_body = Some(arguments.deadline_free_request_body_v2(
                original.parent_operation_v1().into_bytes()).map_err(|cause| Box::new(cause) as Cause));
            if !matches!(self.storage_body, Some(Ok(_))) {
                self.first = Some(First::StorageBody);
                return Err(CLOSED);
            }
            return Ok(());
        }
        if self.purpose == Purpose::MountNamespace {
            self.mount_body = Some(aos_sandbox_protocol::authorization_artifact::start_resource_plan::
                start_mount_request_body_data_v2(manifest, specification.descriptor(), specification.spec(),
                    original.parent_operation_v1().into_bytes()));
            if !matches!(self.mount_body, Some(Ok(_))) {
                self.first = Some(First::MountBody);
                return Err(CLOSED);
            }
            return Ok(());
        }
        self.content = Some(NetworkPreparationContentV2::new(manifest.canonical_bytes(), specification.canonical_bytes())
            .and_then(NetworkPreparationContentV2::encode));
        let Some(Ok(content)) = self.content.as_ref() else { self.first = Some(First::Content); return Err(CLOSED); };
        self.reference = Some(NetworkPreparationContentReferenceV2::for_content(content));
        let Some(Ok(reference)) = self.reference.as_ref() else { self.first = Some(First::Reference); return Err(CLOSED); };
        self.body = Some((|| {
            let assignment = manifest.broker_assignment().map_err(|_| NetworkSemanticsError::InvalidActionShape)?;
            reference.deadline_free_request_body_v2(assignment, original.parent_operation_v1().into_bytes(),
                specification.spec().network_profile().endpoint_ids())
        })());
        if !matches!(self.body, Some(Ok(_))) { self.first = Some(First::Body); return Err(CLOSED); }
        Ok(())
    }

    pub(crate) fn retain_content_after_v2(&mut self, after: Result<(), ResourceReservationErrorV1>) {
        if self.content_after.is_some() { std::process::abort(); }
        let failed = after.is_err();
        self.content_after = Some(after);
        if failed { self.first.get_or_insert(First::ContentAfter); }
    }

    /// Borrows only the actual all-posts completed content request for Root.
    ///
    /// # Errors
    /// Refuses content/native failure or an incomplete source/encoder prefix.
    pub fn deadline_free_request_body_v2(&self) -> Result<&[u8], PreparedStartResourceRequestClosedV2> {
        if self.first.is_some() || !matches!(self.content_after, Some(Ok(()))) { return Err(CLOSED); }
        match self.purpose {
            Purpose::NetworkPrepare => self.body.as_ref().and_then(|value| value.as_ref().ok()),
            Purpose::MountNamespace => self.mount_body.as_ref().and_then(|value| value.as_ref().ok()),
            Purpose::StorageGuestRoot => self.storage_body.as_ref().and_then(|value| value.as_ref().ok()),
            Purpose::HostLaunch => self.host.body.as_ref().and_then(|value| value.as_ref().ok()),
            _ => None,
        }.map(Vec::as_slice).ok_or(CLOSED)
    }

    pub(crate) fn content_parent_v2(&self) -> Result<aos_sandbox_model::OperationId, ResourceReservationErrorV1> {
        self.deadline_free_request_body_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        self.parent.ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Reconstructs exactly Root's admitted plan under the actual live window.
    ///
    /// Native sealed-file creation follows full model/FD payment and retains
    /// every writer, reader, duplicate, readback and error in the SAME original.
    ///
    /// # Errors
    /// Retains original/currentness/Root identity, geometry/payment, exact input,
    /// unsigned comparison, or native sealing refusal without accepting a grant.
    #[doc(hidden)]
    pub fn prepare_admitted_once_v2(&mut self, original: &mut OriginalStartHostRootLoanV1<'_, '_>,
        controller: &Journal, admission: &RootStartResourcePrepareAdmissionOriginalV2<'_>,
        construction: &RootStartResourceConstructionTurnV2<'_>, authority: &SigningAuthority,
        scope: RevocationScopeId,
    ) -> Result<(), PreparedStartResourceRequestClosedV2> {
        if self.first.is_some() || self.model_funding.is_some() { self.first.get_or_insert(First::Reentry); return Err(CLOSED); }
        self.model_funding = Some((|| {
            construction.require_admission_v2(admission, original, controller, false)?;
            if admission.purpose_data_v2()? != self.purpose { return Err(ResourceReservationErrorV1::Conflict); }
            let body = self.deadline_free_request_body_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            if admission.parent_operation_v1() != self.parent.ok_or(ResourceReservationErrorV1::Conflict)?
                || admission.request_body_v1().map_err(|_| ResourceReservationErrorV1::Conflict)? != body {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            let reply = admission.reply_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let content = match self.purpose {
                Purpose::NetworkPrepare => self.content.as_ref().and_then(|value| value.as_ref().ok())
                    .map(Vec::as_slice).ok_or(ResourceReservationErrorV1::Conflict)?,
                Purpose::MountNamespace | Purpose::StorageGuestRoot | Purpose::HostLaunch => &[],
                _ => return Err(ResourceReservationErrorV1::Conflict),
            };
            let (_, spec) = original.start_assignment_v2(controller)?;
            let model = if self.purpose == Purpose::HostLaunch {
                aos_sandbox_protocol::authorization_artifact::start_resource_plan::
                    host_launch_pair_admitted_receiving_demand_v2(body.len(),
                        reply.canonical_plan.len(), reply.canonical_statement.len(),
                        admission.lease_v1(), authority)
            } else if self.purpose == Purpose::StorageGuestRoot {
                aos_sandbox_protocol::authorization_artifact::start_resource_plan::
                    start_storage_guest_root_normalization_receiving_demand_v2(
                        body.len(), reply.canonical_plan.len(), reply.canonical_statement.len(),
                        admission.lease_v1(), authority)
            } else {
                aos_sandbox_protocol::authorization_artifact::start_resource_plan::start_network_normalization_receiving_demand_v2(
                    body.len(), content.len(), spec.canonical_bytes().len(),
                    reply.canonical_plan.len(), reply.canonical_statement.len(),
                    admission.lease_v1(), authority)
            }.ok_or(ResourceReservationErrorV1::Conflict)?;
            if self.purpose == Purpose::HostLaunch {
                self.host.io_receiving = Some(model);
            }
            // The Runtime's retained signing slot and Protocol model buffers
            // do not cover the actual key/message constructor overlap.
            let signing = aos_sandbox_broker::prepared_plan_signing::PreparedBrokerPlanSigningV1::
                receiving_construction_bytes_v1().ok_or(ResourceReservationErrorV1::Conflict)?;
            let model = if self.purpose == Purpose::MountNamespace {
                model.checked_add(aos_sandbox_protocol::authorization_artifact::start_resource_plan::
                    start_mount_request_receiving_demand_v2(spec.canonical_bytes().len())
                    .ok_or(ResourceReservationErrorV1::Conflict)?)?
            } else { model };
            let signing = if self.purpose == Purpose::HostLaunch {
                signing.checked_mul(2).ok_or(ResourceReservationErrorV1::Conflict)?
            } else { signing };
            let model = model.checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
                u64::try_from(signing).map_err(|_| ResourceReservationErrorV1::Conflict)?))?;
            let resident = if self.purpose == Purpose::NetworkPrepare {
            let seal = SealedReadOnlyCredentialCreateOriginalsV1::receiving_footprint_v1(CONTENT_NAME.len(), content.len())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
                model.checked_add(ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(seal.memory_bytes)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?)
                .with(D::OpenFiles, u64::try_from(seal.open_files)
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?))?
            } else { model };
            self.model_resident = Some(resident);
            let demand = construction.receiving_demand_v2()?.checked_add(resident)?;
            self.root_commitment = Some(reply.digest_v1().map_err(|_| ResourceReservationErrorV1::Conflict)?);
            self.construction_turn = Some(original.native_turn_v1());
            let returned = original.require_complete_v1(controller, demand);
            self.original_selected = returned.is_err() && original.failure_v1().is_some();
            returned
        })());
        if !matches!(self.model_funding, Some(Ok(()))) { self.first = Some(First::ModelFunding); return Err(CLOSED); }
        self.normalization = Some((|| {
            let (manifest, spec) = original.start_assignment_v2(controller)?;
            let reply = admission.reply_v1()?;
            let temporal = aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourceAdmissionDataV1::decode_v1(reply.admission)?;
            if self.purpose == Purpose::HostLaunch {
                return aos_sandbox_protocol::authorization_artifact::prepare_admitted_host_launch_plan_v2(
                    self.deadline_free_request_body_v2()?, manifest, spec.spec().resource_profile(),
                    self.host.catalog.catalog_data_v2(original, controller)?,
                    manifest.manifest().policy().digest(), admission.lease_v1(),
                    construction.actual_before_clock_v2()?, construction.cutoff_v2()?,
                    temporal.policy_expires_seconds, original.start_origin_data_v1().accepted_v1(),
                    authority.clone(), scope, reply.canonical_plan, reply.canonical_statement,
                ).map(NormalizedStartResourceV2::Host);
            }
            if self.purpose == Purpose::StorageGuestRoot {
                return aos_sandbox_protocol::authorization_artifact::start_resource_plan::
                    prepare_admitted_start_storage_guest_root_plan_v2(
                        self.deadline_free_request_body_v2()?,
                        self.storage_arguments.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?,
                        manifest, manifest.manifest().policy().digest(), admission.lease_v1(),
                        construction.actual_before_clock_v2()?, construction.cutoff_v2()?,
                        temporal.policy_expires_seconds, authority.clone(), scope,
                        reply.canonical_plan, reply.canonical_statement,
                    ).map(NormalizedStartResourceV2::Resource);
            }
            if self.purpose == Purpose::MountNamespace {
                return aos_sandbox_protocol::authorization_artifact::start_resource_plan::
                    prepare_admitted_start_mount_plan_v2(
                        self.deadline_free_request_body_v2()?, original.parent_operation_v1().into_bytes(),
                        manifest, spec.descriptor(), spec.spec(), admission.lease_v1(),
                        construction.actual_before_clock_v2()?, construction.cutoff_v2()?,
                        temporal.policy_expires_seconds, authority.clone(), scope, reply.canonical_plan, reply.canonical_statement,
                    ).map(NormalizedStartResourceV2::Resource);
            }
            prepare_admitted_start_network_plan_v2(
                self.body.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?,
                self.content.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?,
                manifest, spec.spec(), manifest.manifest().policy().digest(),
                admission.lease_v1(), construction.actual_before_clock_v2()?, construction.cutoff_v2()?,
                temporal.policy_expires_seconds, authority.clone(), scope,
                reply.canonical_plan, reply.canonical_statement,
            ).map(NormalizedStartResourceV2::Resource)
        })());
        if !matches!(self.normalization, Some(Ok(_))) { self.first = Some(First::Normalization); return Err(CLOSED); }
        if self.purpose != Purpose::NetworkPrepare { return Ok(()); }
        let content = self.content.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
        self.seal = Some(self.sealing.create_once(CONTENT_NAME, content, NetworkPreparationContentV2::maximum_encoded_bytes()));
        if !matches!(self.seal, Some(Ok(()))) { self.first = Some(First::Seal); return Err(CLOSED); }
        Ok(())
    }

    /// Borrows exactly the normalized plan beside genuine Root construction.
    ///
    /// # Errors
    /// Refuses another parent/reply, failed sealing or noncurrent Root/Start turn.
    #[doc(hidden)]
    pub fn signing_preparation_v2<'held>(&'held self,
        admission: &RootStartResourcePrepareAdmissionOriginalV2<'_>,
        construction: &RootStartResourceConstructionTurnV2<'_>,
        original: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<&'held BrokerPlanPreparation, PreparedStartResourceRequestClosedV2> {
        construction.require_admission_v2(admission, original, controller, false).map_err(|_| CLOSED)?;
        let reply = admission.reply_v1().map_err(|_| CLOSED)?;
        if self.first.is_some() || !self.descriptor_complete_v2()
            || self.parent != Some(admission.parent_operation_v1())
            || self.root_commitment != Some(reply.digest_v1().map_err(|_| CLOSED)?)
            || self.construction_turn != Some(original.native_turn_v1()) { return Err(CLOSED); }
        self.normalization.as_ref().and_then(|value| value.as_ref().ok()).map(NormalizedStartResourceV2::preparation_v2).ok_or(CLOSED)
    }

    /// Retains the same verified signer result only after the final paid clock.
    ///
    /// # Errors
    /// Refuses a foreign plan, invalid current window, expiry or repeated entry.
    #[doc(hidden)]
    pub fn retain_signed_once_v2(&mut self, signed: &SignedBrokerPlan,
        admission: &RootStartResourcePrepareAdmissionOriginalV2<'_>,
        construction: &RootStartResourceConstructionTurnV2<'_>,
        original: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<(), PreparedStartResourceRequestClosedV2> {
        if self.signed_check.is_some() { self.first.get_or_insert(First::Reentry); return Err(CLOSED); }
        if self.purpose == Purpose::HostLaunch && self.host.guardian.is_none() {
            self.first.get_or_insert(First::Signed);
            return Err(CLOSED);
        }
        self.signed_check = Some((|| {
            construction.require_admission_v2(admission, original, controller, true)?;
            let preparation = self.signing_preparation_v2(admission, construction, original, controller)
                .map_err(|_| ResourceReservationErrorV1::Conflict)?;
            let sample = construction.actual_before_clock_v2()?;
            if signed.canonical_plan() != preparation.canonical_plan()
                || signed.plan() != preparation.plan_data_v1()
                || sample.wall_seconds() < signed.plan().issued_seconds()
                || sample.wall_seconds() >= signed.plan().expires_seconds() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(())
        })());
        if !matches!(self.signed_check, Some(Ok(()))) { self.first = Some(First::Signed); return Err(CLOSED); }
        // The full artifact clone was priced by the shared format supplier;
        // the actual Runtime signer keeps its own whole completion Result.
        self.signed = Some(signed.clone());
        if self.purpose == Purpose::HostLaunch {
            self.host.live_body = Some((|| -> Result<_, Cause> {
                let normalized = self.normalization.as_ref().and_then(|value| value.as_ref().ok()).ok_or(CLOSED)?;
                let guardian = self.host.guardian.as_ref().ok_or(CLOSED)?;
                let deadline = normalized.header_v2().deadline_boottime_nanoseconds;
                let body = aos_sandbox_protocol::dispatch_template::inject_deadline(
                    self.deadline_free_request_body_v2()?, deadline)?;
                Ok(aos_sandbox_protocol::encode_host_guardian_companion_v1(&body,
                    guardian.canonical_plan(), guardian.canonical_signature())?)
            })());
            if !matches!(self.host.live_body, Some(Ok(_))) {
                self.first = Some(First::Signed);
                return Err(CLOSED);
            }
        }
        Ok(())
    }

    /// Rejoins all actual C/Root construction posts before exposing the file.
    ///
    /// # Errors
    /// Refuses failed/missing signing, a foreign root or incomplete native posts.
    #[doc(hidden)]
    pub fn finish_construction_after_posts_once_v2(&mut self,
        client: &RootHostLaunchClientOriginalV1, entry: &mut AcceptedStartEntryOriginalV1,
        controller: &Journal,
    ) -> Result<(), PreparedStartResourceRequestClosedV2> {
        if self.construction_after.is_some() { self.first.get_or_insert(First::Reentry); return Err(CLOSED); }
        self.construction_after = Some((|| {
            if self.first.is_some() || self.signed.is_none() { return Err(ResourceReservationErrorV1::Conflict); }
            client.require_completed_resource_construction_v2(entry, controller, self.purpose,
                self.parent.ok_or(ResourceReservationErrorV1::Conflict)?,
                self.root_commitment.ok_or(ResourceReservationErrorV1::Conflict)?,
                self.construction_turn.ok_or(ResourceReservationErrorV1::Conflict)?)?;
            if self.purpose == Purpose::HostLaunch {
                self.publication.finish_after_posts_once_v2(client, entry, controller)?;
            }
            let model = self.model_resident.ok_or(ResourceReservationErrorV1::Conflict)?;
            let native = entry.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
            let kind = match self.purpose {
                aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1::NetworkPrepare => resource_state::StartResourceKindV2::Network,
                aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1::MountNamespace => resource_state::StartResourceKindV2::Mount,
                aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1::StorageGuestRoot => resource_state::StartResourceKindV2::Storage,
                aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1::HostLaunch => resource_state::StartResourceKindV2::Host,
            };
            let member = native.resources.member_mut_v2(kind);
            if member.preparation_resident.is_some() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            member.preparation_resident = Some(model);
            Ok(())
        })());
        if !matches!(self.construction_after, Some(Ok(()))) { self.first.get_or_insert(First::ConstructionAfter); return Err(CLOSED); }
        Ok(())
    }

    pub(super) fn dispose_completed_representation_v2(&mut self) {
        // The genuine completed Root owner already retains all four signed
        // packets. The actual caller has physically disposed the SDK first.
        *self = Self::new();
    }

    pub(crate) fn completed_root_binding_v2(&self)
        -> Result<(aos_sandbox_model::OperationId, [u8; 32], u64, i64), ResourceReservationErrorV1> {
        self.require_completed_v2().map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let signed = self.signed.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok((self.parent.ok_or(ResourceReservationErrorV1::Conflict)?,
            self.root_commitment.ok_or(ResourceReservationErrorV1::Conflict)?,
            self.construction_turn.ok_or(ResourceReservationErrorV1::Conflict)?,
            signed.plan().expires_seconds()))
    }

    /// Borrows the SAME completed sealed credential retained by this owner.
    ///
    /// # Errors
    /// Refuses incomplete signature/native posts or any retained native failure.
    pub fn sealed_content_v2(&self) -> Result<&SealedReadOnlyCredential, PreparedStartResourceRequestClosedV2> {
        self.require_completed_v2()?;
        self.sealing.completed().ok_or(CLOSED)
    }

    pub(crate) fn require_completed_v2(&self) -> Result<(), PreparedStartResourceRequestClosedV2> {
        if self.first.is_some() || !matches!(self.construction_after, Some(Ok(()))) || self.signed.is_none() { Err(CLOSED) } else { Ok(()) }
    }

    /// Borrows the genuine signed canonical broker plan without adopting bytes.
    ///
    /// # Errors
    /// Refuses incomplete construction or any earlier failure.
    pub fn signed_plan_v2(&self) -> Result<&SignedBrokerPlan, PreparedStartResourceRequestClosedV2> {
        self.require_completed_v2()?;
        self.signed.as_ref().ok_or(CLOSED)
    }

    /// Borrows fixed request coordinates retained by the sole normalizer.
    ///
    /// This DATA comes from its actual decoded canonical body and original
    /// deadline injection. It supplies no parsed header, peer or grant and
    /// performs no second body decode or native work.
    ///
    /// # Errors
    /// Refuses incomplete construction or any earlier signature/native failure.
    pub fn request_header_v2(&self)
        -> Result<&aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2,
            PreparedStartResourceRequestClosedV2> {
        self.require_completed_v2()?;
        self.normalization.as_ref().and_then(|value| value.as_ref().ok())
            .map(NormalizedStartResourceV2::header_v2).ok_or(CLOSED)
    }

    /// Borrows only the exact deadline-injected request returned by normalization.
    ///
    /// # Errors
    /// Refuses incomplete construction or any earlier failure.
    pub fn request_body_v2(&self) -> Result<&[u8], PreparedStartResourceRequestClosedV2> {
        self.require_completed_v2()?;
        if self.purpose == Purpose::HostLaunch {
            return self.host.live_body.as_ref().and_then(|value| value.as_ref().ok())
                .map(Vec::as_slice).ok_or(CLOSED);
        }
        self.normalization.as_ref().and_then(|value| value.as_ref().ok())
            .and_then(NormalizedStartResourceV2::resource_body_v2).ok_or(CLOSED)
    }

    /// Borrows the first original constructor/native cause without allocation.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Host => self.host.failure_v2(),
            First::Publication => self.publication.failure_v2(),
            First::Reentry => Some(&CLOSED as &(dyn Error + 'static)),
            First::ContentFunding => error(&self.content_funding),
            First::Content => error(&self.content),
            First::Reference => error(&self.reference),
            First::Body => error(&self.body),
            First::MountBody => self.mount_body.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::StorageArguments => self.storage_arguments.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::StorageBody => self.storage_body.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::ContentAfter => error(&self.content_after),
            First::ModelFunding => error(&self.model_funding),
            First::Inputs => error(&self.input),
            First::Normalization => self.normalization.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::Seal => self.sealing.failure().or_else(|| error(&self.seal)),
            First::Signed => self.host.failure_v2().or_else(|| error(&self.signed_check)),
            First::ConstructionAfter => error(&self.construction_after),
        }.or(Some(&CLOSED))
    }
}

impl Default for PreparedStartResourceRequestOriginalV2 { fn default() -> Self { Self::new() } }

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

const CLOSED: PreparedStartResourceRequestClosedV2 = PreparedStartResourceRequestClosedV2;


/// Keeps the exact once-only content interval beside the actual Start owner.
#[derive(Default)]
pub(super) struct ResourceContentTurnOriginalV2 {
    demand: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    next: Option<Result<(), ResourceReservationErrorV1>>,
    body: Option<Result<(), ContentEntryFailureV2>>,
    after: Option<Result<(), ResourceReservationErrorV1>>,
    resident: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    selected_native: bool,
    selected_preparation: bool,
    entered: bool,
}

#[derive(Debug, thiserror::Error)]
enum ContentEntryFailureV2 {
    #[error(transparent)]
    Loan(ResourceReservationErrorV1),
    #[error(transparent)]
    Preparation(PreparedStartResourceRequestClosedV2),
}

impl ResourceContentTurnOriginalV2 {
    pub(super) fn native_failure_is_selected_v2(&self) -> bool { self.selected_native }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if self.selected_preparation {
            return error(&self.body);
        }
        error(&self.demand)
            .or_else(|| error(&self.next))
            .or_else(|| error(&self.body))
            .or_else(|| error(&self.after))
            .or_else(|| error(&self.resident))
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Constructs the exact Network content before its first Root child opens.
    ///
    /// The original manifest and Spec lend only immutable historical input.
    /// Fresh Start C pays their canonical construction before native entry and
    /// retains the complete body result before its independently owed C post.
    /// The completed resident invoice is then joined into every later turn.
    ///
    /// # Errors
    /// Retains original affinity, geometry, native entry, encoding and post
    /// refusal without opening Root or replacing any content/native owner.
    #[doc(hidden)]
    pub fn prepare_network_content_once_v2(
        &mut self,
        prepared: &mut PreparedStartResourceRequestOriginalV2,
        intake: &crate::CreateContinuationIntakeAttemptV1,
        controller: &mut Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.prepare_resource_content_once_v2(resource_state::StartResourceKindV2::Network,
            prepared, intake, controller, source)
    }

    /// Enters storage content only after the genuine immediate predecessor retired.
    ///
    /// The completion is checked at its original C ordinal before any next
    /// native entry. A retained digest or an undisposed SDK cannot select it.
    ///
    /// # Errors
    /// Retains a changed or incomplete predecessor, reentry, or native failure.
    #[doc(hidden)]
    pub fn prepare_storage_content_once_v2(
        &mut self,
        prepared: &mut PreparedStartResourceRequestOriginalV2,
        predecessor: &crate::normal_root::RootStartResourceCompletedOriginalV2,
        intake: &crate::CreateContinuationIntakeAttemptV1,
        controller: &mut Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let kind = resource_state::StartResourceKindV2::Storage;
        if self.failure().is_some() || self.resource_entries.member_v2(kind).predecessor.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.resource_entries.member_mut_v2(kind).predecessor = Some((|| {
            predecessor.require_network_disposition_v2(self, controller)?;
            if self.native_state.as_ref().is_none_or(|state|
                state.resources.network.completed_resident.is_none()) {
                return Err(crate::normal_root::RootHostLaunchClientClosedV1);
            }
            Ok(())
        })());
        if !matches!(self.resource_entries.member_v2(kind).predecessor, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.prepare_resource_content_once_v2(kind, prepared, intake, controller, source)
    }

    /// Enters mount content only after the genuine immediate predecessor retired.
    ///
    /// The completion is checked at its original C ordinal before any next
    /// native entry. A retained digest or an undisposed SDK cannot select it.
    ///
    /// # Errors
    /// Retains a changed or incomplete predecessor, reentry, or native failure.
    #[doc(hidden)]
    pub fn prepare_mount_content_once_v2(
        &mut self,
        prepared: &mut PreparedStartResourceRequestOriginalV2,
        predecessor: &crate::normal_root::RootStartResourceCompletedOriginalV2,
        intake: &crate::CreateContinuationIntakeAttemptV1,
        controller: &mut Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let kind = resource_state::StartResourceKindV2::Mount;
        if self.failure().is_some() || self.resource_entries.member_v2(kind).predecessor.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.resource_entries.member_mut_v2(kind).predecessor = Some((|| {
            predecessor.require_storage_disposition_v2(self, controller)?;
            if self.native_state.as_ref().is_none_or(|state|
                state.resources.storage.completed_resident.is_none()) {
                return Err(crate::normal_root::RootHostLaunchClientClosedV1);
            }
            Ok(())
        })());
        if !matches!(self.resource_entries.member_v2(kind).predecessor, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.prepare_resource_content_once_v2(kind, prepared, intake, controller, source)
    }

    fn prepare_resource_content_once_v2(
        &mut self, kind: resource_state::StartResourceKindV2,
        prepared: &mut PreparedStartResourceRequestOriginalV2,
        intake: &crate::CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if kind == resource_state::StartResourceKindV2::Host {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let _ = self.begin_resource_content_once_v2(kind, prepared, intake, controller, source);
        if matches!(self.resource_entries.member_v2(kind).content.next, Some(Ok(())))
            && self.resource_entries.member_v2(kind).content.body.is_none()
            && self.resource_entries.member_v2(kind).content.after.is_none()
        {
            self.resource_entries.member_mut_v2(kind).content.body = Some(match self.borrow_host_root_v1(intake, controller, source) {
                Ok(mut original) => prepared.prepare_content_once_v2(&mut original, controller)
                    .map_err(ContentEntryFailureV2::Preparation),
                Err(cause) => Err(ContentEntryFailureV2::Loan(cause)),
            });
            self.resource_entries.member_mut_v2(kind).content.selected_preparation = self.resource_entries.member_mut_v2(kind).content.body.as_ref()
                .is_some_and(Result::is_err) && prepared.failure().is_some();
            self.resource_entries.member_mut_v2(kind).content.selected_native = prepared.original_selected;
        } else {
            self.resource_entries.member_mut_v2(kind).content.selected_native = self.native_state.as_ref()
                .and_then(StartNativeStateV1::native_failure_v1).is_some();
        }
        self.finish_resource_content_once_v2(kind, prepared, controller)
    }

    fn begin_resource_content_once_v2(
        &mut self, kind: resource_state::StartResourceKindV2,
        prepared: &PreparedStartResourceRequestOriginalV2,
        intake: &crate::CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &crate::source_domain::ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if prepared.purpose_data_v2() != kind.purpose_v2() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if self.failure().is_some() || !self.start_ownership.completed_v1()
            || self.resource_entries.member_mut_v2(kind).content.demand.is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.resource_entries.member_mut_v2(kind).content.demand = Some((|| {
            let state = self.native_state.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            let completed = intake.borrow_completed_provisioning_v1(state.create_parent)?;
            completed.require_original_owners_v1(controller, source, state.profile.as_ref())?;
            let manifest = self.start_assignment.manifest_v2()?;
            let specification = completed.original_specification_v2()?;
            match kind {
                resource_state::StartResourceKindV2::Network =>
                    PreparedStartResourceRequestOriginalV2::content_receiving_data_v2(manifest, specification),
                resource_state::StartResourceKindV2::Mount =>
                    aos_sandbox_protocol::authorization_artifact::start_resource_plan::
                        start_mount_request_receiving_demand_v2(specification.canonical_bytes().len())
                        .ok_or(ResourceReservationErrorV1::Conflict),
                resource_state::StartResourceKindV2::Storage => PreparedStartResourceRequestOriginalV2::storage_request_receiving_demand_v2(),
                resource_state::StartResourceKindV2::Host => {
                    // This same current loan is constructed after native entry;
                    // projection and request models prepay their own growth
                    // through it before their first allocation.
                    let bytes = size_of::<OriginalStartHostRootLoanV1<'_, '_>>().checked_mul(2)
                        .and_then(|bytes| u64::try_from(bytes).ok())
                        .ok_or(ResourceReservationErrorV1::Conflict)?;
                    Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
                }
            }
        })());
        self.resource_entries.member_mut_v2(kind).content.next = Some((|| {
            let demand = *self.resource_entries.member_mut_v2(kind).content.demand.as_ref()
                .and_then(|value| value.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            let state = self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
            let resident = state.history_resident.ok_or(ResourceReservationErrorV1::Conflict)?;
            let returned = state.begin_next_start_native_v1(controller, resident.checked_add(demand)?);
            let entered = state.after.is_none();
            self.resource_entries.member_mut_v2(kind).content.entered = entered;
            returned
        })());
        if matches!(self.resource_entries.member_v2(kind).content.next, Some(Ok(()))) {
            Ok(())
        } else {
            self.resource_entries.member_mut_v2(kind).content.selected_native = self.native_state.as_ref()
                .and_then(StartNativeStateV1::native_failure_v1).is_some();
            Err(ResourceReservationErrorV1::Conflict)
        }
    }

    fn finish_resource_content_once_v2(
        &mut self, kind: resource_state::StartResourceKindV2,
        prepared: &mut PreparedStartResourceRequestOriginalV2,
        controller: &mut Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.resource_entries.member_v2(kind).content.after.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if self.resource_entries.member_v2(kind).content.entered {
            let after = match self.native_state.as_mut() {
                Some(state) => state.finish_native_once_v1(controller),
                None => Err(ResourceReservationErrorV1::Conflict),
            };
            let earlier_failed = self.resource_entries.member_mut_v2(kind).content.failure().is_some();
            let after_failed = after.is_err();
            self.resource_entries.member_mut_v2(kind).content.after = Some(after);
            // The original whole C result stays in its native owner; the two
            // coarse slots preserve scheduling and chronological selection.
            prepared.retain_content_after_v2(if after_failed {
                Err(ResourceReservationErrorV1::Conflict)
            } else {
                Ok(())
            });
            if after_failed && !earlier_failed {
                self.resource_entries.member_mut_v2(kind).content.selected_native = true;
            }
        }
        if self.resource_entries.member_mut_v2(kind).content.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.resource_entries.member_mut_v2(kind).content.resident = Some((|| {
            let demand = *self.resource_entries.member_mut_v2(kind).content.demand.as_ref()
                .and_then(|value| value.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
            if kind == resource_state::StartResourceKindV2::Host {
                return prepared.host.demand.as_ref().and_then(|value| value.as_ref().ok())
                    .copied().ok_or(ResourceReservationErrorV1::Conflict);
            }
            Ok(demand)
        })());
        let resident = *self.resource_entries.member_mut_v2(kind).content.resident.as_ref()
            .and_then(|value| value.as_ref().ok()).ok_or(ResourceReservationErrorV1::Conflict)?;
        self.native_state.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?
            .resources.member_mut_v2(kind).content_resident = Some(resident);
        Ok(())
    }

    /// Selects the retained preparation cause only at the actual content call.
    #[doc(hidden)]
    #[must_use]
    pub fn network_content_failure_is_selected_v2(&self) -> bool {
        self.resource_entries.network.content.selected_preparation && !self.resource_entries.network.content.selected_native
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Selects only the actual Mount content body before independently owed posts.
    #[doc(hidden)]
    #[must_use]
    pub fn mount_content_failure_is_selected_v2(&self) -> bool {
        self.resource_entries.mount.content.selected_preparation
            && !self.resource_entries.mount.content.selected_native
    }
}

impl AcceptedStartEntryOriginalV1 {
    /// Selects only the actual Storage content body before independently owed posts.
    #[doc(hidden)]
    #[must_use]
    pub fn storage_content_failure_is_selected_v2(&self) -> bool {
        self.resource_entries.storage.content.selected_preparation
            && !self.resource_entries.storage.content.selected_native
    }
}
