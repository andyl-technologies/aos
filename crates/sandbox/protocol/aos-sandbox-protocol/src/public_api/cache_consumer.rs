//! Compares public Cache consumer DATA without granting pin or journal authority.
//!
//! Native owners select and decode each projection at its existing health
//! frontier. These finite comparisons preserve View, Attachment and Sandbox
//! ordering; supplied models never construct a native Controller borrower.

use aos_sandbox_api::aos::sandbox::v1::{
    Attachment, AttachmentPhase, FilesystemView, MutationContext,
    ObjectDescriptor as ProtoObjectDescriptor, Sandbox, ViewPhase,
};
use aos_sandbox_model::{
    AttachmentId, IncarnationId, NodeId, ObjectDescriptor, ProjectId, SandboxId, ViewId,
};

use super::request::DormantSandboxRequestKindV1 as Request;

/// Selects acquisition or release comparison rules without authorizing either.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheConsumerMutationDataV1 {
    /// Requires the current ready View and attached runtime.
    Acquire,
    /// Permits draining an older source while retaining exact resource version.
    Release,
}

/// Preserves malformed-request versus rejected-current-state distinctions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CacheConsumerComparisonErrorV1 {
    /// A required feature, identity or request descriptor is malformed.
    #[error("malformed Cache consumer comparison")]
    Malformed,
    /// Current projection DATA do not satisfy the requested comparison.
    #[error("Cache consumer projection comparison rejected")]
    Rejected,
}

use CacheConsumerComparisonErrorV1::{Malformed, Rejected};

/// Retains the exact public cache consumer checked against current desired state.
///
/// This is not source-object membership, protected pin authority, or physical
/// residency evidence. It carries the consumer identity needed to select
/// retained obligations and, for acquisition, the exact desired-state fence
/// that a separately authenticated View source must match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheConsumerDataV1 {
    object: ObjectDescriptor,
    project: ProjectId,
    view: ViewId,
    attachment: Option<AttachmentId>,
    acquisition_fence: Option<CacheAcquisitionFenceDataV1>,
}

/// Retains the current desired-state fence for one public cache pin acquisition.
///
/// The revision and runtime fields must be joined to independent source and
/// protected Cache authority before a pin can be installed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheAcquisitionFenceDataV1 {
    view_revision: ObjectDescriptor,
    view_generation: u64,
    runtime: Option<CacheRuntimeFenceDataV1>,
}

/// Retains the attached runtime identity checked for cache pin acquisition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheRuntimeFenceDataV1 {
    sandbox: SandboxId,
    incarnation: IncarnationId,
    node: NodeId,
    assignment_epoch: u64,
}

impl CacheRuntimeFenceDataV1 {
    /// Returns the Sandbox that owns the current attachment.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the current observed Sandbox incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> IncarnationId {
        self.incarnation
    }

    /// Returns the current observed assignment node.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Returns the current observed assignment epoch.
    #[must_use]
    pub const fn assignment_epoch(&self) -> u64 {
        self.assignment_epoch
    }
}

impl CacheAcquisitionFenceDataV1 {
    /// Returns the exact current portable View revision descriptor.
    #[must_use]
    pub const fn view_revision(&self) -> &ObjectDescriptor {
        &self.view_revision
    }

    /// Returns the current desired generation of that View.
    #[must_use]
    pub const fn view_generation(&self) -> u64 {
        self.view_generation
    }

    /// Returns the attached Sandbox incarnation and assignment epoch, if any.
    #[must_use]
    pub const fn runtime(&self) -> Option<&CacheRuntimeFenceDataV1> {
        self.runtime.as_ref()
    }
}

impl CacheConsumerDataV1 {
    /// Returns the exact immutable object selected by the public request.
    #[must_use]
    pub const fn object(&self) -> &ObjectDescriptor {
        &self.object
    }

    /// Returns the project charged for this logical dependency.
    #[must_use]
    pub const fn project(&self) -> ProjectId {
        self.project
    }

    /// Returns the checked consuming view identity.
    #[must_use]
    pub const fn view(&self) -> ViewId {
        self.view
    }

    /// Returns the checked attached consumer, when one was named.
    #[must_use]
    pub const fn attachment(&self) -> Option<AttachmentId> {
        self.attachment
    }

    /// Returns the acquisition-only View and runtime fence.
    ///
    /// Release intentionally has no acquisition fence: an old attachment
    /// source may still hold a pin after the current View revision changes.
    #[must_use]
    pub const fn acquisition_fence(&self) -> Option<&CacheAcquisitionFenceDataV1> {
        self.acquisition_fence.as_ref()
    }
}

/// Borrows one finite comparison's request DATA; it owns no projection or lease.
pub struct CacheConsumerComparisonDataV1<'request> {
    project: ProjectId,
    view_id: &'request [u8],
    attachment_id: &'request [u8],
    mutation: &'request MutationContext,
    kind: CacheConsumerMutationDataV1,
}

impl<'request> CacheConsumerComparisonDataV1<'request> {
    /// Checks the feature and View identity before the first native read.
    ///
    /// # Errors
    /// Returns `Malformed` for missing features, mutation or nonzero View identity.
    pub fn new(
        project: ProjectId,
        view_id: &'request [u8],
        attachment_id: &'request [u8],
        mutation: Option<&'request MutationContext>,
        kind: CacheConsumerMutationDataV1,
    ) -> Result<Self, CacheConsumerComparisonErrorV1> {
        let mutation = mutation.ok_or(Malformed)?;
        if !super::contains_semantic_features_v1(
            &mutation.required_features,
            &[super::CACHE_CONSUMER_PIN_FEATURE_V1],
        ) {
            return Err(Malformed);
        }
        exact_id(view_id)?;
        Ok(Self {
            project,
            view_id,
            attachment_id,
            mutation,
            kind,
        })
    }

    /// Selects Cache request DATA without decoding its object descriptor early.
    ///
    /// # Errors
    /// Rejects non-Cache requests and malformed feature or View identity DATA.
    pub fn from_request(
        project: ProjectId,
        request: &'request Request,
    ) -> Result<(Self, Option<&'request ProtoObjectDescriptor>), CacheConsumerComparisonErrorV1>
    {
        let (object, view, attachment, mutation, kind) = match request {
            Request::CachePin(value) => (
                value.object.as_option(),
                value.view_id.as_slice(),
                value.attachment_id.as_slice(),
                value.mutation.as_option(),
                CacheConsumerMutationDataV1::Acquire,
            ),
            Request::CacheUnpin(value) => (
                value.object.as_option(),
                value.view_id.as_slice(),
                value.attachment_id.as_slice(),
                value.mutation.as_option(),
                CacheConsumerMutationDataV1::Release,
            ),
            _ => return Err(Rejected),
        };
        Ok((
            Self::new(project, view, attachment, mutation, kind)?,
            object,
        ))
    }

    /// Returns the checked View key as comparison DATA.
    #[must_use]
    pub fn view_id_data_v1(&self) -> [u8; 16] {
        // The constructor checked this exact immutable slice.
        let mut id = [0; 16];
        id.copy_from_slice(self.view_id);
        id
    }

    /// Compares the decoded View before any Attachment lookup.
    ///
    /// # Errors
    /// Rejects another project or an acquisition against a non-current View.
    pub fn compare_view_data_v1(
        &self,
        view: &FilesystemView,
    ) -> Result<(), CacheConsumerComparisonErrorV1> {
        if view.project_id.as_slice() != self.project.as_bytes() {
            return Err(Rejected);
        }
        if self.kind == CacheConsumerMutationDataV1::Acquire
            && (view.revision.as_option().is_none()
                || view.desired_generation == 0
                || !matches!(
                    view.phase.as_known(),
                    Some(ViewPhase::VIEW_PHASE_READY | ViewPhase::VIEW_PHASE_DEGRADED)
                ))
        {
            return Err(Rejected);
        }
        Ok(())
    }

    /// Selects the optional Attachment only after the View comparison.
    ///
    /// # Errors
    /// Returns `Malformed` for a nonempty invalid Attachment identity.
    pub fn attachment_id_data_v1(
        &self,
    ) -> Result<Option<[u8; 16]>, CacheConsumerComparisonErrorV1> {
        if self.attachment_id.is_empty() {
            Ok(None)
        } else {
            exact_id(self.attachment_id).map(Some)
        }
    }

    /// Selects the Sandbox from the actual decoded Attachment DATA.
    ///
    /// # Errors
    /// Returns `Malformed` when the Attachment's Sandbox identity is invalid.
    pub fn sandbox_id_data_v1(
        &self,
        attachment: &Attachment,
    ) -> Result<[u8; 16], CacheConsumerComparisonErrorV1> {
        exact_id(&attachment.sandbox_id)
    }

    /// Compares the unattached View version at the old branch frontier.
    ///
    /// # Errors
    /// Rejects an attached selector or a mismatched View resource version.
    pub fn compare_unattached_resource_data_v1(
        &self,
        view: &FilesystemView,
    ) -> Result<(), CacheConsumerComparisonErrorV1> {
        if !self.attachment_id.is_empty() {
            return Err(Rejected);
        }
        self.compare_resource_version(&view.resource_version)
    }

    /// Compares attached runtime and version DATA before releasing both models.
    ///
    /// The returned identity contains no projection borrow or dynamic backing.
    /// Native callers end the Attachment/Sandbox owning scope before the later
    /// View revision descriptor conversion in `finish_projection_data_v1`.
    ///
    /// # Errors
    /// Preserves malformed runtime identities and rejected project, attachment,
    /// assignment and resource-version comparisons. Release returns no runtime.
    pub fn compare_attached_runtime_data_v1(
        &self,
        view: &FilesystemView,
        attachment: &Attachment,
        sandbox: &Sandbox,
    ) -> Result<Option<CacheRuntimeFenceDataV1>, CacheConsumerComparisonErrorV1> {
        if self.attachment_id.is_empty() {
            return Err(Rejected);
        }
        let mut runtime = None;
        if sandbox.project_id.as_slice() != self.project.as_bytes() {
            return Err(Rejected);
        }
        if self.kind == CacheConsumerMutationDataV1::Acquire {
            let observed = sandbox.observed.as_option().ok_or(Rejected)?;
            if attachment.source_view_id != self.view_id
                || attachment.view_revision.as_option() != view.revision.as_option()
                || attachment.source_generation != view.desired_generation
                || attachment.phase.as_known() != Some(AttachmentPhase::ATTACHMENT_PHASE_READY)
                || attachment.assignment_epoch == 0
                || attachment.assignment_epoch != observed.assignment_epoch
                || exact_id(&observed.incarnation_id).is_err()
                || exact_id(&observed.node_id).is_err()
            {
                return Err(Rejected);
            }
            runtime = Some(CacheRuntimeFenceDataV1 {
                sandbox: SandboxId::from_bytes(exact_id(&attachment.sandbox_id)?),
                incarnation: IncarnationId::from_bytes(exact_id(&observed.incarnation_id)?),
                node: NodeId::from_bytes(exact_id(&observed.node_id)?),
                assignment_epoch: attachment.assignment_epoch,
            });
        }
        self.compare_resource_version(&attachment.resource_version)?;
        Ok(runtime)
    }

    /// Converts the View fence after Attachment and Sandbox models are dropped.
    ///
    /// Callers retain only runtime identity DATA from the earlier comparison.
    /// This method takes no Attachment or Sandbox borrow and grants no authority.
    ///
    /// # Errors
    /// Rejects a missing or invalid acquisition revision. Release returns no
    /// acquisition fence without allocating a View descriptor.
    pub fn finish_projection_data_v1(
        &self,
        view: &FilesystemView,
        runtime: Option<CacheRuntimeFenceDataV1>,
    ) -> Result<Option<CacheAcquisitionFenceDataV1>, CacheConsumerComparisonErrorV1> {
        if self.kind == CacheConsumerMutationDataV1::Release {
            return Ok(None);
        }
        let revision = view.revision.as_option().ok_or(Rejected)?;
        let view_revision = super::mutation::object_descriptor(revision).map_err(|_| Rejected)?;
        Ok(Some(CacheAcquisitionFenceDataV1 {
            view_revision,
            view_generation: view.desired_generation,
            runtime,
        }))
    }

    /// Converts the request object only after all current projection comparisons.
    ///
    /// # Errors
    /// Returns `Malformed` for a missing or invalid request object or identity.
    pub fn finish_consumer_data_v1(
        &self,
        object: Option<&ProtoObjectDescriptor>,
        acquisition_fence: Option<CacheAcquisitionFenceDataV1>,
    ) -> Result<CacheConsumerDataV1, CacheConsumerComparisonErrorV1> {
        let object =
            super::mutation::object_descriptor(object.ok_or(Malformed)?).map_err(|_| Malformed)?;
        let attachment = if self.attachment_id.is_empty() {
            None
        } else {
            Some(AttachmentId::from_bytes(exact_id(self.attachment_id)?))
        };
        Ok(CacheConsumerDataV1 {
            object,
            project: self.project,
            view: ViewId::from_bytes(exact_id(self.view_id)?),
            attachment,
            acquisition_fence,
        })
    }

    fn compare_resource_version(
        &self,
        resource_version: &[u8],
    ) -> Result<(), CacheConsumerComparisonErrorV1> {
        if self.mutation.expected_resource_version == resource_version {
            Ok(())
        } else {
            Err(Rejected)
        }
    }
}

fn exact_id(value: &[u8]) -> Result<[u8; 16], CacheConsumerComparisonErrorV1> {
    value
        .try_into()
        .ok()
        .filter(|id| *id != [0; 16])
        .ok_or(Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_api::aos::sandbox::v1::{Feature, SandboxObservedState};

    fn mutation(version: u8) -> MutationContext {
        MutationContext {
            required_features: vec![Feature {
                namespace: super::super::CACHE_CONSUMER_PIN_FEATURE_V1.to_owned(),
                major: 1,
                minor: 0,
                ..Default::default()
            }],
            expected_resource_version: vec![version],
            ..Default::default()
        }
    }

    fn descriptor() -> ProtoObjectDescriptor {
        ProtoObjectDescriptor {
            sha256: vec![9; 32],
            encoded_size: 17,
            media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
            ..Default::default()
        }
    }

    fn view(project: ProjectId) -> FilesystemView {
        FilesystemView {
            project_id: project.as_bytes().to_vec(),
            phase: ViewPhase::VIEW_PHASE_READY.into(),
            revision: Some(descriptor()).into(),
            desired_generation: 7,
            resource_version: vec![3],
            ..Default::default()
        }
    }

    #[test]
    fn malformed_features_precede_view_identity_and_projection_work() {
        let mutation = MutationContext::default();
        let result = CacheConsumerComparisonDataV1::new(
            ProjectId::from_bytes([1; 16]),
            &[],
            &[],
            Some(&mutation),
            CacheConsumerMutationDataV1::Acquire,
        );
        assert!(matches!(result, Err(Malformed)));
    }

    #[test]
    fn rejected_view_precedes_malformed_attachment_and_request_object() {
        let project = ProjectId::from_bytes([1; 16]);
        let mutation = mutation(3);
        let comparison = CacheConsumerComparisonDataV1::new(
            project,
            &[2; 16],
            &[4],
            Some(&mutation),
            CacheConsumerMutationDataV1::Acquire,
        )
        .unwrap();
        let mut view = view(project);
        view.desired_generation = 0;

        assert_eq!(comparison.compare_view_data_v1(&view), Err(Rejected));
        assert_eq!(comparison.attachment_id_data_v1(), Err(Malformed));
        assert_eq!(
            comparison.finish_consumer_data_v1(None, None),
            Err(Malformed)
        );
    }

    #[test]
    fn unattached_acquisition_keeps_exact_view_fence_and_late_object_check() {
        let project = ProjectId::from_bytes([1; 16]);
        let mutation = mutation(3);
        let comparison = CacheConsumerComparisonDataV1::new(
            project,
            &[2; 16],
            &[],
            Some(&mutation),
            CacheConsumerMutationDataV1::Acquire,
        )
        .unwrap();
        let view = view(project);
        comparison.compare_view_data_v1(&view).unwrap();
        assert_eq!(comparison.attachment_id_data_v1().unwrap(), None);
        comparison
            .compare_unattached_resource_data_v1(&view)
            .unwrap();
        let fence = comparison
            .finish_projection_data_v1(&view, None)
            .unwrap()
            .unwrap();
        assert_eq!(fence.view_generation(), 7);
        assert!(fence.runtime().is_none());
        assert_eq!(
            comparison.finish_consumer_data_v1(None, Some(fence.clone())),
            Err(Malformed)
        );

        let consumer = comparison
            .finish_consumer_data_v1(Some(&descriptor()), Some(fence))
            .unwrap();
        assert_eq!(consumer.project(), project);
        assert_eq!(consumer.view(), ViewId::from_bytes([2; 16]));
        assert!(consumer.attachment().is_none());
        assert!(consumer.acquisition_fence().is_some());
    }

    #[test]
    fn release_drains_older_attachment_but_keeps_project_and_version() {
        let project = ProjectId::from_bytes([1; 16]);
        let mutation = mutation(5);
        let comparison = CacheConsumerComparisonDataV1::new(
            project,
            &[2; 16],
            &[4; 16],
            Some(&mutation),
            CacheConsumerMutationDataV1::Release,
        )
        .unwrap();
        let view = FilesystemView {
            project_id: project.as_bytes().to_vec(),
            ..Default::default()
        };
        let mut attachment = Attachment {
            sandbox_id: vec![6; 16],
            resource_version: vec![5],
            ..Default::default()
        };
        let mut sandbox = Sandbox {
            project_id: project.as_bytes().to_vec(),
            ..Default::default()
        };

        comparison.compare_view_data_v1(&view).unwrap();
        assert_eq!(comparison.sandbox_id_data_v1(&attachment).unwrap(), [6; 16]);
        assert_eq!(
            comparison
                .compare_attached_runtime_data_v1(&view, &attachment, &sandbox)
                .and_then(|runtime| comparison.finish_projection_data_v1(&view, runtime)),
            Ok(None)
        );
        attachment.resource_version = vec![8];
        assert_eq!(
            comparison
                .compare_attached_runtime_data_v1(&view, &attachment, &sandbox)
                .and_then(|runtime| comparison.finish_projection_data_v1(&view, runtime)),
            Err(Rejected)
        );
        attachment.resource_version = vec![5];
        sandbox.project_id = vec![8; 16];
        assert_eq!(
            comparison
                .compare_attached_runtime_data_v1(&view, &attachment, &sandbox)
                .and_then(|runtime| comparison.finish_projection_data_v1(&view, runtime)),
            Err(Rejected)
        );
    }

    #[test]
    fn attached_acquisition_rejects_old_assignment_without_hiding_version_check() {
        let project = ProjectId::from_bytes([1; 16]);
        let mutation = mutation(5);
        let comparison = CacheConsumerComparisonDataV1::new(
            project,
            &[2; 16],
            &[4; 16],
            Some(&mutation),
            CacheConsumerMutationDataV1::Acquire,
        )
        .unwrap();
        let view = view(project);
        let mut attachment = Attachment {
            sandbox_id: vec![6; 16],
            source_view_id: vec![2; 16],
            view_revision: Some(descriptor()).into(),
            source_generation: 7,
            phase: AttachmentPhase::ATTACHMENT_PHASE_READY.into(),
            assignment_epoch: 9,
            resource_version: vec![5],
            ..Default::default()
        };
        let sandbox = Sandbox {
            project_id: project.as_bytes().to_vec(),
            observed: Some(SandboxObservedState {
                assignment_epoch: 9,
                incarnation_id: vec![7; 16],
                node_id: vec![8; 16],
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        comparison.compare_view_data_v1(&view).unwrap();
        let fence = comparison
            .compare_attached_runtime_data_v1(&view, &attachment, &sandbox)
            .and_then(|runtime| comparison.finish_projection_data_v1(&view, runtime))
            .unwrap()
            .unwrap();
        let runtime = fence.runtime().unwrap();
        assert_eq!(runtime.assignment_epoch(), 9);
        assert_eq!(runtime.sandbox(), SandboxId::from_bytes([6; 16]));
        assert_eq!(runtime.incarnation(), IncarnationId::from_bytes([7; 16]));
        assert_eq!(runtime.node(), NodeId::from_bytes([8; 16]));

        attachment.assignment_epoch = 10;
        assert_eq!(
            comparison
                .compare_attached_runtime_data_v1(&view, &attachment, &sandbox)
                .and_then(|runtime| comparison.finish_projection_data_v1(&view, runtime)),
            Err(Rejected)
        );
        attachment.assignment_epoch = 9;
        attachment.resource_version = vec![10];
        assert_eq!(
            comparison
                .compare_attached_runtime_data_v1(&view, &attachment, &sandbox)
                .and_then(|runtime| comparison.finish_projection_data_v1(&view, runtime)),
            Err(Rejected)
        );
    }

    #[test]
    fn late_view_descriptor_refusal_needs_no_attached_model_owner() {
        let project = ProjectId::from_bytes([1; 16]);
        let mutation = mutation(5);
        let comparison = CacheConsumerComparisonDataV1::new(
            project,
            &[2; 16],
            &[4; 16],
            Some(&mutation),
            CacheConsumerMutationDataV1::Acquire,
        )
        .unwrap();
        let mut view = view(project);
        view.revision = Some(ProtoObjectDescriptor {
            sha256: vec![0; 32],
            ..descriptor()
        })
        .into();
        comparison.compare_view_data_v1(&view).unwrap();

        // These are supplied pure DATA, not an authenticated projection/native
        // fixture. The native callers use this same finite scope after decoding.
        let runtime = {
            let attachment = Attachment {
                sandbox_id: vec![6; 16],
                source_view_id: vec![2; 16],
                view_revision: view.revision.clone(),
                source_generation: 7,
                phase: AttachmentPhase::ATTACHMENT_PHASE_READY.into(),
                assignment_epoch: 9,
                resource_version: vec![5],
                ..Default::default()
            };
            let sandbox = Sandbox {
                project_id: project.as_bytes().to_vec(),
                observed: Some(SandboxObservedState {
                    assignment_epoch: 9,
                    incarnation_id: vec![7; 16],
                    node_id: vec![8; 16],
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            };
            comparison
                .compare_attached_runtime_data_v1(&view, &attachment, &sandbox)
                .unwrap()
        };

        assert!(runtime.is_some());
        assert_eq!(
            comparison.finish_projection_data_v1(&view, runtime),
            Err(Rejected)
        );
    }
}
