//! Current-Start input custody for the parentless Nix preflight.
//!
//! The protected Controller supplies the exact current assignment and durable
//! specification; the original Source writer supplies its complete Tree replay.
//! A specification is compared as portable output, never inverted into policy
//! layers. Only the independently signed deployment and project sources supply
//! those layers. This precursor is DATA until the enclosing original flight
//! joins the actual Root floor, fresh signatures and complete derivation.

use aos_sandbox_core::{
    CanonicalAssignmentManifestV1, ObjectDescriptor, ObjectDigest, PortableMediaType,
    ProjectId, SandboxId, descriptor_for_bytes, MediaType,
};

use aos_sandbox_protocol::public_api::request::DormantSandboxRequestKindV1;
use aos_sandbox_core::source_tree_model::SandboxTreeRecordV1;
use crate::hierarchy::protected_journal::{
    CurrentNixSourceInventoryAttemptV1, CurrentNixSourceInventoryDataV1, HierarchyProtectedJournalErrorV1,
    capture_current_nix_inventory_v1,
};
use crate::journal::ProtectedJournalNamesV1;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use crate::production_operation_compiler::{NixStartAdmissionCarrierV2, NixStartAdmissionErrorV2};
use crate::reconciler::{PublicMutationEffectV1, ReconcilerError};
use crate::runtime_authority::{
    RuntimeAuthorityBindingV1, RuntimeAuthorityError, RuntimeAuthorityLimits, RuntimeAuthorityStore,
};
use crate::sandbox_spec_state::{DurableSandboxSpecV1, SandboxSpecStateError};
use crate::{Journal, JournalError};

use super::super::{
    AuthenticatedSandboxProjectRelationV1, PolicyCompilerInputV1,
    PolicyDeploymentHeadErrorV1, PolicyDeploymentHeadV1, PolicyDeploymentSourcesV1,
    PolicyModelError,
    SandboxProjectRelationVerifierV1, VerifiedSignedProjectPolicySourceV2,
};

/// Reports a failed current-Start input comparison without conferring authority.
#[derive(Debug, thiserror::Error)]
pub enum CurrentNixInputErrorV1 {
    /// The admitted Start, assignment, specification or original Source cut differs.
    #[error("current Nix input differs from its original Start")]
    Changed,
    /// A real parent exists but its authenticated raw policy layers are unavailable.
    #[error("current Nix input requires authenticated ancestor policy originals")]
    AncestorPolicyOriginalsRequired,
    /// The complete inherited request could not be constructed.
    #[error(transparent)]
    Inherited(#[from] super::super::public_create_source::CurrentCreateCompilerInputErrorV1),
    /// Current protected publisher state differs from the signed project source.
    #[error(transparent)]
    Project(#[from] PolicyDeploymentHeadErrorV1),
    /// The sole policy-model constructor rejected the exact relation or layers.
    #[error(transparent)]
    Model(#[from] PolicyModelError),
    /// The actual original Source names, full replay or watermark differs.
    #[error(transparent)]
    Source(#[from] HierarchyProtectedJournalErrorV1),
}

#[derive(Clone, Copy)]
pub(super) struct CurrentNixTreeTargetV1 {
    pub(super) record: SandboxTreeRecordV1,
    pub(super) tree: ObjectDigest,
    pub(super) lineage: ObjectDigest,
}

// All returned owners and errors stay in their original slots. The two writers
// remain held by the surrounding CurrentStart and this inventory borrow.
pub(super) struct CurrentNixInputAttemptV1<'source> {
    pub(super) entered: bool,
    pub(super) carrier: Option<Result<Vec<u8>, NixStartAdmissionErrorV2>>,
    pub(super) context: Option<Result<Option<PublicMutationEffectV1>, ReconcilerError>>,
    pub(super) request: Option<Result<DormantSandboxRequestKindV1, ReconcilerError>>,
    pub(super) binding: Option<Result<Option<RuntimeAuthorityBindingV1>, RuntimeAuthorityError>>,
    pub(super) specification: Option<Result<Option<DurableSandboxSpecV1>, SandboxSpecStateError>>,
    pub(super) controller_names: Option<Result<ProtectedJournalNamesV1, JournalError>>,
    pub(super) inventory: Option<CurrentNixSourceInventoryAttemptV1<'source>>,
    pub(super) target: Option<Result<CurrentNixTreeTargetV1, CurrentNixInputErrorV1>>,
    pub(super) comparison: Option<Result<(), CurrentNixInputErrorV1>>,
    pub(super) input: Option<Result<PolicyCompilerInputV1, CurrentNixInputErrorV1>>,
    pub(super) controller_post: Option<Result<(), JournalError>>,
    pub(super) source_post: Option<Result<(), HierarchyProtectedJournalErrorV1>>,
    pub(super) assembly_controller_post: Option<Result<(), JournalError>>,
    pub(super) assembly_source_post: Option<Result<(), HierarchyProtectedJournalErrorV1>>,
}

// A consuming close may archive these originals in the same paid intake. No
// CurrentStart or Source reference enters that resident Session destination.
pub(super) struct CurrentNixInputOriginalsV1 {
    carrier: Option<Result<Vec<u8>, NixStartAdmissionErrorV2>>,
    context: Option<Result<Option<PublicMutationEffectV1>, ReconcilerError>>,
    request: Option<Result<DormantSandboxRequestKindV1, ReconcilerError>>,
    binding: Option<Result<Option<RuntimeAuthorityBindingV1>, RuntimeAuthorityError>>,
    specification: Option<Result<Option<DurableSandboxSpecV1>, SandboxSpecStateError>>,
    controller_names: Option<Result<ProtectedJournalNamesV1, JournalError>>,
    inventory: Option<CurrentNixSourceInventoryDataV1>,
    target: Option<Result<CurrentNixTreeTargetV1, CurrentNixInputErrorV1>>,
    comparison: Option<Result<(), CurrentNixInputErrorV1>>,
    input: Option<Result<PolicyCompilerInputV1, CurrentNixInputErrorV1>>,
    controller_post: Option<Result<(), JournalError>>,
    source_post: Option<Result<(), HierarchyProtectedJournalErrorV1>>,
    assembly_controller_post: Option<Result<(), JournalError>>,
    assembly_source_post: Option<Result<(), HierarchyProtectedJournalErrorV1>>,
}

// Both live and closed custody borrow the same result vocabulary. This view
// moves no payload and never reconstructs a former journal or Source loan.
struct CurrentNixInputResultViewV1<'original> {
    carrier: &'original Option<Result<Vec<u8>, NixStartAdmissionErrorV2>>,
    context: &'original Option<Result<Option<PublicMutationEffectV1>, ReconcilerError>>,
    request: &'original Option<Result<DormantSandboxRequestKindV1, ReconcilerError>>,
    binding: &'original Option<Result<Option<RuntimeAuthorityBindingV1>, RuntimeAuthorityError>>,
    specification: &'original Option<Result<Option<DurableSandboxSpecV1>, SandboxSpecStateError>>,
    controller_names: &'original Option<Result<ProtectedJournalNamesV1, JournalError>>,
    inventory_failure: Option<&'original (dyn std::error::Error + 'static)>,
    target: &'original Option<Result<CurrentNixTreeTargetV1, CurrentNixInputErrorV1>>,
    comparison: &'original Option<Result<(), CurrentNixInputErrorV1>>,
    input: &'original Option<Result<PolicyCompilerInputV1, CurrentNixInputErrorV1>>,
    controller_post: &'original Option<Result<(), JournalError>>,
    source_post: &'original Option<Result<(), HierarchyProtectedJournalErrorV1>>,
    assembly_controller_post: &'original Option<Result<(), JournalError>>,
    assembly_source_post: &'original Option<Result<(), HierarchyProtectedJournalErrorV1>>,
}

impl<'original> CurrentNixInputResultViewV1<'original> {
    fn failure(self) -> Option<&'original (dyn std::error::Error + 'static)> {
        self.controller_names.as_ref().and_then(|result| result.as_ref().err()).map(|e| e as _)
            .or_else(|| self.carrier.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.context.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.request.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.binding.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.specification.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or(self.inventory_failure)
            .or_else(|| self.target.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.comparison.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.controller_post.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.source_post.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.input.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.assembly_controller_post.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
            .or_else(|| self.assembly_source_post.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _))
    }
}

impl CurrentNixInputOriginalsV1 {
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        CurrentNixInputResultViewV1 {
            carrier: &self.carrier, context: &self.context, request: &self.request,
            binding: &self.binding, specification: &self.specification,
            controller_names: &self.controller_names,
            inventory_failure: self.inventory.as_ref().and_then(CurrentNixSourceInventoryDataV1::first_error),
            target: &self.target, comparison: &self.comparison, input: &self.input,
            controller_post: &self.controller_post, source_post: &self.source_post,
            assembly_controller_post: &self.assembly_controller_post,
            assembly_source_post: &self.assembly_source_post,
        }.failure()
    }
}

impl<'source> CurrentNixInputAttemptV1<'source> {
    pub(super) const fn empty() -> Self {
        Self {
            entered: false,
            carrier: None,
            context: None,
            request: None,
            binding: None,
            specification: None,
            controller_names: None,
            inventory: None,
            target: None,
            comparison: None,
            input: None,
            controller_post: None,
            source_post: None,
            assembly_controller_post: None,
            assembly_source_post: None,
        }
    }

    pub(super) fn into_retained_originals(self) -> CurrentNixInputOriginalsV1 {
        CurrentNixInputOriginalsV1 {
            carrier: self.carrier, context: self.context, request: self.request,
            binding: self.binding, specification: self.specification,
            controller_names: self.controller_names,
            inventory: self.inventory.map(CurrentNixSourceInventoryAttemptV1::into_retained_data),
            target: self.target, comparison: self.comparison, input: self.input,
            controller_post: self.controller_post, source_post: self.source_post,
            assembly_controller_post: self.assembly_controller_post,
            assembly_source_post: self.assembly_source_post,
        }
    }

    // Called only from the same retained CurrentStart's purpose-closed handoff.
    // Its original carrier/target are comparison inputs, not a new admission.
    pub(super) fn capture_once(
        &mut self,
        controller: &mut Journal,
        source: &'source mut ProtectedSourceDomainJournalOwnerV1,
        original: &NixStartAdmissionCarrierV2,
        original_binding: &RuntimeAuthorityBindingV1,
    ) -> Result<(), ()> {
        if self.entered {
            return Err(());
        }
        self.entered = true;

        self.controller_names = Some(controller.protected_writer_physical_names_v1());
        self.carrier = Some(original.encode());
        self.context = Some(PublicMutationEffectV1::decode_plain(original.ordinary_effect()));
        if let Some(Ok(Some(context))) = self.context.as_ref() {
            self.request = Some(context.validated_request());
        }
        self.binding = Some(
            RuntimeAuthorityStore::load(controller, RuntimeAuthorityLimits::default())
                .and_then(|store| store.current(original_binding.sandbox())),
        );
        if matches!(self.binding.as_ref(), Some(Ok(Some(binding))) if binding == original_binding) {
            self.specification = Some(crate::sandbox_spec_state::get(
                controller,
                original_binding.manifest().manifest().sandbox_spec(),
            ));
        }

        self.inventory = Some(capture_current_nix_inventory_v1(source));
        if let Some(inventory) = self.inventory.as_ref().filter(|owner| owner.first_error().is_none()) {
            self.target = Some(select_parentless_target(
                inventory,
                original_binding.manifest(),
                original.original_generation(),
            ));
        }
        self.comparison = Some(self.compare_original(original, original_binding));

        // Run independent owner observations even when a prior result failed.
        self.controller_post = Some(controller.validate_held_protected_names());
        if let Some(inventory) = self.inventory.as_ref() {
            self.source_post = Some(inventory.recheck());
        }
        if self.failure().is_some() { Err(()) } else { Ok(()) }
    }

    fn compare_original(
        &self,
        original: &NixStartAdmissionCarrierV2,
        original_binding: &RuntimeAuthorityBindingV1,
    ) -> Result<(), CurrentNixInputErrorV1> {
        let Some(Ok(Some(binding))) = self.binding.as_ref() else {
            return Err(CurrentNixInputErrorV1::Changed);
        };
        let Some(Ok(Some(spec))) = self.specification.as_ref() else {
            return Err(CurrentNixInputErrorV1::Changed);
        };
        let Some(Ok(Some(context))) = self.context.as_ref() else {
            return Err(CurrentNixInputErrorV1::Changed);
        };
        let Some(Ok(DormantSandboxRequestKindV1::Start(request))) = self.request.as_ref() else {
            return Err(CurrentNixInputErrorV1::Changed);
        };
        let Some(Ok(target)) = self.target.as_ref() else {
            return Err(CurrentNixInputErrorV1::Changed);
        };
        let manifest = binding.manifest().manifest();
        if binding != original_binding
            || context.project() != manifest.project()
            || request.sandbox_id != manifest.sandbox().as_bytes()
            || original.original_generation().checked_add(1)
                != Some(manifest.desired_generation().get())
            || spec.descriptor() != manifest.sandbox_spec()
            || spec.spec().environment() != manifest.environment()
            || spec.spec().root_view() != manifest.root_view()
            || target.record.project() != context.project()
        {
            return Err(CurrentNixInputErrorV1::Changed);
        }
        Ok(())
    }

    // The Root flight supplies these signature-checked sources while retaining
    // its original owner. Local construction still produces proposal DATA.
    pub(super) fn assemble_parentless_once(
        &mut self,
        controller: &mut Journal,
        deployment_head: PolicyDeploymentHeadV1,
        deployment: &PolicyDeploymentSourcesV1,
        signed_project: &VerifiedSignedProjectPolicySourceV2,
        original_now: i64,
    ) -> Result<(), ()> {
        if self.input.is_some() || self.failure().is_some() {
            return Err(());
        }
        self.input = Some(self.assemble_parentless(
            controller, deployment_head, deployment, signed_project, original_now,
        ));
        self.assembly_controller_post = Some(controller.validate_held_protected_names());
        if let Some(inventory) = self.inventory.as_ref() {
            self.assembly_source_post = Some(inventory.recheck());
        }
        if self.failure().is_some() { Err(()) } else { Ok(()) }
    }

    fn assemble_parentless(
        &self,
        controller: &mut Journal,
        deployment_head: PolicyDeploymentHeadV1,
        deployment: &PolicyDeploymentSourcesV1,
        signed_project: &VerifiedSignedProjectPolicySourceV2,
        original_now: i64,
    ) -> Result<PolicyCompilerInputV1, CurrentNixInputErrorV1> {
        let Some(Ok(Some(binding))) = self.binding.as_ref() else {
            return Err(CurrentNixInputErrorV1::Changed);
        };
        let Some(Ok(target)) = self.target.as_ref() else {
            return Err(CurrentNixInputErrorV1::Changed);
        };
        let head = signed_project.head();
        if original_now >= deployment_head.expires_at()
            || original_now >= head.expires_at()
            || head.project() != target.record.project()
            || head.prerequisite_claims()[0] != target.tree
            || head.prerequisite_claims()[1] != deployment_head.packet_digest()
            || !deployment.endpoints().entries().is_empty()
            || !deployment.destinations().entries().is_empty()
        {
            return Err(CurrentNixInputErrorV1::Changed);
        }

        let publisher = crate::publisher_policy::PublisherPolicyStore::load(
            controller, crate::publisher_policy::PublisherPolicyLimits::default(),
        ).map_err(PolicyDeploymentHeadErrorV1::from)?;
        let revocation = publisher.project_revocation_head(head.project())
            .map_err(PolicyDeploymentHeadErrorV1::from)?
            .ok_or(CurrentNixInputErrorV1::Changed)?;
        drop(publisher);
        let project_layer = super::super::project_source_v2::current_explicit_layer(
            controller, revocation.scope(), signed_project, original_now,
        )?;
        let relation = AuthenticatedSandboxProjectRelationV1::authenticate(
            target.record.sandbox(), target.record.project(),
            &CurrentNixRelationV1 { binding, target },
        )?;
        Ok(super::super::public_create_source::parentless_create_input_from_authenticated_layers_v1(
            relation, project_layer, deployment,
        )?)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        CurrentNixInputResultViewV1 {
            carrier: &self.carrier, context: &self.context, request: &self.request,
            binding: &self.binding, specification: &self.specification,
            controller_names: &self.controller_names,
            inventory_failure: self.inventory.as_ref().and_then(CurrentNixSourceInventoryAttemptV1::first_error),
            target: &self.target, comparison: &self.comparison, input: &self.input,
            controller_post: &self.controller_post, source_post: &self.source_post,
            assembly_controller_post: &self.assembly_controller_post,
            assembly_source_post: &self.assembly_source_post,
        }.failure()
    }
}

fn select_parentless_target(
    inventory: &CurrentNixSourceInventoryAttemptV1<'_>,
    manifest: &CanonicalAssignmentManifestV1,
    original_generation: u64,
) -> Result<CurrentNixTreeTargetV1, CurrentNixInputErrorV1> {
    let assignment = manifest.manifest();
    let (record, head, lineage) = inventory.original_nix_target_data(
        assignment.project(), assignment.sandbox(),
    )?;
    if record.parent().is_some() || !assignment.ancestry().ancestors().is_empty() {
        return Err(CurrentNixInputErrorV1::AncestorPolicyOriginalsRequired);
    }
    if record.project() != assignment.project()
        || record.sandbox() != assignment.sandbox()
        || record.incarnation().is_some_and(|incarnation| incarnation != assignment.incarnation())
        || record.desired_generation().get() != original_generation
    {
        return Err(CurrentNixInputErrorV1::Changed);
    }
    Ok(CurrentNixTreeTargetV1 { record, tree: head, lineage })
}

struct CurrentNixRelationV1<'original> {
    binding: &'original RuntimeAuthorityBindingV1,
    target: &'original CurrentNixTreeTargetV1,
}

impl SandboxProjectRelationVerifierV1 for CurrentNixRelationV1<'_> {
    fn verify(
        &self, sandbox: SandboxId, project: ProjectId,
        descriptor: &ObjectDescriptor, bytes: &[u8],
    ) -> bool {
        let Ok(media) = MediaType::new(PortableMediaType::Content.as_str()) else {
            return false;
        };
        let manifest = self.binding.manifest().manifest();
        sandbox == manifest.sandbox()
            && project == manifest.project()
            && sandbox == self.target.record.sandbox()
            && project == self.target.record.project()
            && !bytes.is_empty()
            && descriptor_for_bytes(media, bytes) == *descriptor
    }
}
