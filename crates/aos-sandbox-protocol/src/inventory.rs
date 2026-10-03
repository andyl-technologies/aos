//! Authoritative mount-broker inventory validation.
//!
//! Inventory is a durable resource-table snapshot, not a repetition of the
//! last action result. This module closes every nested enum and field shape,
//! bounds allocation before decoding, and requires canonical handle order so
//! consumers can reconcile without inventing identity from list position.

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::local::v1::{
    InventoryMountResourcesResponse, InventoryMountsRequest, MountFaultCorrelation,
    MountFaultPhase, MountInventoryRecord, MountInventorySourceAuthority, MountKernelObservation,
    MountLifecycle, MountOperationCorrelation, MountPublicationCorrelation, MountRecipe,
    MountSourceConsistency, MountSourceProofClass,
};
use aos_sandbox_core::{DescriptorRole, ObjectDescriptor, ObjectDigest, ProtocolId};
use buffa::Message as _;

use crate::{
    MAXIMUM_REQUEST_BYTES, MAXIMUM_RESPONSE_BYTES, MINIMUM_RESPONSE_BYTES,
    MountSourceProviderHistoryV1, PeerCredentials, PeerPolicy, ProtocolValidationError,
    SourceRealizationBindingV1, ValidatedAssignmentFence, ValidatedHeader,
    ValidatedMountAttributes, exact_nonzero, mount_source_provider_history_is_valid_v1,
    validate_descriptor, validate_fence, validate_mount_attributes, validate_mount_source_handle,
    validate_request_header,
};

/// Maximum durable mount rows accepted in one complete inventory snapshot.
pub const MAXIMUM_MOUNT_INVENTORY_RECORDS: usize = 1024;
const MAXIMUM_KERNEL_PATH_BYTES: usize = 4096;
const HAS_DETACHED: u16 = 1 << 0;
const HAS_INSTALLED: u16 = 1 << 1;
const HAS_CREATION: u16 = 1 << 2;
const HAS_PUBLICATION: u16 = 1 << 3;
const HAS_REPLACEMENT: u16 = 1 << 4;
const HAS_FAULT: u16 = 1 << 5;
const HAS_LAST_INSTALLED: u16 = 1 << 6;
const HAS_DETACHMENT: u16 = 1 << 7;
const HAS_RELEASE: u16 = 1 << 8;

/// Carries a complete, validated mount-broker inventory snapshot.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedMountInventory {
    kernel_boot_id: [u8; 16],
    broker_instance_id: [u8; 16],
    journal_sequence: u64,
    mounts: Vec<ValidatedMountInventoryRecord>,
}

impl ValidatedMountInventory {
    /// Returns the current Linux boot identifier for reconciliation.
    #[must_use]
    pub const fn kernel_boot_id(&self) -> &[u8; 16] {
        &self.kernel_boot_id
    }

    /// Returns the identity of the broker process that emitted the snapshot.
    #[must_use]
    pub const fn broker_instance_id(&self) -> &[u8; 16] {
        &self.broker_instance_id
    }

    /// Returns the nonzero next-frame boundary after the durable snapshot.
    #[must_use]
    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    /// Returns durable resources in strict stable-handle order.
    #[must_use]
    pub fn mounts(&self) -> &[ValidatedMountInventoryRecord] {
        &self.mounts
    }
}

/// Carries the assignment and mount-namespace identity bound to a resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMountAssignmentBinding {
    fence: ValidatedAssignmentFence,
    namespace_generation: u64,
}

impl ValidatedMountAssignmentBinding {
    /// Returns the complete control-plane assignment fence.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the payload mount-namespace generation.
    #[must_use]
    pub const fn namespace_generation(&self) -> u64 {
        self.namespace_generation
    }
}

/// Carries the immutable recipe associated with one stable mount handle.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedMountRecipe {
    attachment_id: [u8; 16],
    destination_slot_id: [u8; 16],
    view_revision: ObjectDescriptor,
    source_generation: u64,
    attributes: ValidatedMountAttributes,
    resource_attachment_generation: u64,
    source_view_id: [u8; 16],
    source_incarnation_id: Option<[u8; 16]>,
    source_assignment_digest: Option<ObjectDigest>,
    source_consistency: MountSourceConsistency,
    source: Box<SourceRealizationBindingV1>,
    source_realization_handle: [u8; 32],
    source_physical_proof_digest: [u8; 32],
    source_kernel_boot_id: [u8; 16],
    source_device: u64,
    source_inode: u64,
    source_proof_class: MountSourceProofClass,
    source_unique_mount_id: u64,
    source_provider_authority_id: [u8; 16],
    source_provider_authority_generation: u64,
    source_provider_authority_digest: [u8; 32],
    source_provider_resource_id: [u8; 32],
    source_provider_resource_generation: u64,
    source_provider_resource_digest: [u8; 32],
    source_provider_catalog_generation: u64,
    source_provider_catalog_digest: [u8; 32],
}

impl ValidatedMountRecipe {
    /// Returns the logical attachment identifier.
    #[must_use]
    pub const fn attachment_id(&self) -> &[u8; 16] {
        &self.attachment_id
    }

    /// Returns the broker-owned destination-slot identifier.
    #[must_use]
    pub const fn destination_slot_id(&self) -> &[u8; 16] {
        &self.destination_slot_id
    }

    /// Returns the immutable filesystem-view descriptor.
    #[must_use]
    pub const fn view_revision(&self) -> &ObjectDescriptor {
        &self.view_revision
    }

    /// Returns the immutable source generation.
    #[must_use]
    pub const fn source_generation(&self) -> u64 {
        self.source_generation
    }

    /// Returns the closed mount and mutation attributes.
    #[must_use]
    pub const fn attributes(&self) -> ValidatedMountAttributes {
        self.attributes
    }

    /// Returns the attachment generation whose recipe created this resource.
    #[must_use]
    pub const fn resource_attachment_generation(&self) -> u64 {
        self.resource_attachment_generation
    }

    /// Returns the logical source-view identity.
    #[must_use]
    pub const fn source_view_id(&self) -> &[u8; 16] {
        &self.source_view_id
    }

    /// Returns the source incarnation required by a local-live recipe.
    #[must_use]
    pub const fn source_incarnation_id(&self) -> Option<&[u8; 16]> {
        self.source_incarnation_id.as_ref()
    }

    /// Returns the signed source Host assignment bound to a live recipe.
    #[must_use]
    pub const fn source_assignment_digest(&self) -> Option<ObjectDigest> {
        self.source_assignment_digest
    }

    /// Returns the closed source consistency contract.
    #[must_use]
    pub const fn source_consistency(&self) -> MountSourceConsistency {
        self.source_consistency
    }

    /// Returns the complete exact-source binding carried by this recipe.
    #[must_use]
    pub const fn source(&self) -> &SourceRealizationBindingV1 {
        &self.source
    }

    /// Returns the Mount-minted physical realization handle.
    #[must_use]
    pub const fn source_realization_handle(&self) -> &[u8; 32] {
        &self.source_realization_handle
    }

    /// Returns the authenticated physical source-proof digest.
    #[must_use]
    pub const fn source_physical_proof_digest(&self) -> &[u8; 32] {
        &self.source_physical_proof_digest
    }

    /// Returns the kernel boot in which the source identity was observed.
    #[must_use]
    pub const fn source_kernel_boot_id(&self) -> &[u8; 16] {
        &self.source_kernel_boot_id
    }

    /// Returns the source descriptor's device identity.
    #[must_use]
    pub const fn source_device(&self) -> u64 {
        self.source_device
    }

    /// Returns the source descriptor's inode identity.
    #[must_use]
    pub const fn source_inode(&self) -> u64 {
        self.source_inode
    }

    /// Returns the closed physical proof class.
    #[must_use]
    pub const fn source_proof_class(&self) -> MountSourceProofClass {
        self.source_proof_class
    }

    /// Returns the source mount's kernel-lifetime identity.
    #[must_use]
    pub const fn source_unique_mount_id(&self) -> u64 {
        self.source_unique_mount_id
    }

    /// Returns the stable provider authority identity.
    #[must_use]
    pub const fn source_provider_authority_id(&self) -> &[u8; 16] {
        &self.source_provider_authority_id
    }

    /// Returns the stable provider authority generation.
    #[must_use]
    pub const fn source_provider_authority_generation(&self) -> u64 {
        self.source_provider_authority_generation
    }

    /// Returns the stable provider authority digest.
    #[must_use]
    pub const fn source_provider_authority_digest(&self) -> &[u8; 32] {
        &self.source_provider_authority_digest
    }

    /// Returns the stable provider resource identity.
    #[must_use]
    pub const fn source_provider_resource_id(&self) -> &[u8; 32] {
        &self.source_provider_resource_id
    }

    /// Returns the stable provider resource generation.
    #[must_use]
    pub const fn source_provider_resource_generation(&self) -> u64 {
        self.source_provider_resource_generation
    }

    /// Returns the stable provider resource digest.
    #[must_use]
    pub const fn source_provider_resource_digest(&self) -> &[u8; 32] {
        &self.source_provider_resource_digest
    }

    /// Returns the provider catalog generation used for admission.
    #[must_use]
    pub const fn source_provider_catalog_generation(&self) -> u64 {
        self.source_provider_catalog_generation
    }

    /// Returns the provider catalog digest used for admission.
    #[must_use]
    pub const fn source_provider_catalog_digest(&self) -> &[u8; 32] {
        &self.source_provider_catalog_digest
    }
}

/// Captures kernel identity for an installed mount generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMountKernelObservation {
    unique_mount_id: u64,
    parent_mount_id: u64,
    mount_namespace_id: u64,
    device_major: u32,
    device_minor: u32,
    superblock_magic: u64,
    superblock_flags: u32,
    mount_attributes: u64,
    propagation: u64,
    root: Vec<u8>,
    mount_point: Vec<u8>,
    identity_map_digest: [u8; 32],
}

impl ValidatedMountKernelObservation {
    /// Returns the non-recycled unique mount identifier.
    #[must_use]
    pub const fn unique_mount_id(&self) -> u64 {
        self.unique_mount_id
    }
    /// Returns the observed parent mount identifier.
    #[must_use]
    pub const fn parent_mount_id(&self) -> u64 {
        self.parent_mount_id
    }
    /// Returns the mount namespace identifier containing the installation.
    #[must_use]
    pub const fn mount_namespace_id(&self) -> u64 {
        self.mount_namespace_id
    }
    /// Returns the kernel device major number.
    #[must_use]
    pub const fn device_major(&self) -> u32 {
        self.device_major
    }
    /// Returns the kernel device minor number.
    #[must_use]
    pub const fn device_minor(&self) -> u32 {
        self.device_minor
    }
    /// Returns the filesystem superblock magic.
    #[must_use]
    pub const fn superblock_magic(&self) -> u64 {
        self.superblock_magic
    }
    /// Returns the observed superblock flags.
    #[must_use]
    pub const fn superblock_flags(&self) -> u32 {
        self.superblock_flags
    }
    /// Returns the observed VFS mount-attribute mask.
    #[must_use]
    pub const fn mount_attributes(&self) -> u64 {
        self.mount_attributes
    }
    /// Returns the observed propagation mask.
    #[must_use]
    pub const fn propagation(&self) -> u64 {
        self.propagation
    }
    /// Returns the raw, NUL-free kernel root path.
    #[must_use]
    pub fn root(&self) -> &[u8] {
        &self.root
    }
    /// Returns the raw, NUL-free kernel mount-point path.
    #[must_use]
    pub fn mount_point(&self) -> &[u8] {
        &self.mount_point
    }
    /// Returns the commitment to the complete UID and GID identity maps.
    #[must_use]
    pub const fn identity_map_digest(&self) -> &[u8; 32] {
        &self.identity_map_digest
    }
}

/// Correlates detached-mount creation with its idempotent request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedMountOperationCorrelation {
    operation_id: [u8; 16],
    request_digest: [u8; 32],
}

impl ValidatedMountOperationCorrelation {
    /// Returns the idempotent operation identifier.
    #[must_use]
    pub const fn operation_id(&self) -> &[u8; 16] {
        &self.operation_id
    }

    /// Returns the digest of the exact creation request.
    #[must_use]
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
}

/// Correlates a publishing resource with the request and replaced generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedMountPublicationCorrelation {
    operation_id: [u8; 16],
    request_digest: [u8; 32],
    target_mount_namespace_id: u64,
    target_namespace_generation: u64,
    replaces_mount_handle: Option<[u8; 32]>,
}

impl ValidatedMountPublicationCorrelation {
    /// Returns the idempotent operation identifier.
    #[must_use]
    pub const fn operation_id(&self) -> &[u8; 16] {
        &self.operation_id
    }
    /// Returns the digest of the publication request.
    #[must_use]
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
    /// Returns the exact target mount namespace identity.
    #[must_use]
    pub const fn target_mount_namespace_id(&self) -> u64 {
        self.target_mount_namespace_id
    }
    /// Returns the target namespace generation used by the publication.
    #[must_use]
    pub const fn target_namespace_generation(&self) -> u64 {
        self.target_namespace_generation
    }
    /// Returns the stable handle replaced by this publication, when any.
    #[must_use]
    pub const fn replaces_mount_handle(&self) -> Option<&[u8; 32]> {
        self.replaces_mount_handle.as_ref()
    }
}

/// Correlates a fault with its originating phase and sanitized failure identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedMountFaultCorrelation {
    from: MountFaultPhase,
    failure_digest: [u8; 32],
}

impl ValidatedMountFaultCorrelation {
    /// Returns the closed lifecycle phase in which the failure occurred.
    #[must_use]
    pub const fn from(&self) -> MountFaultPhase {
        self.from
    }
    /// Returns the non-secret failure correlation digest.
    #[must_use]
    pub const fn failure_digest(&self) -> &[u8; 32] {
        &self.failure_digest
    }
}

/// Carries one complete durable mount resource after semantic validation.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedMountInventoryRecord {
    mount_handle: [u8; 32],
    resource_revision: u64,
    binding: ValidatedMountAssignmentBinding,
    recipe: ValidatedMountRecipe,
    lifecycle: MountLifecycle,
    resource_kernel_boot_id: [u8; 16],
    creation: Option<ValidatedMountOperationCorrelation>,
    detachment: Option<ValidatedMountOperationCorrelation>,
    release: Option<ValidatedMountOperationCorrelation>,
    detached_unique_mount_id: Option<u64>,
    installed_observation: Option<ValidatedMountKernelObservation>,
    publication: Option<ValidatedMountPublicationCorrelation>,
    replaced_by_mount_handle: Option<[u8; 32]>,
    fault: Option<ValidatedMountFaultCorrelation>,
    last_installed_unique_mount_id: Option<u64>,
}

impl ValidatedMountInventoryRecord {
    /// Returns the stable broker-minted resource handle.
    #[must_use]
    pub const fn mount_handle(&self) -> &[u8; 32] {
        &self.mount_handle
    }
    /// Returns the nonzero compare-and-swap revision.
    #[must_use]
    pub const fn resource_revision(&self) -> u64 {
        self.resource_revision
    }
    /// Returns the assignment identity bound to the resource.
    #[must_use]
    pub const fn binding(&self) -> &ValidatedMountAssignmentBinding {
        &self.binding
    }
    /// Returns the immutable mount recipe.
    #[must_use]
    pub const fn recipe(&self) -> &ValidatedMountRecipe {
        &self.recipe
    }
    /// Returns the closed durable lifecycle phase.
    #[must_use]
    pub const fn lifecycle(&self) -> MountLifecycle {
        self.lifecycle
    }
    /// Returns the Linux boot ID under which this durable resource was created.
    #[must_use]
    pub const fn resource_kernel_boot_id(&self) -> &[u8; 16] {
        &self.resource_kernel_boot_id
    }
    /// Returns detached-mount creation correlation before publication begins.
    #[must_use]
    pub const fn creation(&self) -> Option<ValidatedMountOperationCorrelation> {
        self.creation
    }
    /// Returns ordinary-detach correlation while target removal is uncertain.
    #[must_use]
    pub const fn detachment(&self) -> Option<ValidatedMountOperationCorrelation> {
        self.detachment
    }
    /// Returns release correlation while descriptor-store removal is uncertain.
    #[must_use]
    pub const fn release(&self) -> Option<ValidatedMountOperationCorrelation> {
        self.release
    }
    /// Returns the detached mount's unique kernel identifier when one existed.
    #[must_use]
    pub const fn detached_unique_mount_id(&self) -> Option<u64> {
        self.detached_unique_mount_id
    }
    /// Returns installed kernel identity when required or retained by lifecycle.
    #[must_use]
    pub const fn installed_observation(&self) -> Option<&ValidatedMountKernelObservation> {
        self.installed_observation.as_ref()
    }
    /// Returns publication correlation for publishing or publication-fault rows.
    #[must_use]
    pub const fn publication(&self) -> Option<ValidatedMountPublicationCorrelation> {
        self.publication
    }
    /// Returns the successor handle for draining resources.
    #[must_use]
    pub const fn replaced_by_mount_handle(&self) -> Option<&[u8; 32]> {
        self.replaced_by_mount_handle.as_ref()
    }
    /// Returns fault correlation exactly for faulted rows.
    #[must_use]
    pub const fn fault(&self) -> Option<ValidatedMountFaultCorrelation> {
        self.fault
    }
    /// Returns the last installed mount ID retained after release, when any.
    #[must_use]
    pub const fn last_installed_unique_mount_id(&self) -> Option<u64> {
        self.last_installed_unique_mount_id
    }
}

/// Decodes and validates one mount inventory request from hostile wire bytes.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for size or wire failures, unknown
/// fields, peer or audience mismatch, incompatible protocol versions, expired
/// deadlines, malformed request IDs, or invalid response ceilings.
pub fn decode_mount_inventory_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHeader, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_REQUEST_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = InventoryMountsRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    reject_unknown(&request.__buffa_unknown_fields)?;
    validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::MountBroker,
        now_boottime_nanoseconds,
    )
}

/// Validates and encodes one authoritative Mount 2.0 inventory.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for a response above the fixed protocol
/// ceiling or any malformed or noncanonical inventory field.
pub fn encode_mount_inventory_response(
    response: InventoryMountResourcesResponse,
) -> Result<Vec<u8>, ProtocolValidationError> {
    let bytes = response.encode_to_vec();
    decode_mount_inventory_response(&bytes, MAXIMUM_RESPONSE_BYTES)?;
    Ok(bytes)
}

/// Decodes and validates one complete mount inventory from hostile wire bytes.
///
/// `maximum_response_bytes` is the ceiling negotiated by the client hello and
/// request header. Validation rejects unknown fields at every nesting level,
/// unknown enums, noncanonical row order, duplicate live kernel identities,
/// and lifecycle-dependent presence mismatches.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] when the response exceeds either byte
/// ceiling, protobuf decoding fails, an inventory contains more than
/// [`MAXIMUM_MOUNT_INVENTORY_RECORDS`] rows, or any identity, recipe,
/// observation, correlation, ordering, or lifecycle invariant is invalid.
pub fn decode_mount_inventory_response(
    bytes: &[u8],
    maximum_response_bytes: u32,
) -> Result<ValidatedMountInventory, ProtocolValidationError> {
    if !(MINIMUM_RESPONSE_BYTES..=MAXIMUM_RESPONSE_BYTES).contains(&maximum_response_bytes) {
        return Err(ProtocolValidationError::InvalidResponseBound);
    }
    if bytes.len() > maximum_response_bytes as usize {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = InventoryMountResourcesResponse::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    reject_unknown(&response.__buffa_unknown_fields)?;
    if response.journal_sequence == 0 {
        return Err(ProtocolValidationError::InvalidField("journal_sequence"));
    }
    if response.mounts.len() > MAXIMUM_MOUNT_INVENTORY_RECORDS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "inventory.mounts",
            maximum: MAXIMUM_MOUNT_INVENTORY_RECORDS,
        });
    }

    let kernel_boot_id = exact_nonzero::<16>(&response.kernel_boot_id, "kernel_boot_id")?;
    let broker_instance_id =
        exact_nonzero::<16>(&response.broker_instance_id, "broker_instance_id")?;
    let mut mounts = Vec::with_capacity(response.mounts.len());
    let mut mount_id_owners = BTreeMap::new();
    for record in &response.mounts {
        let record = validate_record(record)?;
        if claims_current_kernel_state(record.lifecycle)
            && record.resource_kernel_boot_id != kernel_boot_id
        {
            return Err(ProtocolValidationError::InvalidField(
                "inventory current kernel boot",
            ));
        }
        if mounts
            .last()
            .is_some_and(|previous: &ValidatedMountInventoryRecord| {
                previous.mount_handle >= record.mount_handle
            })
        {
            return Err(ProtocolValidationError::InvalidField(
                "inventory.mounts order",
            ));
        }
        for unique_id in record
            .detached_unique_mount_id
            .into_iter()
            .chain(
                record
                    .installed_observation
                    .as_ref()
                    .map(|value| value.unique_mount_id),
            )
            .chain(record.last_installed_unique_mount_id)
        {
            if mount_id_owners
                .insert(
                    (record.resource_kernel_boot_id, unique_id),
                    record.mount_handle,
                )
                .is_some_and(|owner| owner != record.mount_handle)
            {
                return Err(ProtocolValidationError::InvalidField(
                    "inventory unique mount IDs",
                ));
            }
        }
        mounts.push(record);
    }
    validate_source_realizations(&mounts)?;
    validate_replacement_correlations(&mounts)?;
    validate_slot_ownership(&mounts, kernel_boot_id)?;

    Ok(ValidatedMountInventory {
        kernel_boot_id,
        broker_instance_id,
        journal_sequence: response.journal_sequence,
        mounts,
    })
}

fn validate_source_realizations(
    mounts: &[ValidatedMountInventoryRecord],
) -> Result<(), ProtocolValidationError> {
    let mut handles: BTreeMap<[u8; 32], &ValidatedMountRecipe> = BTreeMap::new();
    let mut files = BTreeMap::new();
    let mut mount_ids = BTreeMap::new();
    let mut authority_generations = BTreeMap::new();
    let mut catalog_generations = BTreeMap::new();
    let mut resource_generations = BTreeMap::new();
    let mut provider_history = Vec::with_capacity(mounts.len());
    for record in mounts {
        let recipe = &record.recipe;
        if let Some(prior) = handles.insert(recipe.source_realization_handle, recipe)
            && !same_source_realization(prior, recipe)
        {
            return Err(ProtocolValidationError::InvalidField(
                "inventory source realization handle correlation",
            ));
        }
        if record.lifecycle != MountLifecycle::MOUNT_LIFECYCLE_RELEASED {
            for prior_handle in files
                .insert(
                    (
                        recipe.source_kernel_boot_id,
                        recipe.source_device,
                        recipe.source_inode,
                    ),
                    recipe.source_realization_handle,
                )
                .into_iter()
                .chain(mount_ids.insert(
                    (recipe.source_kernel_boot_id, recipe.source_unique_mount_id),
                    recipe.source_realization_handle,
                ))
            {
                if prior_handle != recipe.source_realization_handle {
                    return Err(ProtocolValidationError::InvalidField(
                        "inventory physical source alias",
                    ));
                }
            }
        }
        check_generation_digest(
            &mut authority_generations,
            (
                recipe.source_provider_authority_id,
                recipe.source_provider_authority_generation,
            ),
            recipe.source_provider_authority_digest,
            "inventory source provider authority equivocation",
        )?;
        check_generation_digest(
            &mut catalog_generations,
            (
                recipe.source_provider_authority_id,
                recipe.source_provider_catalog_generation,
            ),
            recipe.source_provider_catalog_digest,
            "inventory source provider catalog equivocation",
        )?;
        check_generation_digest(
            &mut resource_generations,
            (
                recipe.source_provider_authority_id,
                recipe.source_provider_resource_id,
                recipe.source_provider_resource_generation,
            ),
            recipe.source_provider_resource_digest,
            "inventory source provider resource equivocation",
        )?;
        provider_history.push(MountSourceProviderHistoryV1 {
            authority_id: recipe.source_provider_authority_id,
            authority_generation: recipe.source_provider_authority_generation,
            authority_digest: recipe.source_provider_authority_digest,
            resource_id: recipe.source_provider_resource_id,
            resource_generation: recipe.source_provider_resource_generation,
            resource_digest: recipe.source_provider_resource_digest,
            catalog_generation: recipe.source_provider_catalog_generation,
            catalog_digest: recipe.source_provider_catalog_digest,
            physical_proof_digest: recipe.source_physical_proof_digest,
        });
    }
    if !mount_source_provider_history_is_valid_v1(&provider_history) {
        return Err(ProtocolValidationError::InvalidField(
            "inventory source provider history",
        ));
    }
    Ok(())
}

fn check_generation_digest<K: Ord>(
    generations: &mut BTreeMap<K, [u8; 32]>,
    key: K,
    digest: [u8; 32],
    field: &'static str,
) -> Result<(), ProtocolValidationError> {
    if generations
        .insert(key, digest)
        .is_some_and(|prior| prior != digest)
    {
        return Err(ProtocolValidationError::InvalidField(field));
    }
    Ok(())
}

fn same_source_realization(left: &ValidatedMountRecipe, right: &ValidatedMountRecipe) -> bool {
    left.source == right.source
        && left.source_physical_proof_digest == right.source_physical_proof_digest
        && left.source_kernel_boot_id == right.source_kernel_boot_id
        && left.source_device == right.source_device
        && left.source_inode == right.source_inode
        && left.source_proof_class == right.source_proof_class
        && left.source_unique_mount_id == right.source_unique_mount_id
        && left.source_provider_authority_id == right.source_provider_authority_id
        && left.source_provider_authority_generation == right.source_provider_authority_generation
        && left.source_provider_authority_digest == right.source_provider_authority_digest
        && left.source_provider_resource_id == right.source_provider_resource_id
        && left.source_provider_resource_generation == right.source_provider_resource_generation
        && left.source_provider_resource_digest == right.source_provider_resource_digest
        && left.source_provider_catalog_generation == right.source_provider_catalog_generation
        && left.source_provider_catalog_digest == right.source_provider_catalog_digest
}

fn validate_slot_ownership(
    mounts: &[ValidatedMountInventoryRecord],
    kernel_boot_id: [u8; 16],
) -> Result<(), ProtocolValidationError> {
    let mut slots = BTreeMap::new();
    for resource in mounts
        .iter()
        .filter(|value| claims_slot(value, kernel_boot_id))
    {
        let key = (
            *resource.binding.fence.sandbox_id(),
            *resource.binding.fence.incarnation_id(),
            resource.recipe.destination_slot_id,
        );
        slots.entry(key).or_insert_with(Vec::new).push(resource);
    }
    for claimants in slots.values() {
        if claimants.len() > 2
            || (claimants.len() == 2
                && !declares_replacement(claimants[0], claimants[1])
                && !declares_replacement(claimants[1], claimants[0]))
        {
            return Err(ProtocolValidationError::InvalidField(
                "inventory destination slot ownership",
            ));
        }
    }
    Ok(())
}

fn claims_current_kernel_state(lifecycle: MountLifecycle) -> bool {
    matches!(
        lifecycle,
        MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED
            | MountLifecycle::MOUNT_LIFECYCLE_PREPARED
            | MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING
            | MountLifecycle::MOUNT_LIFECYCLE_INSTALLED
            | MountLifecycle::MOUNT_LIFECYCLE_DETACHING
            | MountLifecycle::MOUNT_LIFECYCLE_DRAINING
            | MountLifecycle::MOUNT_LIFECYCLE_RELEASING
    )
}

fn claims_slot(resource: &ValidatedMountInventoryRecord, kernel_boot_id: [u8; 16]) -> bool {
    if resource.resource_kernel_boot_id != kernel_boot_id {
        // Faulted rows from an earlier boot retain historical observations but
        // no longer claim topology in the broker's current mount namespace.
        return false;
    }
    matches!(
        resource.lifecycle,
        MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING
            | MountLifecycle::MOUNT_LIFECYCLE_INSTALLED
            | MountLifecycle::MOUNT_LIFECYCLE_DETACHING
            | MountLifecycle::MOUNT_LIFECYCLE_DRAINING
    ) || (resource.lifecycle == MountLifecycle::MOUNT_LIFECYCLE_RELEASING
        && resource.installed_observation.is_some())
        || resource.fault.is_some_and(|fault| {
            matches!(
                fault.from,
                MountFaultPhase::MOUNT_FAULT_PHASE_PUBLISHING
                    | MountFaultPhase::MOUNT_FAULT_PHASE_INSTALLED
                    | MountFaultPhase::MOUNT_FAULT_PHASE_DETACHING
                    | MountFaultPhase::MOUNT_FAULT_PHASE_DRAINING
            )
        })
        || (resource
            .fault
            .is_some_and(|fault| fault.from == MountFaultPhase::MOUNT_FAULT_PHASE_RELEASING)
            && resource.installed_observation.is_some())
}

fn declares_replacement(
    successor: &ValidatedMountInventoryRecord,
    predecessor: &ValidatedMountInventoryRecord,
) -> bool {
    successor
        .publication
        .and_then(|value| value.replaces_mount_handle)
        == Some(predecessor.mount_handle)
        && successor.resource_kernel_boot_id == predecessor.resource_kernel_boot_id
        && same_slot(successor, predecessor)
        && binding_strictly_advances(&successor.binding, &predecessor.binding)
        && successor.recipe.resource_attachment_generation
            > predecessor.recipe.resource_attachment_generation
        && ((is_phase(successor, MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING)
            && is_phase(predecessor, MountLifecycle::MOUNT_LIFECYCLE_INSTALLED))
            || (is_phase(successor, MountLifecycle::MOUNT_LIFECYCLE_INSTALLED)
                && is_phase(predecessor, MountLifecycle::MOUNT_LIFECYCLE_DRAINING)
                && predecessor.replaced_by_mount_handle == Some(successor.mount_handle)))
}

fn is_phase(resource: &ValidatedMountInventoryRecord, lifecycle: MountLifecycle) -> bool {
    resource.lifecycle == lifecycle
        || (resource.lifecycle == MountLifecycle::MOUNT_LIFECYCLE_FAULTED
            && resource.fault.is_some_and(|fault| {
                matches!(
                    (lifecycle, fault.from),
                    (
                        MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING,
                        MountFaultPhase::MOUNT_FAULT_PHASE_PUBLISHING
                    ) | (
                        MountLifecycle::MOUNT_LIFECYCLE_INSTALLED,
                        MountFaultPhase::MOUNT_FAULT_PHASE_INSTALLED
                    ) | (
                        MountLifecycle::MOUNT_LIFECYCLE_DRAINING,
                        MountFaultPhase::MOUNT_FAULT_PHASE_DRAINING
                    )
                )
            }))
        || (lifecycle == MountLifecycle::MOUNT_LIFECYCLE_DRAINING
            && resource.lifecycle == MountLifecycle::MOUNT_LIFECYCLE_RELEASING
            && resource.installed_observation.is_some()
            && resource.replaced_by_mount_handle.is_some())
        || (lifecycle == MountLifecycle::MOUNT_LIFECYCLE_DRAINING
            && resource.lifecycle == MountLifecycle::MOUNT_LIFECYCLE_FAULTED
            && resource
                .fault
                .is_some_and(|fault| fault.from == MountFaultPhase::MOUNT_FAULT_PHASE_RELEASING)
            && resource.installed_observation.is_some()
            && resource.replaced_by_mount_handle.is_some())
}

fn validate_replacement_correlations(
    mounts: &[ValidatedMountInventoryRecord],
) -> Result<(), ProtocolValidationError> {
    for resource in mounts {
        if let Some(replaced_handle) = resource
            .publication
            .and_then(|value| value.replaces_mount_handle)
        {
            let replaced = find_mount(mounts, replaced_handle)?;
            if !declares_replacement(resource, replaced) {
                return Err(ProtocolValidationError::InvalidField(
                    "inventory replacement correlation",
                ));
            }
        }
        if let Some(successor_handle) = resource.replaced_by_mount_handle {
            let successor = find_mount(mounts, successor_handle)?;
            if !declares_replacement(successor, resource) {
                return Err(ProtocolValidationError::InvalidField(
                    "inventory replacement correlation",
                ));
            }
        }
    }
    Ok(())
}

fn find_mount(
    mounts: &[ValidatedMountInventoryRecord],
    handle: [u8; 32],
) -> Result<&ValidatedMountInventoryRecord, ProtocolValidationError> {
    mounts
        .binary_search_by_key(&handle, |value| value.mount_handle)
        .ok()
        .map(|index| &mounts[index])
        .ok_or(ProtocolValidationError::InvalidField(
            "inventory replacement correlation",
        ))
}

fn same_slot(left: &ValidatedMountInventoryRecord, right: &ValidatedMountInventoryRecord) -> bool {
    left.recipe.attachment_id == right.recipe.attachment_id
        && left.recipe.destination_slot_id == right.recipe.destination_slot_id
}

fn binding_strictly_advances(
    successor: &ValidatedMountAssignmentBinding,
    predecessor: &ValidatedMountAssignmentBinding,
) -> bool {
    successor.fence.sandbox_id() == predecessor.fence.sandbox_id()
        && successor.fence.incarnation_id() == predecessor.fence.incarnation_id()
        && successor.namespace_generation == predecessor.namespace_generation
        && (
            successor.fence.assignment_epoch(),
            successor.fence.desired_generation(),
        ) > (
            predecessor.fence.assignment_epoch(),
            predecessor.fence.desired_generation(),
        )
}

#[allow(clippy::too_many_lines)]
fn validate_record(
    record: &MountInventoryRecord,
) -> Result<ValidatedMountInventoryRecord, ProtocolValidationError> {
    reject_unknown(&record.__buffa_unknown_fields)?;
    let mount_handle = exact_nonzero::<32>(&record.mount_handle, "inventory.mount_handle")?;
    let (lifecycle, resource_kernel_boot_id) = validate_record_identity(record)?;
    let binding = validate_binding(
        record
            .binding
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("inventory.binding"))?,
    )?;
    let recipe = validate_recipe(
        record
            .recipe
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("inventory.recipe"))?,
    )?;
    if recipe.source_kernel_boot_id != resource_kernel_boot_id {
        return Err(ProtocolValidationError::InvalidField(
            "inventory recipe source kernel boot",
        ));
    }
    let creation = record
        .creation
        .as_option()
        .map(validate_operation)
        .transpose()?;
    let detachment = record
        .detachment
        .as_option()
        .map(validate_operation)
        .transpose()?;
    let release = record
        .release
        .as_option()
        .map(validate_operation)
        .transpose()?;
    let detached_unique_mount_id = record
        .detached_unique_mount_id
        .map(|value| nonzero(value, "inventory.detached_unique_mount_id"))
        .transpose()?;
    let installed_observation = record
        .installed_observation
        .as_option()
        .map(validate_observation)
        .transpose()?;
    if installed_observation
        .as_ref()
        .is_some_and(|observation| Some(observation.unique_mount_id) != detached_unique_mount_id)
    {
        return Err(ProtocolValidationError::InvalidField(
            "inventory installed mount identity",
        ));
    }
    let publication = record
        .publication
        .as_option()
        .map(|value| validate_publication(value, mount_handle))
        .transpose()?;
    if publication.is_some_and(|value| {
        value.target_namespace_generation != binding.namespace_generation
            || installed_observation.as_ref().is_some_and(|observation| {
                observation.mount_namespace_id != value.target_mount_namespace_id
            })
    }) {
        return Err(ProtocolValidationError::InvalidField(
            "inventory publication target",
        ));
    }
    let replaced_by_mount_handle = optional_handle(
        &record.replaced_by_mount_handle,
        "inventory.replaced_by_mount_handle",
    )?;
    if replaced_by_mount_handle == Some(mount_handle) {
        return Err(ProtocolValidationError::InvalidField(
            "inventory replacement self correlation",
        ));
    }
    let fault = record.fault.as_option().map(validate_fault).transpose()?;
    let last_installed_unique_mount_id = record
        .last_installed_unique_mount_id
        .map(|value| nonzero(value, "inventory.last_installed_unique_mount_id"))
        .transpose()?;
    let presence = (u16::from(detached_unique_mount_id.is_some()) * HAS_DETACHED)
        | (u16::from(installed_observation.is_some()) * HAS_INSTALLED)
        | (u16::from(creation.is_some()) * HAS_CREATION)
        | (u16::from(detachment.is_some()) * HAS_DETACHMENT)
        | (u16::from(release.is_some()) * HAS_RELEASE)
        | (u16::from(publication.is_some()) * HAS_PUBLICATION)
        | (u16::from(replaced_by_mount_handle.is_some()) * HAS_REPLACEMENT)
        | (u16::from(fault.is_some()) * HAS_FAULT)
        | (u16::from(last_installed_unique_mount_id.is_some()) * HAS_LAST_INSTALLED);
    validate_lifecycle_shape(lifecycle, presence, fault.map(|value| value.from))?;

    Ok(ValidatedMountInventoryRecord {
        mount_handle,
        resource_revision: record.resource_revision,
        binding,
        recipe,
        lifecycle,
        resource_kernel_boot_id,
        creation,
        detachment,
        release,
        detached_unique_mount_id,
        installed_observation,
        publication,
        replaced_by_mount_handle,
        fault,
        last_installed_unique_mount_id,
    })
}

fn validate_record_identity(
    record: &MountInventoryRecord,
) -> Result<(MountLifecycle, [u8; 16]), ProtocolValidationError> {
    nonzero(record.resource_revision, "inventory.resource_revision")?;
    let lifecycle = record
        .lifecycle
        .as_known()
        .filter(|value| *value != MountLifecycle::MOUNT_LIFECYCLE_UNSPECIFIED)
        .ok_or(ProtocolValidationError::UnknownState)?;
    let boot_id = exact_nonzero::<16>(
        &record.resource_kernel_boot_id,
        "inventory.resource_kernel_boot_id",
    )?;
    Ok((lifecycle, boot_id))
}

fn validate_binding(
    value: &aos_proto::aos::sandbox::local::v1::MountAssignmentBinding,
) -> Result<ValidatedMountAssignmentBinding, ProtocolValidationError> {
    reject_unknown(&value.__buffa_unknown_fields)?;
    let fence = validate_fence(value.fence.as_option().ok_or(
        ProtocolValidationError::MissingField("inventory.binding.fence"),
    )?)?;
    let namespace_generation = nonzero(
        value.namespace_generation,
        "inventory.binding.namespace_generation",
    )?;
    Ok(ValidatedMountAssignmentBinding {
        fence,
        namespace_generation,
    })
}

fn validate_recipe(value: &MountRecipe) -> Result<ValidatedMountRecipe, ProtocolValidationError> {
    reject_unknown(&value.__buffa_unknown_fields)?;
    let attachment_id =
        exact_nonzero::<16>(&value.attachment_id, "inventory.recipe.attachment_id")?;
    let destination_slot_id = exact_nonzero::<16>(
        &value.destination_slot_id,
        "inventory.recipe.destination_slot_id",
    )?;
    let view_revision = validate_descriptor(
        value
            .view_revision
            .as_option()
            .ok_or(ProtocolValidationError::MissingField(
                "inventory.recipe.view_revision",
            ))?,
        DescriptorRole::FilesystemViewRevision,
    )?;
    let source_generation = nonzero(
        value.source_generation,
        "inventory.recipe.source_generation",
    )?;
    let resource_attachment_generation = nonzero(
        value.resource_attachment_generation,
        "inventory.recipe.resource_attachment_generation",
    )?;
    let source_view_id =
        exact_nonzero::<16>(&value.source_view_id, "inventory.recipe.source_view_id")?;
    let source_incarnation_id = if value.source_incarnation_id.is_empty() {
        None
    } else {
        Some(exact_nonzero::<16>(
            &value.source_incarnation_id,
            "inventory.recipe.source_incarnation_id",
        )?)
    };
    let source_consistency = value
        .source_consistency
        .as_known()
        .filter(|consistency| {
            !matches!(
                consistency,
                MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_UNSPECIFIED
                    | MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_TRANSACTIONAL_SERVICE
            )
        })
        .ok_or(ProtocolValidationError::InvalidField(
            "inventory.recipe.source_consistency",
        ))?;
    if source_incarnation_id.is_some()
        != (source_consistency == MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE)
    {
        return Err(ProtocolValidationError::InvalidField(
            "inventory.recipe.source_incarnation_id",
        ));
    }
    let source_assignment_digest = if value.source_assignment_digest.is_empty() {
        None
    } else {
        Some(ObjectDigest::from_bytes(exact_nonzero::<32>(
            &value.source_assignment_digest,
            "inventory.recipe.source_assignment_digest",
        )?))
    };
    // Legacy LocalLive rows remain readable for exact teardown, but their
    // absent assignment digest cannot satisfy a version-two Present decision.
    if source_assignment_digest.is_some()
        && source_consistency != MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE
    {
        return Err(ProtocolValidationError::InvalidField(
            "inventory.recipe.source_assignment_digest",
        ));
    }
    if value.source_authority.as_known()
        != Some(MountInventorySourceAuthority::MOUNT_INVENTORY_SOURCE_AUTHORITY_EXACT)
    {
        return Err(ProtocolValidationError::InvalidField(
            "inventory.recipe.source_authority",
        ));
    }
    let handle = validate_mount_source_handle(
        &value.source_handle,
        source_consistency,
        source_incarnation_id,
    )?;
    let source = Box::new(
        SourceRealizationBindingV1::new_with_source_assignment(
            source_view_id,
            source_generation,
            view_revision.clone(),
            handle,
            source_consistency,
            source_incarnation_id,
            source_assignment_digest,
        )
        .map_err(|_| ProtocolValidationError::InvalidField("inventory.recipe.source_binding"))?,
    );
    if source.digest().as_bytes() != value.source_binding_digest.as_slice() {
        return Err(ProtocolValidationError::InvalidField(
            "inventory.recipe.source_binding_digest",
        ));
    }
    let source_realization_handle = exact_nonzero::<32>(
        &value.source_realization_handle,
        "inventory.recipe.source_realization_handle",
    )?;
    let source_physical_proof_digest = exact_nonzero::<32>(
        &value.source_physical_proof_digest,
        "inventory.recipe.source_physical_proof_digest",
    )?;
    let source_kernel_boot_id = exact_nonzero::<16>(
        &value.source_kernel_boot_id,
        "inventory.recipe.source_kernel_boot_id",
    )?;
    let source_device = nonzero(value.source_device, "inventory.recipe.source_device")?;
    let source_inode = nonzero(value.source_inode, "inventory.recipe.source_inode")?;
    let source_proof_class = value
        .source_proof_class
        .as_known()
        .filter(|proof| {
            matches!(
                (*proof, source_consistency),
                (
                    MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_IMMUTABLE_TREE,
                    MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION
                ) | (
                    MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_LOCAL_LIVE,
                    MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE
                ) | (
                    MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_BEST_EFFORT_REPLICA,
                    MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_BEST_EFFORT_REPLICA
                )
            )
        })
        .ok_or(ProtocolValidationError::InvalidField(
            "inventory.recipe.source_proof_class",
        ))?;
    let source_unique_mount_id = nonzero(
        value.source_unique_mount_id,
        "inventory.recipe.source_unique_mount_id",
    )?;
    let source_provider_authority_id = exact_nonzero::<16>(
        &value.source_provider_authority_id,
        "inventory.recipe.source_provider_authority_id",
    )?;
    let source_provider_authority_generation = nonzero(
        value.source_provider_authority_generation,
        "inventory.recipe.source_provider_authority_generation",
    )?;
    let source_provider_authority_digest = exact_nonzero::<32>(
        &value.source_provider_authority_digest,
        "inventory.recipe.source_provider_authority_digest",
    )?;
    let source_provider_resource_id = exact_nonzero::<32>(
        &value.source_provider_resource_id,
        "inventory.recipe.source_provider_resource_id",
    )?;
    let source_provider_resource_generation = nonzero(
        value.source_provider_resource_generation,
        "inventory.recipe.source_provider_resource_generation",
    )?;
    let source_provider_resource_digest = exact_nonzero::<32>(
        &value.source_provider_resource_digest,
        "inventory.recipe.source_provider_resource_digest",
    )?;
    let source_provider_catalog_generation = nonzero(
        value.source_provider_catalog_generation,
        "inventory.recipe.source_provider_catalog_generation",
    )?;
    let source_provider_catalog_digest = exact_nonzero::<32>(
        &value.source_provider_catalog_digest,
        "inventory.recipe.source_provider_catalog_digest",
    )?;
    let proof_class = match source_proof_class {
        MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_IMMUTABLE_TREE => {
            crate::MountSourceProofClassV1::ImmutableTree
        }
        MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_LOCAL_LIVE => {
            crate::MountSourceProofClassV1::LocalLive
        }
        MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_BEST_EFFORT_REPLICA => {
            crate::MountSourceProofClassV1::BestEffortReplica
        }
        MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_UNSPECIFIED => {
            return Err(ProtocolValidationError::InvalidField(
                "inventory.recipe.source_proof_class",
            ));
        }
    };
    let reproduced_proof =
        crate::mount_source_physical_proof_digest_v1(crate::MountSourcePhysicalProofV1 {
            binding_digest: *source.digest().as_bytes(),
            proof_class,
            provider_authority_id: source_provider_authority_id,
            provider_authority_generation: source_provider_authority_generation,
            provider_authority_digest: source_provider_authority_digest,
            provider_resource_id: source_provider_resource_id,
            provider_resource_generation: source_provider_resource_generation,
            provider_resource_digest: source_provider_resource_digest,
            provider_catalog_generation: source_provider_catalog_generation,
            provider_catalog_digest: source_provider_catalog_digest,
            kernel_boot_id: source_kernel_boot_id,
            device: source_device,
            inode: source_inode,
            unique_mount_id: source_unique_mount_id,
        });
    if reproduced_proof != source_physical_proof_digest
        || crate::mount_source_realization_handle_v1(*source.digest().as_bytes(), reproduced_proof)
            != source_realization_handle
    {
        return Err(ProtocolValidationError::InvalidField(
            "inventory.recipe.source_realization_handle",
        ));
    }
    let attributes = validate_mount_attributes(value.attributes.as_option().ok_or(
        ProtocolValidationError::MissingField("inventory.recipe.attributes"),
    )?)?;
    Ok(ValidatedMountRecipe {
        attachment_id,
        destination_slot_id,
        view_revision,
        source_generation,
        attributes,
        resource_attachment_generation,
        source_view_id,
        source_incarnation_id,
        source_assignment_digest,
        source_consistency,
        source,
        source_realization_handle,
        source_physical_proof_digest,
        source_kernel_boot_id,
        source_device,
        source_inode,
        source_proof_class,
        source_unique_mount_id,
        source_provider_authority_id,
        source_provider_authority_generation,
        source_provider_authority_digest,
        source_provider_resource_id,
        source_provider_resource_generation,
        source_provider_resource_digest,
        source_provider_catalog_generation,
        source_provider_catalog_digest,
    })
}

fn validate_observation(
    value: &MountKernelObservation,
) -> Result<ValidatedMountKernelObservation, ProtocolValidationError> {
    reject_unknown(&value.__buffa_unknown_fields)?;
    let root = validate_kernel_path(&value.root, "inventory.observation.root")?;
    let mount_point =
        validate_kernel_path(&value.mount_point, "inventory.observation.mount_point")?;
    Ok(ValidatedMountKernelObservation {
        unique_mount_id: nonzero(
            value.unique_mount_id,
            "inventory.observation.unique_mount_id",
        )?,
        parent_mount_id: nonzero(
            value.parent_mount_id,
            "inventory.observation.parent_mount_id",
        )?,
        mount_namespace_id: nonzero(
            value.mount_namespace_id,
            "inventory.observation.mount_namespace_id",
        )?,
        device_major: value.device_major,
        device_minor: value.device_minor,
        superblock_magic: nonzero(
            value.superblock_magic,
            "inventory.observation.superblock_magic",
        )?,
        superblock_flags: value.superblock_flags,
        mount_attributes: value.mount_attributes,
        propagation: value.propagation,
        root,
        mount_point,
        identity_map_digest: exact_nonzero::<32>(
            &value.identity_map_digest,
            "inventory.observation.identity_map_digest",
        )?,
    })
}

fn validate_operation(
    value: &MountOperationCorrelation,
) -> Result<ValidatedMountOperationCorrelation, ProtocolValidationError> {
    reject_unknown(&value.__buffa_unknown_fields)?;
    Ok(ValidatedMountOperationCorrelation {
        operation_id: exact_nonzero::<16>(&value.operation_id, "inventory.operation.operation_id")?,
        request_digest: exact_nonzero::<32>(
            &value.request_digest,
            "inventory.operation.request_digest",
        )?,
    })
}

fn validate_publication(
    value: &MountPublicationCorrelation,
    own_handle: [u8; 32],
) -> Result<ValidatedMountPublicationCorrelation, ProtocolValidationError> {
    reject_unknown(&value.__buffa_unknown_fields)?;
    let operation = validate_operation(value.operation.as_option().ok_or(
        ProtocolValidationError::MissingField("inventory.publication.operation"),
    )?)?;
    let replaces_mount_handle = if value.replaces_mount_handle.is_empty() {
        None
    } else {
        Some(exact_nonzero::<32>(
            &value.replaces_mount_handle,
            "inventory.publication.replaces_mount_handle",
        )?)
    };
    if replaces_mount_handle == Some(own_handle) {
        return Err(ProtocolValidationError::InvalidField(
            "inventory publication self replacement",
        ));
    }
    Ok(ValidatedMountPublicationCorrelation {
        operation_id: operation.operation_id,
        request_digest: operation.request_digest,
        target_mount_namespace_id: nonzero(
            value.target_mount_namespace_id,
            "inventory.publication.target_mount_namespace_id",
        )?,
        target_namespace_generation: nonzero(
            value.target_namespace_generation,
            "inventory.publication.target_namespace_generation",
        )?,
        replaces_mount_handle,
    })
}

fn validate_fault(
    value: &MountFaultCorrelation,
) -> Result<ValidatedMountFaultCorrelation, ProtocolValidationError> {
    reject_unknown(&value.__buffa_unknown_fields)?;
    let from = value
        .from
        .as_known()
        .filter(|phase| *phase != MountFaultPhase::MOUNT_FAULT_PHASE_UNSPECIFIED)
        .ok_or(ProtocolValidationError::InvalidField(
            "inventory.fault.from",
        ))?;
    let failure_digest =
        exact_nonzero::<32>(&value.failure_digest, "inventory.fault.failure_digest")?;
    Ok(ValidatedMountFaultCorrelation {
        from,
        failure_digest,
    })
}

fn validate_lifecycle_shape(
    lifecycle: MountLifecycle,
    presence: u16,
    fault_from: Option<MountFaultPhase>,
) -> Result<(), ProtocolValidationError> {
    let valid = match lifecycle {
        MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED => presence == HAS_CREATION,
        MountLifecycle::MOUNT_LIFECYCLE_PREPARED => presence == (HAS_DETACHED | HAS_CREATION),
        MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING => presence == (HAS_DETACHED | HAS_PUBLICATION),
        MountLifecycle::MOUNT_LIFECYCLE_INSTALLED => {
            presence == (HAS_DETACHED | HAS_INSTALLED | HAS_PUBLICATION)
        }
        MountLifecycle::MOUNT_LIFECYCLE_DETACHING => {
            presence == (HAS_DETACHED | HAS_INSTALLED | HAS_DETACHMENT)
        }
        MountLifecycle::MOUNT_LIFECYCLE_DRAINING => {
            presence == (HAS_DETACHED | HAS_INSTALLED | HAS_REPLACEMENT)
        }
        MountLifecycle::MOUNT_LIFECYCLE_RELEASING => {
            presence == (HAS_DETACHED | HAS_RELEASE)
                || presence == (HAS_DETACHED | HAS_INSTALLED | HAS_REPLACEMENT | HAS_RELEASE)
        }
        MountLifecycle::MOUNT_LIFECYCLE_RELEASED => {
            presence & !(HAS_DETACHED | HAS_LAST_INSTALLED) == 0
        }
        MountLifecycle::MOUNT_LIFECYCLE_FAULTED => fault_presence_matches(fault_from, presence),
        MountLifecycle::MOUNT_LIFECYCLE_UNSPECIFIED => false,
    };
    if valid {
        Ok(())
    } else {
        Err(ProtocolValidationError::InvalidField(
            "inventory lifecycle shape",
        ))
    }
}

fn fault_presence(from: Option<MountFaultPhase>) -> Option<u16> {
    match from? {
        MountFaultPhase::MOUNT_FAULT_PHASE_ALLOCATED => Some(HAS_CREATION | HAS_FAULT),
        MountFaultPhase::MOUNT_FAULT_PHASE_PREPARED => {
            Some(HAS_DETACHED | HAS_CREATION | HAS_FAULT)
        }
        MountFaultPhase::MOUNT_FAULT_PHASE_PUBLISHING => {
            Some(HAS_DETACHED | HAS_PUBLICATION | HAS_FAULT)
        }
        MountFaultPhase::MOUNT_FAULT_PHASE_INSTALLED => {
            Some(HAS_DETACHED | HAS_INSTALLED | HAS_PUBLICATION | HAS_FAULT)
        }
        MountFaultPhase::MOUNT_FAULT_PHASE_DETACHING => {
            Some(HAS_DETACHED | HAS_INSTALLED | HAS_DETACHMENT | HAS_FAULT)
        }
        MountFaultPhase::MOUNT_FAULT_PHASE_DRAINING => {
            Some(HAS_DETACHED | HAS_INSTALLED | HAS_REPLACEMENT | HAS_FAULT)
        }
        MountFaultPhase::MOUNT_FAULT_PHASE_RELEASING
        | MountFaultPhase::MOUNT_FAULT_PHASE_UNSPECIFIED => None,
    }
}

fn fault_presence_matches(from: Option<MountFaultPhase>, presence: u16) -> bool {
    if from == Some(MountFaultPhase::MOUNT_FAULT_PHASE_RELEASING) {
        return presence == (HAS_DETACHED | HAS_RELEASE | HAS_FAULT)
            || presence
                == (HAS_DETACHED | HAS_INSTALLED | HAS_REPLACEMENT | HAS_RELEASE | HAS_FAULT);
    }
    fault_presence(from) == Some(presence)
}

fn optional_handle(
    value: &[u8],
    field: &'static str,
) -> Result<Option<[u8; 32]>, ProtocolValidationError> {
    if value.is_empty() {
        Ok(None)
    } else {
        exact_nonzero::<32>(value, field).map(Some)
    }
}

fn validate_kernel_path(
    value: &[u8],
    field: &'static str,
) -> Result<Vec<u8>, ProtocolValidationError> {
    if value.is_empty() || value.len() > MAXIMUM_KERNEL_PATH_BYTES || value.contains(&0) {
        return Err(ProtocolValidationError::InvalidField(field));
    }
    Ok(value.to_vec())
}

fn nonzero(value: u64, field: &'static str) -> Result<u64, ProtocolValidationError> {
    if value == 0 {
        Err(ProtocolValidationError::InvalidField(field))
    } else {
        Ok(value)
    }
}

fn reject_unknown(fields: &buffa::UnknownFields) -> Result<(), ProtocolValidationError> {
    if fields.is_empty() {
        Ok(())
    } else {
        Err(ProtocolValidationError::UnknownFields)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        MountSourcePhysicalProofV1, MountSourceProofClassV1, mount_source_physical_proof_digest_v1,
        mount_source_realization_handle_v1,
    };
    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Descriptor, InventoryMountResourcesResponse, MountAssignmentBinding,
        MountAttributes, MountFaultCorrelation, MountFaultPhase, MountInventoryRecord,
        MountKernelObservation, MountLifecycle, MountOperationCorrelation,
        MountPublicationCorrelation, MountRecipe,
    };

    use super::*;

    fn installed_record(handle_byte: u8, mount_id: u64) -> MountInventoryRecord {
        let fence = AssignmentFence {
            sandbox_id: vec![1; 16],
            incarnation_id: vec![2; 16],
            assignment_epoch: 3,
            desired_generation: 4,
            assignment_digest: vec![5; 32],
            ..Default::default()
        };
        let binding = MountAssignmentBinding {
            fence: Some(fence).into(),
            namespace_generation: 6,
            ..Default::default()
        };
        let revision = Descriptor {
            media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
            sha256: vec![7; 32],
            encoded_size: 8,
            ..Default::default()
        };
        let attributes = MountAttributes {
            read_only: true,
            no_exec: true,
            no_suid: true,
            no_device: true,
            no_atime: true,
            mutation_mode: 0,
            recursive: true,
            ..Default::default()
        };
        let source_handle = crate::immutable_source_handle_fixture();
        let source_binding_digest = SourceRealizationBindingV1::new(
            [14; 16],
            11,
            validate_descriptor(&revision, DescriptorRole::FilesystemViewRevision)
                .unwrap_or_else(|error| panic!("test descriptor failed: {error}")),
            validate_mount_source_handle(
                &source_handle,
                MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
                None,
            )
            .unwrap_or_else(|error| panic!("test source handle failed: {error}")),
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION,
            None,
        )
        .unwrap_or_else(|error| panic!("test source binding failed: {error}"))
        .digest();
        let source_proof = mount_source_physical_proof_digest_v1(MountSourcePhysicalProofV1 {
            binding_digest: *source_binding_digest.as_bytes(),
            proof_class: MountSourceProofClassV1::ImmutableTree,
            provider_authority_id: [24; 16],
            provider_authority_generation: 25,
            provider_authority_digest: [18; 32],
            provider_resource_id: [19; 32],
            provider_resource_generation: 20,
            provider_resource_digest: [21; 32],
            provider_catalog_generation: 22,
            provider_catalog_digest: [23; 32],
            kernel_boot_id: [16; 16],
            device: 26,
            inode: 27,
            unique_mount_id: 17,
        });
        let recipe = MountRecipe {
            attachment_id: vec![9; 16],
            destination_slot_id: vec![10; 16],
            view_revision: Some(revision).into(),
            source_generation: 11,
            resource_attachment_generation: 13,
            source_view_id: vec![14; 16],
            source_consistency: MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION
                .into(),
            source_handle,
            source_authority: MountInventorySourceAuthority::MOUNT_INVENTORY_SOURCE_AUTHORITY_EXACT
                .into(),
            attributes: Some(attributes).into(),
            source_binding_digest: source_binding_digest.as_bytes().to_vec(),
            source_realization_handle: mount_source_realization_handle_v1(
                *source_binding_digest.as_bytes(),
                source_proof,
            )
            .to_vec(),
            source_physical_proof_digest: source_proof.to_vec(),
            source_kernel_boot_id: vec![16; 16],
            source_device: 26,
            source_inode: 27,
            source_proof_class: MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_IMMUTABLE_TREE
                .into(),
            source_unique_mount_id: 17,
            source_provider_authority_id: vec![24; 16],
            source_provider_authority_generation: 25,
            source_provider_authority_digest: vec![18; 32],
            source_provider_resource_id: vec![19; 32],
            source_provider_resource_generation: 20,
            source_provider_resource_digest: vec![21; 32],
            source_provider_catalog_generation: 22,
            source_provider_catalog_digest: vec![23; 32],
            ..Default::default()
        };
        let observation = MountKernelObservation {
            unique_mount_id: mount_id,
            parent_mount_id: 100,
            mount_namespace_id: 200,
            device_major: 8,
            device_minor: 1,
            superblock_magic: 0xef53,
            superblock_flags: 1,
            mount_attributes: 2,
            propagation: 4,
            root: b"/root".to_vec(),
            mount_point: b"/mnt/view".to_vec(),
            identity_map_digest: vec![12; 32],
            ..Default::default()
        };
        let publication = MountPublicationCorrelation {
            operation: Some(MountOperationCorrelation {
                operation_id: vec![13; 16],
                request_digest: vec![14; 32],
                ..Default::default()
            })
            .into(),
            target_mount_namespace_id: 200,
            target_namespace_generation: 6,
            ..Default::default()
        };
        MountInventoryRecord {
            mount_handle: vec![handle_byte; 32],
            resource_revision: 12,
            binding: Some(binding).into(),
            recipe: Some(recipe).into(),
            lifecycle: MountLifecycle::MOUNT_LIFECYCLE_INSTALLED.into(),
            resource_kernel_boot_id: vec![16; 16],
            detached_unique_mount_id: Some(mount_id),
            installed_observation: Some(observation).into(),
            publication: Some(publication).into(),
            ..Default::default()
        }
    }

    fn advance_replacement_generation(record: &mut MountInventoryRecord) {
        let fence = record
            .binding
            .get_or_insert_default()
            .fence
            .get_or_insert_default();
        fence.desired_generation = 5;
        fence.assignment_digest = vec![21; 32];
        record
            .recipe
            .get_or_insert_default()
            .resource_attachment_generation = 14;
    }

    fn response(records: Vec<MountInventoryRecord>) -> InventoryMountResourcesResponse {
        InventoryMountResourcesResponse {
            kernel_boot_id: vec![16; 16],
            journal_sequence: 14,
            mounts: records,
            broker_instance_id: vec![17; 16],
            ..Default::default()
        }
    }

    fn released_source_record(handle_byte: u8, mount_id: u64) -> MountInventoryRecord {
        let mut record = installed_record(handle_byte, mount_id);
        record.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_RELEASED.into();
        record.installed_observation = None.into();
        record.publication = None.into();
        record
    }

    fn set_resource_boot(record: &mut MountInventoryRecord, boot_id: [u8; 16]) {
        record.resource_kernel_boot_id = boot_id.to_vec();
        record.recipe.get_or_insert_default().source_kernel_boot_id = boot_id.to_vec();
        recompute_source_commitments(record.recipe.get_or_insert_default());
    }

    fn set_earlier_provider_history(record: &mut MountInventoryRecord) {
        let recipe = record.recipe.get_or_insert_default();
        recipe.source_provider_authority_generation = 24;
        recipe.source_provider_authority_digest = vec![31; 32];
        recipe.source_provider_catalog_generation = 21;
        recipe.source_provider_catalog_digest = vec![32; 32];
        recipe.source_provider_resource_generation = 19;
        recipe.source_provider_resource_digest = vec![33; 32];
        recompute_source_commitments(recipe);
    }

    fn recompute_source_commitments(recipe: &mut MountRecipe) {
        let binding_digest: [u8; 32] = recipe.source_binding_digest.as_slice().try_into().unwrap();
        let proof_class = match recipe.source_proof_class.as_known().unwrap() {
            MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_IMMUTABLE_TREE => {
                MountSourceProofClassV1::ImmutableTree
            }
            MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_LOCAL_LIVE => {
                MountSourceProofClassV1::LocalLive
            }
            MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_BEST_EFFORT_REPLICA => {
                MountSourceProofClassV1::BestEffortReplica
            }
            MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_UNSPECIFIED => unreachable!(),
        };
        let proof = mount_source_physical_proof_digest_v1(MountSourcePhysicalProofV1 {
            binding_digest,
            proof_class,
            provider_authority_id: recipe
                .source_provider_authority_id
                .as_slice()
                .try_into()
                .unwrap(),
            provider_authority_generation: recipe.source_provider_authority_generation,
            provider_authority_digest: recipe
                .source_provider_authority_digest
                .as_slice()
                .try_into()
                .unwrap(),
            provider_resource_id: recipe
                .source_provider_resource_id
                .as_slice()
                .try_into()
                .unwrap(),
            provider_resource_generation: recipe.source_provider_resource_generation,
            provider_resource_digest: recipe
                .source_provider_resource_digest
                .as_slice()
                .try_into()
                .unwrap(),
            provider_catalog_generation: recipe.source_provider_catalog_generation,
            provider_catalog_digest: recipe
                .source_provider_catalog_digest
                .as_slice()
                .try_into()
                .unwrap(),
            kernel_boot_id: recipe.source_kernel_boot_id.as_slice().try_into().unwrap(),
            device: recipe.source_device,
            inode: recipe.source_inode,
            unique_mount_id: recipe.source_unique_mount_id,
        });
        recipe.source_physical_proof_digest = proof.to_vec();
        recipe.source_realization_handle =
            mount_source_realization_handle_v1(binding_digest, proof).to_vec();
    }

    fn move_physical_source(recipe: &mut MountRecipe, offset: u64) {
        recipe.source_device += offset;
        recipe.source_inode += offset;
        recipe.source_unique_mount_id += offset;
        recompute_source_commitments(recipe);
    }

    fn move_logical_binding(recipe: &mut MountRecipe, source_view_id: [u8; 16]) {
        recipe.source_view_id = source_view_id.to_vec();
        let consistency = recipe.source_consistency.as_known().unwrap();
        let source_incarnation_id = (!recipe.source_incarnation_id.is_empty())
            .then(|| recipe.source_incarnation_id.as_slice().try_into().unwrap());
        let binding = SourceRealizationBindingV1::new(
            source_view_id,
            recipe.source_generation,
            validate_descriptor(
                recipe.view_revision.as_option().unwrap(),
                DescriptorRole::FilesystemViewRevision,
            )
            .unwrap(),
            validate_mount_source_handle(&recipe.source_handle, consistency, source_incarnation_id)
                .unwrap(),
            consistency,
            source_incarnation_id,
        )
        .unwrap();
        recipe.source_binding_digest = binding.digest().as_bytes().to_vec();
        recompute_source_commitments(recipe);
    }

    #[test]
    fn inventory_request_binds_the_mount_broker_header() {
        let mut request = InventoryMountsRequest::default();
        let header = request.header.get_or_insert_default();
        header.protocol_major = 2;
        header.protocol_minor = 0;
        header.request_id = vec![15; 16];
        header.audience =
            aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER.into();
        header.deadline_boottime_nanoseconds = 101;
        header.maximum_response_bytes = MINIMUM_RESPONSE_BYTES;
        let peer = PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        };
        let policy = PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER,
        };

        let validated = decode_mount_inventory_request(&request.encode_to_vec(), peer, policy, 100)
            .unwrap_or_else(|error| panic!("valid inventory request failed: {error}"));
        assert_eq!(validated.request_id(), &[15; 16]);
        assert_eq!(validated.maximum_response_bytes(), MINIMUM_RESPONSE_BYTES);
    }

    #[test]
    fn complete_inventory_preserves_authoritative_identity() {
        let encoded = response(vec![installed_record(1, 101)]).encode_to_vec();
        let inventory = decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES)
            .unwrap_or_else(|error| panic!("valid inventory failed: {error}"));
        assert_eq!(inventory.kernel_boot_id(), &[16; 16]);
        assert_eq!(inventory.broker_instance_id(), &[17; 16]);
        assert_eq!(inventory.journal_sequence(), 14);
        let record = &inventory.mounts()[0];
        assert_eq!(record.mount_handle(), &[1; 32]);
        assert_eq!(record.resource_revision(), 12);
        assert_eq!(record.binding().fence().assignment_epoch(), 3);
        assert_eq!(record.binding().namespace_generation(), 6);
        assert_eq!(record.recipe().attachment_id(), &[9; 16]);
        assert_eq!(record.recipe().resource_attachment_generation(), 13);
        assert_eq!(record.recipe().source_view_id(), &[14; 16]);
        let source_binding = record.recipe().source();
        assert!(matches!(
            source_binding.source(),
            aos_sandbox_core::model::ViewSource::ImmutableTree { .. }
        ));
        assert!(record.recipe().attributes().recursive());
        assert_eq!(record.resource_kernel_boot_id(), &[16; 16]);
        assert_eq!(record.detached_unique_mount_id(), Some(101));
        assert_eq!(
            record
                .installed_observation()
                .map(ValidatedMountKernelObservation::unique_mount_id),
            Some(101)
        );
    }

    #[test]
    fn legacy_live_recipe_is_readable_but_distinct_from_assignment_bound_recipe() {
        let mut record = installed_record(1, 101);
        let recipe = record.recipe.get_or_insert_default();
        recipe.source_consistency =
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE.into();
        recipe.source_incarnation_id = vec![31; 16];
        recipe.source_handle = crate::live_source_handle_fixture(recipe.source_generation);
        recipe.source_proof_class =
            MountSourceProofClass::MOUNT_SOURCE_PROOF_CLASS_LOCAL_LIVE.into();
        let source_generation = recipe.source_generation;
        let descriptor = validate_descriptor(
            recipe.view_revision.as_option().unwrap(),
            DescriptorRole::FilesystemViewRevision,
        )
        .unwrap();
        let source = validate_mount_source_handle(
            &recipe.source_handle,
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
            Some([31; 16]),
        )
        .unwrap();
        let legacy = SourceRealizationBindingV1::new(
            [14; 16],
            source_generation,
            descriptor.clone(),
            source.clone(),
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
            Some([31; 16]),
        )
        .unwrap();
        recipe.source_binding_digest = legacy.digest().as_bytes().to_vec();
        recompute_source_commitments(recipe);

        let legacy_inventory = decode_mount_inventory_response(
            &response(vec![record.clone()]).encode_to_vec(),
            MINIMUM_RESPONSE_BYTES,
        )
        .unwrap();
        assert_eq!(
            legacy_inventory.mounts()[0]
                .recipe()
                .source_assignment_digest(),
            None
        );

        let current = SourceRealizationBindingV1::new_with_source_assignment(
            [14; 16],
            source_generation,
            descriptor,
            source,
            MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_LOCAL_LIVE,
            Some([31; 16]),
            Some(ObjectDigest::from_bytes([32; 32])),
        )
        .unwrap();
        let recipe = record.recipe.get_or_insert_default();
        recipe.source_assignment_digest = vec![32; 32];
        recipe.source_binding_digest = current.digest().as_bytes().to_vec();
        recompute_source_commitments(recipe);
        let current_inventory = decode_mount_inventory_response(
            &response(vec![record.clone()]).encode_to_vec(),
            MINIMUM_RESPONSE_BYTES,
        )
        .unwrap();
        assert_eq!(
            current_inventory.mounts()[0]
                .recipe()
                .source_assignment_digest(),
            Some(ObjectDigest::from_bytes([32; 32]))
        );

        record
            .recipe
            .get_or_insert_default()
            .source_assignment_digest = vec![0; 32];
        assert!(
            decode_mount_inventory_response(
                &response(vec![record]).encode_to_vec(),
                MINIMUM_RESPONSE_BYTES,
            )
            .is_err()
        );
    }

    #[test]
    fn inventory_requires_exact_source_authority() {
        let exact_record = installed_record(1, 101);
        let exact_response = response(vec![exact_record.clone()]).encode_to_vec();
        let exact = decode_mount_inventory_response(&exact_response, MINIMUM_RESPONSE_BYTES)
            .unwrap_or_else(|error| panic!("exact inventory failed: {error}"));
        assert!(matches!(
            exact.mounts()[0].recipe().source().source(),
            aos_sandbox_core::model::ViewSource::ImmutableTree { .. }
        ));

        let mut absent = exact_record.clone();
        absent.recipe.get_or_insert_default().source_handle.clear();
        assert!(matches!(
            decode_mount_inventory_response(
                &response(vec![absent]).encode_to_vec(),
                MINIMUM_RESPONSE_BYTES,
            ),
            Err(ProtocolValidationError::MissingField("source_handle"))
        ));

        let mut unspecified = exact_record.clone();
        unspecified.recipe.get_or_insert_default().source_authority =
            MountInventorySourceAuthority::MOUNT_INVENTORY_SOURCE_AUTHORITY_UNSPECIFIED.into();
        assert!(matches!(
            decode_mount_inventory_response(
                &response(vec![unspecified]).encode_to_vec(),
                MINIMUM_RESPONSE_BYTES,
            ),
            Err(ProtocolValidationError::InvalidField(
                "inventory.recipe.source_authority"
            ))
        ));

        let mut malformed = exact_record;
        malformed.recipe.get_or_insert_default().source_handle = vec![0xff];
        assert!(
            decode_mount_inventory_response(
                &response(vec![malformed]).encode_to_vec(),
                MINIMUM_RESPONSE_BYTES,
            )
            .is_err()
        );

        for field in ["proof", "handle"] {
            let mut forged = installed_record(1, 101);
            let recipe = forged.recipe.get_or_insert_default();
            match field {
                "proof" => recipe.source_physical_proof_digest[0] ^= 1,
                "handle" => recipe.source_realization_handle[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(
                decode_mount_inventory_response(
                    &response(vec![forged]).encode_to_vec(),
                    MINIMUM_RESPONSE_BYTES,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn live_kernel_lifecycles_must_belong_to_the_inventory_boot() {
        let operation = || {
            Some(MountOperationCorrelation {
                operation_id: vec![18; 16],
                request_digest: vec![19; 32],
                ..Default::default()
            })
            .into()
        };

        let mut allocated = installed_record(1, 100);
        allocated.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_ALLOCATED.into();
        allocated.detached_unique_mount_id = None;
        allocated.installed_observation = None.into();
        allocated.publication = None.into();
        allocated.creation = operation();

        let mut prepared = installed_record(1, 101);
        prepared.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_PREPARED.into();
        prepared.installed_observation = None.into();
        prepared.publication = None.into();
        prepared.creation = operation();

        let mut publishing = installed_record(1, 101);
        publishing.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING.into();
        publishing.installed_observation = None.into();

        let installed = installed_record(1, 101);

        let mut detaching = installed_record(1, 101);
        detaching.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_DETACHING.into();
        detaching.publication = None.into();
        detaching.detachment = operation();

        let mut draining = installed_record(1, 101);
        draining.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_DRAINING.into();
        draining.publication = None.into();
        draining.replaced_by_mount_handle = vec![2; 32];

        let mut releasing = installed_record(1, 101);
        releasing.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_RELEASING.into();
        releasing.installed_observation = None.into();
        releasing.publication = None.into();
        releasing.release = operation();

        for mut record in [
            allocated, prepared, publishing, installed, detaching, draining, releasing,
        ] {
            set_resource_boot(&mut record, [15; 16]);
            let encoded = response(vec![record]).encode_to_vec();
            assert_eq!(
                decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES),
                Err(ProtocolValidationError::InvalidField(
                    "inventory current kernel boot"
                ))
            );
        }
    }

    #[test]
    fn historical_terminal_rows_may_precede_the_inventory_boot() {
        let mut released = installed_record(2, 101);
        released.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_RELEASED.into();
        set_resource_boot(&mut released, [15; 16]);
        set_earlier_provider_history(&mut released);
        released.installed_observation = None.into();
        released.publication = None.into();

        let mut faulted = installed_record(3, 102);
        faulted.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_FAULTED.into();
        set_resource_boot(&mut faulted, [15; 16]);
        set_earlier_provider_history(&mut faulted);
        faulted.fault = Some(MountFaultCorrelation {
            from: MountFaultPhase::MOUNT_FAULT_PHASE_INSTALLED.into(),
            failure_digest: vec![20; 32],
            ..Default::default()
        })
        .into();

        // Numerical IDs are scoped by boot. Historical terminal rows do not
        // claim the current slot or alias its current kernel object.
        let current = installed_record(4, 101);
        let encoded = response(vec![released, faulted, current]).encode_to_vec();
        let inventory = decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES)
            .unwrap_or_else(|error| panic!("historical inventory failed: {error}"));
        assert_eq!(inventory.mounts().len(), 3);
    }

    #[test]
    fn inventory_rejects_physical_source_aliases_across_distinct_handles() {
        let first = installed_record(1, 101);
        let mut second = installed_record(2, 102);
        let recipe = second.recipe.get_or_insert_default();
        recipe.source_provider_resource_id = vec![31; 32];
        recipe.source_provider_resource_generation += 1;
        recipe.source_provider_resource_digest = vec![32; 32];
        recompute_source_commitments(recipe);

        let error = decode_mount_inventory_response(
            &response(vec![first, second]).encode_to_vec(),
            MINIMUM_RESPONSE_BYTES,
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProtocolValidationError::InvalidField("inventory physical source alias")
        );
    }

    #[test]
    fn released_history_does_not_reserve_a_reused_physical_source() {
        let first = released_source_record(1, 101);
        let mut second = released_source_record(2, 102);
        let second_recipe = second.recipe.get_or_insert_default();
        move_physical_source(second_recipe, 10);
        second_recipe.source_provider_resource_id = vec![31; 32];
        second_recipe.source_provider_resource_digest = vec![32; 32];
        recompute_source_commitments(second_recipe);

        let mut reused = installed_record(3, 103);
        let reused_recipe = reused.recipe.get_or_insert_default();
        reused_recipe.source_provider_resource_id = vec![41; 32];
        reused_recipe.source_provider_resource_digest = vec![42; 32];
        recompute_source_commitments(reused_recipe);

        let inventory = decode_mount_inventory_response(
            &response(vec![first, second, reused]).encode_to_vec(),
            MINIMUM_RESPONSE_BYTES,
        )
        .unwrap_or_else(|error| panic!("released source reuse failed: {error}"));
        assert_eq!(inventory.mounts().len(), 3);
    }

    #[test]
    fn inventory_rejects_provider_generation_equivocation_across_realizations() {
        let first = released_source_record(1, 101);
        let mut second = released_source_record(2, 102);
        let recipe = second.recipe.get_or_insert_default();
        recipe.source_device += 10;
        recipe.source_inode += 10;
        recipe.source_unique_mount_id += 10;
        recipe.source_provider_authority_digest = vec![33; 32];
        recompute_source_commitments(recipe);

        let error = decode_mount_inventory_response(
            &response(vec![first, second]).encode_to_vec(),
            MINIMUM_RESPONSE_BYTES,
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProtocolValidationError::InvalidField(
                "inventory source provider authority equivocation"
            )
        );
    }

    #[test]
    fn inventory_rejects_crossed_provider_authority_and_catalog_history() {
        let first = released_source_record(1, 101);
        let mut crossed = released_source_record(2, 102);
        let recipe = crossed.recipe.get_or_insert_default();
        move_physical_source(recipe, 10);
        recipe.source_provider_authority_generation += 1;
        recipe.source_provider_authority_digest = vec![31; 32];
        recipe.source_provider_catalog_generation -= 1;
        recipe.source_provider_catalog_digest = vec![32; 32];
        recompute_source_commitments(recipe);

        assert_eq!(
            decode_mount_inventory_response(
                &response(vec![first, crossed]).encode_to_vec(),
                MINIMUM_RESPONSE_BYTES,
            ),
            Err(ProtocolValidationError::InvalidField(
                "inventory source provider history"
            ))
        );
    }

    #[test]
    fn inventory_rejects_resource_rollback_across_logical_bindings() {
        let first = released_source_record(1, 101);
        let mut rollback = released_source_record(2, 102);
        let recipe = rollback.recipe.get_or_insert_default();
        move_logical_binding(recipe, [44; 16]);
        move_physical_source(recipe, 10);
        recipe.source_provider_authority_generation += 1;
        recipe.source_provider_authority_digest = vec![31; 32];
        recipe.source_provider_catalog_generation += 1;
        recipe.source_provider_catalog_digest = vec![32; 32];
        recipe.source_provider_resource_generation -= 1;
        recipe.source_provider_resource_digest = vec![33; 32];
        recompute_source_commitments(recipe);

        assert_eq!(
            decode_mount_inventory_response(
                &response(vec![first, rollback]).encode_to_vec(),
                MINIMUM_RESPONSE_BYTES,
            ),
            Err(ProtocolValidationError::InvalidField(
                "inventory source provider history"
            ))
        );
    }

    #[test]
    fn inventory_rejects_equal_resource_generation_proof_equivocation() {
        let first = released_source_record(1, 101);
        let mut equivocation = released_source_record(2, 102);
        move_physical_source(equivocation.recipe.get_or_insert_default(), 10);

        assert_eq!(
            decode_mount_inventory_response(
                &response(vec![first, equivocation]).encode_to_vec(),
                MINIMUM_RESPONSE_BYTES,
            ),
            Err(ProtocolValidationError::InvalidField(
                "inventory source provider history"
            ))
        );
    }

    #[test]
    fn released_rows_reject_proof_and_handle_substitution_independently() {
        let released = released_source_record(1, 101);
        for field in ["proof", "handle"] {
            let mut forged = released.clone();
            let recipe = forged.recipe.get_or_insert_default();
            match field {
                "proof" => recipe.source_physical_proof_digest[0] ^= 1,
                "handle" => recipe.source_realization_handle[0] ^= 1,
                _ => unreachable!(),
            }

            assert!(
                decode_mount_inventory_response(
                    &response(vec![forged]).encode_to_vec(),
                    MINIMUM_RESPONSE_BYTES,
                )
                .is_err(),
                "accepted released {field} substitution"
            );
        }
    }

    #[test]
    fn releasing_inventory_retains_exact_operation_correlation() {
        let mut record = installed_record(1, 101);
        record.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_RELEASING.into();
        record.installed_observation = None.into();
        record.publication = None.into();
        record.release = Some(MountOperationCorrelation {
            operation_id: vec![18; 16],
            request_digest: vec![19; 32],
            ..Default::default()
        })
        .into();
        let encoded = response(vec![record]).encode_to_vec();
        let inventory = decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES)
            .unwrap_or_else(|error| panic!("valid releasing inventory failed: {error}"));
        assert_eq!(
            inventory.mounts()[0]
                .release()
                .map(|value| *value.operation_id()),
            Some([18; 16])
        );
    }

    #[test]
    fn faulted_releasing_replacement_pair_remains_reciprocal() {
        let mut predecessor = installed_record(1, 101);
        predecessor.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_FAULTED.into();
        predecessor.publication = None.into();
        predecessor.replaced_by_mount_handle = vec![2; 32];
        predecessor.release = Some(MountOperationCorrelation {
            operation_id: vec![18; 16],
            request_digest: vec![19; 32],
            ..Default::default()
        })
        .into();
        predecessor.fault = Some(MountFaultCorrelation {
            from: MountFaultPhase::MOUNT_FAULT_PHASE_RELEASING.into(),
            failure_digest: vec![20; 32],
            ..Default::default()
        })
        .into();

        let mut successor = installed_record(2, 102);
        advance_replacement_generation(&mut successor);
        successor
            .publication
            .get_or_insert_default()
            .replaces_mount_handle = vec![1; 32];
        successor.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_FAULTED.into();
        successor.fault = Some(MountFaultCorrelation {
            from: MountFaultPhase::MOUNT_FAULT_PHASE_INSTALLED.into(),
            failure_digest: vec![22; 32],
            ..Default::default()
        })
        .into();

        let encoded = response(vec![predecessor, successor]).encode_to_vec();
        let inventory = decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES)
            .unwrap_or_else(|error| panic!("faulted reciprocal pair failed: {error}"));
        assert_eq!(inventory.mounts().len(), 2);
    }

    #[test]
    fn replacement_recipe_generation_must_strictly_advance() {
        let predecessor = installed_record(1, 101);
        let mut successor = installed_record(2, 102);
        advance_replacement_generation(&mut successor);
        successor
            .recipe
            .get_or_insert_default()
            .resource_attachment_generation = 13;
        successor.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_PUBLISHING.into();
        successor.installed_observation = None.into();
        successor
            .publication
            .get_or_insert_default()
            .replaces_mount_handle = vec![1; 32];

        let encoded = response(vec![predecessor, successor]).encode_to_vec();
        assert_eq!(
            decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES),
            Err(ProtocolValidationError::InvalidField(
                "inventory replacement correlation"
            ))
        );
    }

    #[test]
    fn reciprocal_replacement_rows_must_share_one_kernel_boot() {
        let mut predecessor = installed_record(1, 101);
        predecessor.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_FAULTED.into();
        set_resource_boot(&mut predecessor, [15; 16]);
        set_earlier_provider_history(&mut predecessor);
        predecessor.publication = None.into();
        predecessor.replaced_by_mount_handle = vec![2; 32];
        predecessor.fault = Some(MountFaultCorrelation {
            from: MountFaultPhase::MOUNT_FAULT_PHASE_DRAINING.into(),
            failure_digest: vec![20; 32],
            ..Default::default()
        })
        .into();

        let mut successor = installed_record(2, 102);
        advance_replacement_generation(&mut successor);
        successor
            .publication
            .get_or_insert_default()
            .replaces_mount_handle = vec![1; 32];
        successor.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_FAULTED.into();
        successor.fault = Some(MountFaultCorrelation {
            from: MountFaultPhase::MOUNT_FAULT_PHASE_INSTALLED.into(),
            failure_digest: vec![22; 32],
            ..Default::default()
        })
        .into();

        let encoded = response(vec![predecessor, successor]).encode_to_vec();
        assert_eq!(
            decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES),
            Err(ProtocolValidationError::InvalidField(
                "inventory replacement correlation"
            ))
        );
    }

    #[test]
    fn historical_installed_forward_edge_requires_draining_reciprocity() {
        let mut predecessor = installed_record(1, 101);
        set_resource_boot(&mut predecessor, [15; 16]);
        predecessor.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_FAULTED.into();
        predecessor.fault = Some(MountFaultCorrelation {
            from: MountFaultPhase::MOUNT_FAULT_PHASE_INSTALLED.into(),
            failure_digest: vec![20; 32],
            ..Default::default()
        })
        .into();

        let mut successor = installed_record(2, 102);
        set_resource_boot(&mut successor, [15; 16]);
        advance_replacement_generation(&mut successor);
        successor
            .publication
            .get_or_insert_default()
            .replaces_mount_handle = vec![1; 32];
        successor.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_FAULTED.into();
        successor.fault = Some(MountFaultCorrelation {
            from: MountFaultPhase::MOUNT_FAULT_PHASE_INSTALLED.into(),
            failure_digest: vec![22; 32],
            ..Default::default()
        })
        .into();

        let encoded = response(vec![predecessor, successor]).encode_to_vec();
        assert_eq!(
            decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES),
            Err(ProtocolValidationError::InvalidField(
                "inventory replacement correlation"
            ))
        );
    }

    #[test]
    fn historical_publishing_cannot_replace_a_draining_row() {
        let mut predecessor = installed_record(1, 101);
        set_resource_boot(&mut predecessor, [15; 16]);
        predecessor.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_FAULTED.into();
        predecessor.publication = None.into();
        predecessor.replaced_by_mount_handle = vec![2; 32];
        predecessor.fault = Some(MountFaultCorrelation {
            from: MountFaultPhase::MOUNT_FAULT_PHASE_DRAINING.into(),
            failure_digest: vec![20; 32],
            ..Default::default()
        })
        .into();

        let mut successor = installed_record(2, 102);
        set_resource_boot(&mut successor, [15; 16]);
        advance_replacement_generation(&mut successor);
        successor
            .publication
            .get_or_insert_default()
            .replaces_mount_handle = vec![1; 32];
        successor.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_FAULTED.into();
        successor.installed_observation = None.into();
        successor.fault = Some(MountFaultCorrelation {
            from: MountFaultPhase::MOUNT_FAULT_PHASE_PUBLISHING.into(),
            failure_digest: vec![22; 32],
            ..Default::default()
        })
        .into();

        let encoded = response(vec![predecessor, successor]).encode_to_vec();
        assert_eq!(
            decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES),
            Err(ProtocolValidationError::InvalidField(
                "inventory replacement correlation"
            ))
        );
    }

    #[test]
    fn historical_publishing_to_installed_one_way_edge_is_valid() {
        let mut predecessor = installed_record(1, 101);
        set_resource_boot(&mut predecessor, [15; 16]);
        predecessor.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_FAULTED.into();
        predecessor.fault = Some(MountFaultCorrelation {
            from: MountFaultPhase::MOUNT_FAULT_PHASE_INSTALLED.into(),
            failure_digest: vec![20; 32],
            ..Default::default()
        })
        .into();

        let mut successor = installed_record(2, 102);
        set_resource_boot(&mut successor, [15; 16]);
        advance_replacement_generation(&mut successor);
        successor
            .publication
            .get_or_insert_default()
            .replaces_mount_handle = vec![1; 32];
        successor.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_FAULTED.into();
        successor.installed_observation = None.into();
        successor.fault = Some(MountFaultCorrelation {
            from: MountFaultPhase::MOUNT_FAULT_PHASE_PUBLISHING.into(),
            failure_digest: vec![22; 32],
            ..Default::default()
        })
        .into();

        let encoded = response(vec![predecessor, successor]).encode_to_vec();
        let inventory = decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES)
            .unwrap_or_else(|error| panic!("valid historical publication failed: {error}"));
        assert_eq!(inventory.mounts().len(), 2);
    }

    #[test]
    fn ordinary_faulted_release_cannot_be_a_replacement_predecessor() {
        let mut predecessor = installed_record(1, 101);
        predecessor.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_FAULTED.into();
        predecessor.installed_observation = None.into();
        predecessor.publication = None.into();
        predecessor.release = Some(MountOperationCorrelation {
            operation_id: vec![18; 16],
            request_digest: vec![19; 32],
            ..Default::default()
        })
        .into();
        predecessor.fault = Some(MountFaultCorrelation {
            from: MountFaultPhase::MOUNT_FAULT_PHASE_RELEASING.into(),
            failure_digest: vec![20; 32],
            ..Default::default()
        })
        .into();

        let mut successor = installed_record(2, 102);
        advance_replacement_generation(&mut successor);
        successor
            .publication
            .get_or_insert_default()
            .replaces_mount_handle = vec![1; 32];

        let encoded = response(vec![predecessor, successor]).encode_to_vec();
        assert_eq!(
            decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES),
            Err(ProtocolValidationError::InvalidField(
                "inventory replacement correlation"
            ))
        );
    }

    #[test]
    fn unknown_nested_fields_and_lifecycle_smuggling_fail_closed() {
        let mut record = installed_record(1, 101);
        let mut hostile = record.encode_to_vec();
        hostile.extend_from_slice(&[0xf8, 0x07, 0x01]);
        record = MountInventoryRecord::decode_from_slice(&hostile)
            .unwrap_or_else(|error| panic!("hostile fixture failed: {error}"));
        let encoded = response(vec![record]).encode_to_vec();
        assert_eq!(
            decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES),
            Err(ProtocolValidationError::UnknownFields)
        );

        let mut record = installed_record(1, 101);
        record.lifecycle = MountLifecycle::MOUNT_LIFECYCLE_RELEASED.into();
        let encoded = response(vec![record]).encode_to_vec();
        assert_eq!(
            decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES),
            Err(ProtocolValidationError::InvalidField(
                "inventory lifecycle shape"
            ))
        );

        let mut record = installed_record(1, 101);
        record.creation = Some(MountOperationCorrelation {
            operation_id: vec![17; 16],
            request_digest: vec![18; 32],
            ..Default::default()
        })
        .into();
        let encoded = response(vec![record]).encode_to_vec();
        assert_eq!(
            decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES),
            Err(ProtocolValidationError::InvalidField(
                "inventory lifecycle shape"
            ))
        );

        let mut record = installed_record(1, 101);
        record
            .installed_observation
            .get_or_insert_default()
            .unique_mount_id = 102;
        let encoded = response(vec![record]).encode_to_vec();
        assert_eq!(
            decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES),
            Err(ProtocolValidationError::InvalidField(
                "inventory installed mount identity"
            ))
        );
    }

    #[test]
    fn order_and_unique_kernel_identity_are_canonical() {
        let encoded =
            response(vec![installed_record(2, 102), installed_record(1, 101)]).encode_to_vec();
        assert_eq!(
            decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES),
            Err(ProtocolValidationError::InvalidField(
                "inventory.mounts order"
            ))
        );

        let encoded =
            response(vec![installed_record(1, 101), installed_record(2, 101)]).encode_to_vec();
        assert_eq!(
            decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES),
            Err(ProtocolValidationError::InvalidField(
                "inventory unique mount IDs"
            ))
        );

        let encoded =
            response(vec![installed_record(1, 101), installed_record(2, 102)]).encode_to_vec();
        assert_eq!(
            decode_mount_inventory_response(&encoded, MINIMUM_RESPONSE_BYTES),
            Err(ProtocolValidationError::InvalidField(
                "inventory destination slot ownership"
            ))
        );
    }

    #[test]
    fn negotiated_response_ceiling_is_applied_before_decode() {
        assert_eq!(
            decode_mount_inventory_response(
                &vec![0; MINIMUM_RESPONSE_BYTES as usize + 1],
                MINIMUM_RESPONSE_BYTES
            ),
            Err(ProtocolValidationError::ResponseTooLarge)
        );
        assert_eq!(
            decode_mount_inventory_response(&[], MINIMUM_RESPONSE_BYTES - 1),
            Err(ProtocolValidationError::InvalidResponseBound)
        );
    }
}
