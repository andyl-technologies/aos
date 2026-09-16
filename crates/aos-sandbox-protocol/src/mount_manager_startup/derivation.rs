//! Pure protected-state derivation of startup descriptor expectations.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest as _, Sha256};

use crate::mount_source_acquisition_state::mount_source_consumption_companion_digest_v2;
use crate::mount_source_acquisition_state::{
    validate_mount_source_state_graph_v2, AcquisitionRecoveryV2, ProviderAttemptStateV2,
    ProviderMethodV2, ProviderStatusV2, ReleaseProofV2, SourceAcquisitionPhaseV2,
    SourceAcquisitionProofClassV2,
};
use crate::mount_source_consumption_state::{
    decode_mount_resource_key_v2, decode_mount_resource_value_v2, decode_source_pin_key_v1,
    decode_source_pin_value_v1, encode_source_pin_value_v1, source_pin_key_v1, MountFaultPhaseV1,
    MountResourceStateV1, SourcePinLifecycleV1, MOUNT_RESOURCE_KEY_PREFIX_V2,
};
use crate::{
    mount_source_physical_proof_digest_v1, mount_source_provider_history_is_valid_v1,
    mount_source_realization_handle_v1, MountSourcePhysicalProofV1, MountSourceProofClassV1,
    MountSourceProviderHistoryV1,
};

use super::{
    encode_mount_manager_startup_policy_v1, mount_manager_startup_derivation_digest_v1,
    mount_manager_startup_listener_identity_v1, startup_expected_table_digest_v1,
    startup_source_subjects_digest_v1, DerivedMountManagerStartupV1, ExpectedStartupDescriptorV1,
    MountManagerStartupDerivationHeadV1, MountManagerStartupPolicyV1, StartupCleanupEvidenceV1,
    StartupCleanupPhaseV1, StartupCleanupSourceSubjectV1, StartupDescriptorPresenceV1,
    StartupDescriptorRoleV1, StartupPersistedCustodyOwnerV1, StartupSourceSubjectV1,
    StartupTerminalSourceSubjectV1, MAXIMUM_STARTUP_ABSENCE_SUBJECTS_V1,
    MAXIMUM_STARTUP_DESCRIPTORS_V1,
};

const MAXIMUM_INPUT_MATERIALIZED_BYTES: usize = 768 * 1_024 * 1_024;
const SOURCE_NAME_PREFIX: &str = "aos-source-v1-";
const MOUNT_NAME_PREFIX: &str = "aos-mount-v1-";

/// Reports a malformed or inconsistent protected startup derivation input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MountManagerStartupDerivationError {
    /// The sealed protected policy is invalid.
    #[error("invalid Mount-manager startup policy")]
    InvalidPolicy,
    /// Namespace-40 acquisition state is invalid.
    #[error("invalid Mount source-acquisition state")]
    InvalidAcquisitionState,
    /// Namespace-39 SourcePin state is invalid.
    #[error("invalid Mount SourcePin state")]
    InvalidSourcePinState,
    /// Namespace-2 Mount-resource lifecycle state is invalid.
    #[error("invalid Mount-resource lifecycle state")]
    InvalidMountResourceState,
    /// Cross-namespace source lifecycle references disagree.
    #[error("inconsistent Mount source lifecycle derivation")]
    InconsistentLifecycle,
    /// A configured or hard startup bound was exceeded.
    #[error("Mount-manager startup derivation exceeds its bound")]
    LimitExceeded,
}

/// Derives the complete expected startup table and terminal absence batch.
///
/// All input families are copied, bytewise sorted, duplicate-checked, and
/// hashed before their canonical values are interpreted. Namespace-2 input may
/// contain unrelated operations; every key in the Mount-resource family must
/// decode exactly, while unrelated keys are excluded from the family head.
///
/// # Errors
///
/// Returns an error for an unsealed policy, malformed record, duplicate key,
/// invalid complete AOSMSA02 graph, inconsistent cross-namespace reference, or
/// any configured or hard count/byte bound violation.
pub fn derive_mount_manager_startup_v1<'a>(
    policy: &MountManagerStartupPolicyV1,
    journal_sequence: u64,
    current_kernel_boot_id: [u8; 16],
    acquisition_records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    source_pin_records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    operation_records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> Result<DerivedMountManagerStartupV1, MountManagerStartupDerivationError> {
    if journal_sequence == 0
        || current_kernel_boot_id == [0; 16]
        || encode_mount_manager_startup_policy_v1(policy).is_err()
    {
        return Err(MountManagerStartupDerivationError::InvalidPolicy);
    }

    let acquisition_records = collect_records(acquisition_records, |_| true)?;
    let source_pin_records = collect_records(source_pin_records, |_| true)?;
    let mount_resource_records = collect_records(operation_records, |key| {
        key.starts_with(MOUNT_RESOURCE_KEY_PREFIX_V2)
    })?;
    let acquisition_graph = validate_mount_source_state_graph_v2(
        acquisition_records
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .map_err(|_| MountManagerStartupDerivationError::InvalidAcquisitionState)?;

    let source_pins = decode_source_pins(&source_pin_records)?;
    let mount_resources = decode_mount_resources(&mount_resource_records)?;
    let mut expected = standard_and_listener_expectations(policy);

    let acquisition_by_handle = acquisition_context_by_handle(&acquisition_graph)?;
    validate_source_pin_correspondence(&source_pins, &acquisition_by_handle)?;
    append_source_expectations(
        &mut expected,
        policy,
        current_kernel_boot_id,
        &source_pins,
        &acquisition_by_handle,
    )?;
    append_mount_expectations(
        &mut expected,
        policy,
        current_kernel_boot_id,
        &mount_resources,
        &source_pins,
    )?;
    expected.sort();
    validate_expected_table(policy, &expected)?;

    let mut source_subjects =
        derive_source_subjects(&acquisition_graph, &source_pins, &mount_resources)?;
    source_subjects.sort();
    if source_subjects.len() > MAXIMUM_STARTUP_ABSENCE_SUBJECTS_V1 {
        return Err(MountManagerStartupDerivationError::LimitExceeded);
    }

    let acquisition_state_digest = exact_record_set_digest(
        b"aos.sandbox.mount-manager.acquisition-state-head.v1\0",
        &acquisition_records,
    );
    let source_pin_state_digest = exact_record_set_digest(
        b"aos.sandbox.mount-manager.source-pin-state-head.v1\0",
        &source_pin_records,
    );
    let mount_resource_state_digest = exact_record_set_digest(
        b"aos.sandbox.mount-manager.mount-resource-state-head.v1\0",
        &mount_resource_records,
    );
    let acquisition_record_count = record_count(&acquisition_records)?;
    let source_pin_record_count = record_count(&source_pin_records)?;
    let mount_resource_record_count = record_count(&mount_resource_records)?;
    let mut head = MountManagerStartupDerivationHeadV1 {
        journal_sequence,
        acquisition_record_count,
        source_pin_record_count,
        mount_resource_record_count,
        acquisition_state_digest,
        source_pin_state_digest,
        mount_resource_state_digest,
        derivation_digest: [0; 32],
    };
    head.derivation_digest = mount_manager_startup_derivation_digest_v1(&head);
    let expected_table_digest = startup_expected_table_digest_v1(&expected)
        .map_err(|_| MountManagerStartupDerivationError::InconsistentLifecycle)?;
    let source_subjects_digest = startup_source_subjects_digest_v1(&source_subjects)
        .map_err(|_| MountManagerStartupDerivationError::InconsistentLifecycle)?;

    Ok(DerivedMountManagerStartupV1 {
        head,
        expected_descriptors: expected,
        source_subjects,
        expected_table_digest,
        source_subjects_digest,
    })
}

fn collect_records<'a>(
    records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    include: impl Fn(&[u8]) -> bool,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, MountManagerStartupDerivationError> {
    let mut materialized = 0usize;
    let mut collected = Vec::new();
    for (key, value) in records {
        if !include(key) {
            continue;
        }
        materialized = materialized
            .checked_add(key.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(MountManagerStartupDerivationError::LimitExceeded)?;
        if materialized > MAXIMUM_INPUT_MATERIALIZED_BYTES
            || collected.len() >= MAXIMUM_STARTUP_DESCRIPTORS_V1 * 16
        {
            return Err(MountManagerStartupDerivationError::LimitExceeded);
        }
        collected.push((key.to_vec(), value.to_vec()));
    }
    collected.sort_by(|left, right| left.0.cmp(&right.0));
    if collected.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(MountManagerStartupDerivationError::InconsistentLifecycle);
    }
    Ok(collected)
}

fn decode_source_pins(
    records: &[(Vec<u8>, Vec<u8>)],
) -> Result<
    BTreeMap<[u8; 32], crate::mount_source_consumption_state::SourcePinRowV1>,
    MountManagerStartupDerivationError,
> {
    let mut pins = BTreeMap::new();
    let mut live_mount_ids = BTreeSet::new();
    let mut live_inodes = BTreeSet::new();
    for (key, value) in records {
        let (binding_digest, handle) = decode_source_pin_key_v1(key)
            .map_err(|_| MountManagerStartupDerivationError::InvalidSourcePinState)?;
        let pin = decode_source_pin_value_v1(value)
            .map_err(|_| MountManagerStartupDerivationError::InvalidSourcePinState)?;
        if pin.handle != handle
            || pin.binding_digest != binding_digest
            || pin.handle == [0; 32]
            || pin.revision == 0
            || pin.binding_digest == [0; 32]
            || pin.physical_proof_digest == [0; 32]
            || pin.provider_authority_id == [0; 16]
            || pin.provider_authority_generation == 0
            || pin.provider_authority_digest == [0; 32]
            || pin.provider_resource_id == [0; 32]
            || pin.provider_resource_generation == 0
            || pin.provider_resource_digest == [0; 32]
            || pin.provider_catalog_generation == 0
            || pin.provider_catalog_digest == [0; 32]
            || pin.kernel_boot_id == [0; 16]
            || pin.device == 0
            || pin.inode == 0
            || pin.unique_mount_id == 0
            || pin.admission_operation_id == [0; 16]
            || pin.admission_request_digest == [0; 32]
            || pin.binding_bytes.is_empty()
            || pin.binding_bytes.len() > 128 * 1_024
            || !canonical_source_pin_lifecycle(&pin)
            || mount_source_physical_proof_digest_v1(MountSourcePhysicalProofV1 {
                binding_digest: pin.binding_digest,
                proof_class: pin.proof_class,
                provider_authority_id: pin.provider_authority_id,
                provider_authority_generation: pin.provider_authority_generation,
                provider_authority_digest: pin.provider_authority_digest,
                provider_resource_id: pin.provider_resource_id,
                provider_resource_generation: pin.provider_resource_generation,
                provider_resource_digest: pin.provider_resource_digest,
                provider_catalog_generation: pin.provider_catalog_generation,
                provider_catalog_digest: pin.provider_catalog_digest,
                kernel_boot_id: pin.kernel_boot_id,
                device: pin.device,
                inode: pin.inode,
                unique_mount_id: pin.unique_mount_id,
            }) != pin.physical_proof_digest
            || mount_source_realization_handle_v1(pin.binding_digest, pin.physical_proof_digest)
                != pin.handle
            || pins.insert(handle, pin.clone()).is_some()
        {
            return Err(MountManagerStartupDerivationError::InvalidSourcePinState);
        }
        if pin.lifecycle != SourcePinLifecycleV1::Released
            && (!live_mount_ids.insert((pin.kernel_boot_id, pin.unique_mount_id))
                || !live_inodes.insert((pin.kernel_boot_id, pin.device, pin.inode)))
        {
            return Err(MountManagerStartupDerivationError::InvalidSourcePinState);
        }
    }
    let history = pins
        .values()
        .map(|pin| MountSourceProviderHistoryV1 {
            authority_id: pin.provider_authority_id,
            authority_generation: pin.provider_authority_generation,
            authority_digest: pin.provider_authority_digest,
            resource_id: pin.provider_resource_id,
            resource_generation: pin.provider_resource_generation,
            resource_digest: pin.provider_resource_digest,
            catalog_generation: pin.provider_catalog_generation,
            catalog_digest: pin.provider_catalog_digest,
            physical_proof_digest: pin.physical_proof_digest,
        })
        .collect::<Vec<_>>();
    if !mount_source_provider_history_is_valid_v1(&history) {
        return Err(MountManagerStartupDerivationError::InvalidSourcePinState);
    }
    Ok(pins)
}

fn canonical_source_pin_lifecycle(
    pin: &crate::mount_source_consumption_state::SourcePinRowV1,
) -> bool {
    matches!(
        (pin.lifecycle, pin.current, pin.revision),
        (SourcePinLifecycleV1::Active, true, 1)
            | (SourcePinLifecycleV1::Active, false, 2)
            | (SourcePinLifecycleV1::Reaping, false, 2 | 3)
            | (SourcePinLifecycleV1::Released, false, 3 | 4)
    )
}

fn decode_mount_resources(
    records: &[(Vec<u8>, Vec<u8>)],
) -> Result<
    BTreeMap<[u8; 32], crate::mount_source_consumption_state::MountResourceV1>,
    MountManagerStartupDerivationError,
> {
    let mut resources = BTreeMap::new();
    let mut store_keys = BTreeSet::new();
    let mut detached_mounts = BTreeSet::new();
    for (key, value) in records {
        let handle = decode_mount_resource_key_v2(key)
            .map_err(|_| MountManagerStartupDerivationError::InvalidMountResourceState)?;
        let resource = decode_mount_resource_value_v2(value)
            .map_err(|_| MountManagerStartupDerivationError::InvalidMountResourceState)?;
        if resource.handle != handle
            || resource.handle == [0; 32]
            || resource.fd_store_key != handle
            || resource.kernel_boot_id == [0; 16]
            || resource.revision == 0
            || resource.recipe.source_realization_handle == [0; 32]
            || !valid_mount_resource_state(&resource.state)
            || mount_descriptor_expectation(&resource.state).is_some_and(|(_, mount_id)| {
                !detached_mounts.insert((resource.kernel_boot_id, mount_id))
            })
            || !store_keys.insert(resource.fd_store_key)
            || resources.insert(handle, resource).is_some()
        {
            return Err(MountManagerStartupDerivationError::InvalidMountResourceState);
        }
    }
    Ok(resources)
}

fn valid_mount_resource_state(state: &MountResourceStateV1) -> bool {
    let valid_detached = |mount_id: u64| mount_id != 0;
    match state {
        MountResourceStateV1::Allocated { creation }
        | MountResourceStateV1::Prepared { creation, .. } => valid_operation(creation),
        MountResourceStateV1::Publishing {
            detached,
            publication,
        }
        | MountResourceStateV1::Installed {
            detached,
            publication,
            ..
        } => valid_detached(detached.unique_mount_id) && valid_publication(publication),
        MountResourceStateV1::Detaching {
            detached,
            detachment,
            ..
        } => valid_detached(detached.unique_mount_id) && valid_operation(detachment),
        MountResourceStateV1::Draining {
            detached,
            replaced_by,
            ..
        } => valid_detached(detached.unique_mount_id) && *replaced_by != [0; 32],
        MountResourceStateV1::Releasing {
            detached,
            release,
            replaced_by,
            ..
        } => {
            valid_detached(detached.unique_mount_id)
                && valid_operation(release)
                && replaced_by.is_none_or(|handle| handle != [0; 32])
        }
        MountResourceStateV1::Released {
            last_detached_mount_id,
            last_installed_mount_id,
        } => {
            last_detached_mount_id.is_none_or(valid_detached)
                && last_installed_mount_id.is_none_or(valid_detached)
        }
        MountResourceStateV1::Faulted {
            from,
            creation,
            publication,
            detachment,
            release,
            replaced_by,
            detached,
            installed,
            failure_digest,
        } => {
            let correlations_match = creation.is_some()
                == matches!(
                    from,
                    MountFaultPhaseV1::Allocated | MountFaultPhaseV1::Prepared
                )
                && publication.is_some()
                    == matches!(
                        from,
                        MountFaultPhaseV1::Publishing | MountFaultPhaseV1::Installed
                    )
                && detachment.is_some() == matches!(from, MountFaultPhaseV1::Detaching)
                && release.is_some() == matches!(from, MountFaultPhaseV1::Releasing);
            let evidence_matches = match from {
                MountFaultPhaseV1::Allocated => detached.is_none() && installed.is_none(),
                MountFaultPhaseV1::Prepared | MountFaultPhaseV1::Publishing => {
                    detached.is_some() && installed.is_none()
                }
                MountFaultPhaseV1::Installed
                | MountFaultPhaseV1::Detaching
                | MountFaultPhaseV1::Draining => detached.is_some() && installed.is_some(),
                MountFaultPhaseV1::Releasing => {
                    detached.is_some() && (installed.is_some() == replaced_by.is_some())
                }
            };
            correlations_match
                && evidence_matches
                && *failure_digest != [0; 32]
                && creation.as_ref().is_none_or(valid_operation)
                && publication.as_ref().is_none_or(valid_publication)
                && detachment.as_ref().is_none_or(valid_operation)
                && release.as_ref().is_none_or(valid_operation)
                && replaced_by.is_none_or(|handle| handle != [0; 32])
                && detached
                    .as_ref()
                    .is_none_or(|identity| valid_detached(identity.unique_mount_id))
        }
    }
}

fn valid_operation(
    operation: &crate::mount_source_consumption_state::OperationCorrelationV1,
) -> bool {
    operation.operation_id != [0; 16] && operation.request_digest != [0; 32]
}

fn valid_publication(
    publication: &crate::mount_source_consumption_state::PublicationCorrelationV1,
) -> bool {
    valid_operation(&publication.operation)
        && publication.target_mount_namespace_id != 0
        && publication.target_namespace_generation != 0
        && publication.replaces.is_none_or(|handle| handle != [0; 32])
}

#[derive(Clone, Debug)]
struct AcquisitionSourceContext {
    row: crate::mount_source_acquisition_state::SourceAcquisitionRowV2,
}

fn acquisition_context_by_handle(
    graph: &crate::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
) -> Result<BTreeMap<[u8; 32], AcquisitionSourceContext>, MountManagerStartupDerivationError> {
    let mut contexts: BTreeMap<[u8; 32], AcquisitionSourceContext> = BTreeMap::new();
    for row in graph.acquisitions.values() {
        let Some(candidate) = &row.evidence else {
            continue;
        };
        let context = AcquisitionSourceContext { row: row.clone() };
        match contexts.get(&candidate.source_realization_handle) {
            Some(existing) if existing.row != context.row => {
                return Err(MountManagerStartupDerivationError::InconsistentLifecycle);
            }
            Some(_) => {}
            None => {
                contexts.insert(candidate.source_realization_handle, context);
            }
        }
    }
    Ok(contexts)
}

fn validate_source_pin_correspondence(
    pins: &BTreeMap<[u8; 32], crate::mount_source_consumption_state::SourcePinRowV1>,
    contexts: &BTreeMap<[u8; 32], AcquisitionSourceContext>,
) -> Result<(), MountManagerStartupDerivationError> {
    for (handle, context) in contexts {
        if context.row.consumption.is_some() && !pins.contains_key(handle) {
            return Err(MountManagerStartupDerivationError::InconsistentLifecycle);
        }
    }
    for pin in pins.values() {
        let context = contexts
            .get(&pin.handle)
            .ok_or(MountManagerStartupDerivationError::InconsistentLifecycle)?;
        let row = &context.row;
        let evidence = row
            .evidence
            .as_ref()
            .ok_or(MountManagerStartupDerivationError::InconsistentLifecycle)?;
        let consumption = row
            .consumption
            .as_ref()
            .ok_or(MountManagerStartupDerivationError::InconsistentLifecycle)?;
        let signer = &evidence.historical_lease_signer.signer;
        let mut admitted = pin.clone();
        admitted.revision = 1;
        admitted.current = true;
        admitted.lifecycle = SourcePinLifecycleV1::Active;
        let admitted_key = source_pin_key_v1(admitted.binding_digest, admitted.handle);
        let admitted_value = encode_source_pin_value_v1(&admitted)
            .map_err(|_| MountManagerStartupDerivationError::InvalidSourcePinState)?;
        let admitted_digest =
            mount_source_consumption_companion_digest_v2(39, &admitted_key, Some(&admitted_value));
        let effective_phase = effective_acquisition_phase(row)
            .ok_or(MountManagerStartupDerivationError::InconsistentLifecycle)?;
        let lifecycle_matches = match pin.lifecycle {
            SourcePinLifecycleV1::Active | SourcePinLifecycleV1::Reaping => {
                effective_phase == SourceAcquisitionPhaseV2::Consumed
            }
            SourcePinLifecycleV1::Released => matches!(
                effective_phase,
                SourceAcquisitionPhaseV2::Consumed
                    | SourceAcquisitionPhaseV2::Releasing
                    | SourceAcquisitionPhaseV2::Released
            ),
        };
        if !lifecycle_matches
            || evidence.source_realization_handle != pin.handle
            || evidence.source_kernel_boot_id != pin.kernel_boot_id
            || evidence.source_device != pin.device
            || evidence.source_inode != pin.inode
            || evidence.source_unique_mount_id != pin.unique_mount_id
            || evidence.source_physical_proof_digest != pin.physical_proof_digest
            || row.source_binding != pin.binding_bytes
            || row.source_binding_digest != pin.binding_digest
            || source_proof_class(evidence.proof_class) != pin.proof_class
            || signer.authority_id != pin.provider_authority_id
            || signer.authority_generation != pin.provider_authority_generation
            || signer.authority_digest != pin.provider_authority_digest
            || evidence.provider_resource_id != pin.provider_resource_id
            || evidence.provider_resource_generation != pin.provider_resource_generation
            || evidence.provider_resource_digest != pin.provider_resource_digest
            || evidence.provider_catalog_generation != pin.provider_catalog_generation
            || evidence.provider_catalog_digest != pin.provider_catalog_digest
            || consumption.operation_id != pin.admission_operation_id
            || consumption.transport_request_digest != pin.admission_request_digest
            || consumption.source_pin_record_digest != admitted_digest
        {
            return Err(MountManagerStartupDerivationError::InconsistentLifecycle);
        }
    }
    Ok(())
}

fn effective_acquisition_phase(
    row: &crate::mount_source_acquisition_state::SourceAcquisitionRowV2,
) -> Option<SourceAcquisitionPhaseV2> {
    if row.phase == SourceAcquisitionPhaseV2::Faulted {
        row.faulted_from
    } else {
        Some(row.phase)
    }
}

fn standard_and_listener_expectations(
    policy: &MountManagerStartupPolicyV1,
) -> Vec<ExpectedStartupDescriptorV1> {
    let mut expected = Vec::new();
    for (bit, role) in [
        (0, StartupDescriptorRoleV1::StandardInput),
        (1, StartupDescriptorRoleV1::StandardOutput),
        (2, StartupDescriptorRoleV1::StandardError),
    ] {
        if policy.standard_descriptor_bitmap & (1 << bit) != 0 {
            expected.push(ExpectedStartupDescriptorV1 {
                role,
                presence: StartupDescriptorPresenceV1::Required,
                name: None,
                logical_identity: [0; 32],
                kernel_boot_id: None,
                device: None,
                inode: None,
                unique_mount_id: None,
                descriptor_commitment: None,
                source_acquisition_id: None,
                source_acquisition_revision: None,
                source_acquisition_record_digest: None,
                socket: None,
            });
        }
    }
    expected.push(ExpectedStartupDescriptorV1 {
        role: StartupDescriptorRoleV1::Listener,
        presence: StartupDescriptorPresenceV1::Required,
        name: Some(policy.listener_name.clone()),
        logical_identity: mount_manager_startup_listener_identity_v1(&policy.listener_name),
        kernel_boot_id: None,
        device: None,
        inode: None,
        unique_mount_id: None,
        descriptor_commitment: None,
        source_acquisition_id: None,
        source_acquisition_revision: None,
        source_acquisition_record_digest: None,
        socket: Some(super::StartupSocketObservationV1 {
            domain: policy.listener_domain,
            socket_type: policy.listener_socket_type,
            accepting: policy.listener_accepting,
            local_address: policy.listener_local_address.clone(),
        }),
    });
    expected
}

fn append_source_expectations(
    expected: &mut Vec<ExpectedStartupDescriptorV1>,
    policy: &MountManagerStartupPolicyV1,
    current_boot: [u8; 16],
    pins: &BTreeMap<[u8; 32], crate::mount_source_consumption_state::SourcePinRowV1>,
    contexts: &BTreeMap<[u8; 32], AcquisitionSourceContext>,
) -> Result<(), MountManagerStartupDerivationError> {
    let mut count = 0u32;

    for context in contexts.values() {
        let row = &context.row;
        let evidence = match &row.evidence {
            Some(evidence) if evidence.source_kernel_boot_id == current_boot => evidence,
            Some(_) | None => continue,
        };
        let presence = match effective_acquisition_phase(row) {
            Some(SourceAcquisitionPhaseV2::PendingQuery) => {
                StartupDescriptorPresenceV1::Conditional
            }
            Some(SourceAcquisitionPhaseV2::DescriptorCustodied)
            | Some(SourceAcquisitionPhaseV2::Active) => StartupDescriptorPresenceV1::Conditional,
            Some(SourceAcquisitionPhaseV2::Releasing) => StartupDescriptorPresenceV1::Conditional,
            Some(SourceAcquisitionPhaseV2::Consumed | SourceAcquisitionPhaseV2::Released)
            | Some(SourceAcquisitionPhaseV2::Faulted)
            | None => continue,
        };
        append_source_expectation(expected, policy, &mut count, row, evidence, presence)?;
    }

    for pin in pins.values() {
        if pin.kernel_boot_id != current_boot || pin.lifecycle == SourcePinLifecycleV1::Released {
            continue;
        }
        let context = contexts
            .get(&pin.handle)
            .ok_or(MountManagerStartupDerivationError::InconsistentLifecycle)?;
        let row = &context.row;
        let acquisition = row
            .evidence
            .as_ref()
            .ok_or(MountManagerStartupDerivationError::InconsistentLifecycle)?;
        let signer = &acquisition.historical_lease_signer.signer;
        if acquisition.source_kernel_boot_id != pin.kernel_boot_id
            || acquisition.source_device != pin.device
            || acquisition.source_inode != pin.inode
            || acquisition.source_unique_mount_id != pin.unique_mount_id
            || acquisition.source_physical_proof_digest != pin.physical_proof_digest
            || acquisition.descriptor_commitment == [0; 32]
            || row.source_binding != pin.binding_bytes
            || row.source_binding_digest != pin.binding_digest
            || source_proof_class(acquisition.proof_class) != pin.proof_class
            || signer.authority_id != pin.provider_authority_id
            || signer.authority_generation != pin.provider_authority_generation
            || signer.authority_digest != pin.provider_authority_digest
            || acquisition.provider_resource_id != pin.provider_resource_id
            || acquisition.provider_resource_generation != pin.provider_resource_generation
            || acquisition.provider_resource_digest != pin.provider_resource_digest
            || acquisition.provider_catalog_generation != pin.provider_catalog_generation
            || acquisition.provider_catalog_digest != pin.provider_catalog_digest
            || row
                .consumption
                .as_ref()
                .map(|value| value.transport_request_digest)
                != Some(pin.admission_request_digest)
        {
            return Err(MountManagerStartupDerivationError::InconsistentLifecycle);
        }
        count = count
            .checked_add(1)
            .ok_or(MountManagerStartupDerivationError::LimitExceeded)?;
        if count > policy.maximum_source_count {
            return Err(MountManagerStartupDerivationError::LimitExceeded);
        }
        expected.push(ExpectedStartupDescriptorV1 {
            role: StartupDescriptorRoleV1::SourceRoot,
            presence: match pin.lifecycle {
                SourcePinLifecycleV1::Active => StartupDescriptorPresenceV1::Conditional,
                SourcePinLifecycleV1::Reaping => StartupDescriptorPresenceV1::Conditional,
                SourcePinLifecycleV1::Released => continue,
            },
            name: Some(mount_manager_source_activation_name_v1(pin.handle)),
            logical_identity: pin.handle,
            kernel_boot_id: Some(pin.kernel_boot_id),
            device: Some(pin.device),
            inode: Some(pin.inode),
            unique_mount_id: Some(pin.unique_mount_id),
            descriptor_commitment: Some(acquisition.descriptor_commitment),
            source_acquisition_id: Some(row.acquisition_id),
            source_acquisition_revision: Some(row.revision),
            source_acquisition_record_digest: Some(row.record_digest),
            socket: None,
        });
    }
    Ok(())
}

fn append_source_expectation(
    expected: &mut Vec<ExpectedStartupDescriptorV1>,
    policy: &MountManagerStartupPolicyV1,
    count: &mut u32,
    row: &crate::mount_source_acquisition_state::SourceAcquisitionRowV2,
    evidence: &crate::mount_source_acquisition_state::SourceAcquisitionEvidenceV2,
    presence: StartupDescriptorPresenceV1,
) -> Result<(), MountManagerStartupDerivationError> {
    *count = count
        .checked_add(1)
        .ok_or(MountManagerStartupDerivationError::LimitExceeded)?;
    if *count > policy.maximum_source_count {
        return Err(MountManagerStartupDerivationError::LimitExceeded);
    }

    expected.push(ExpectedStartupDescriptorV1 {
        role: StartupDescriptorRoleV1::SourceRoot,
        presence,
        name: Some(mount_manager_source_activation_name_v1(
            evidence.source_realization_handle,
        )),
        logical_identity: evidence.source_realization_handle,
        kernel_boot_id: Some(evidence.source_kernel_boot_id),
        device: Some(evidence.source_device),
        inode: Some(evidence.source_inode),
        unique_mount_id: Some(evidence.source_unique_mount_id),
        descriptor_commitment: Some(evidence.descriptor_commitment),
        source_acquisition_id: Some(row.acquisition_id),
        source_acquisition_revision: Some(row.revision),
        source_acquisition_record_digest: Some(row.record_digest),
        socket: None,
    });
    Ok(())
}

/// Derives the sole canonical manager activation name for one SourceRoot.
#[must_use]
pub fn mount_manager_source_activation_name_v1(source_realization_handle: [u8; 32]) -> String {
    digest_name(SOURCE_NAME_PREFIX, source_realization_handle)
}

/// Projects one exact durable acquisition row into a fresh control source.
///
/// The caller supplies no physical fields or activation name independently;
/// all values come from the row's signed, graph-validated Acquire evidence.
///
/// # Errors
///
/// Returns an error when the row has no complete SourceRoot evidence or any
/// required identity is zero.
pub fn derive_manager_control_source_v1(
    row: &crate::mount_source_acquisition_state::SourceAcquisitionRowV2,
) -> Result<super::ManagerControlSourceV1, MountManagerStartupDerivationError> {
    let evidence = row
        .evidence
        .as_ref()
        .ok_or(MountManagerStartupDerivationError::InconsistentLifecycle)?;
    if row.acquisition_id == [0; 32]
        || row.revision == 0
        || row.record_digest == [0; 32]
        || row.phase
            != crate::mount_source_acquisition_state::SourceAcquisitionPhaseV2::PendingQuery
        || row.descriptor_custody_digest.is_some()
        || row.positive_custody_digest.is_some()
        || row.negative_custody_digest.is_some()
        || !matches!(
            row.recovery,
            crate::mount_source_acquisition_state::AcquisitionRecoveryV2::Ready
        )
        || evidence.source_realization_handle == [0; 32]
        || evidence.descriptor_commitment == [0; 32]
        || evidence.source_kernel_boot_id == [0; 16]
        || evidence.source_device == 0
        || evidence.source_inode == 0
        || evidence.source_unique_mount_id == 0
    {
        return Err(MountManagerStartupDerivationError::InconsistentLifecycle);
    }
    Ok(super::ManagerControlSourceV1 {
        acquisition_id: row.acquisition_id,
        acquisition_revision: row.revision,
        acquisition_record_digest: row.record_digest,
        source_realization_handle: evidence.source_realization_handle,
        descriptor_commitment: evidence.descriptor_commitment,
        kernel_boot_id: evidence.source_kernel_boot_id,
        device: evidence.source_device,
        inode: evidence.source_inode,
        unique_mount_id: evidence.source_unique_mount_id,
        activation_name: mount_manager_source_activation_name_v1(
            evidence.source_realization_handle,
        ),
    })
}

const fn source_proof_class(class: SourceAcquisitionProofClassV2) -> MountSourceProofClassV1 {
    match class {
        SourceAcquisitionProofClassV2::ImmutableTree => MountSourceProofClassV1::ImmutableTree,
        SourceAcquisitionProofClassV2::LocalLive => MountSourceProofClassV1::LocalLive,
        SourceAcquisitionProofClassV2::BestEffortReplica => {
            MountSourceProofClassV1::BestEffortReplica
        }
    }
}

fn append_mount_expectations(
    expected: &mut Vec<ExpectedStartupDescriptorV1>,
    policy: &MountManagerStartupPolicyV1,
    current_boot: [u8; 16],
    resources: &BTreeMap<[u8; 32], crate::mount_source_consumption_state::MountResourceV1>,
    source_pins: &BTreeMap<[u8; 32], crate::mount_source_consumption_state::SourcePinRowV1>,
) -> Result<(), MountManagerStartupDerivationError> {
    let mut count = 0u32;
    for resource in resources.values() {
        let is_live = !matches!(&resource.state, MountResourceStateV1::Released { .. });
        let source_pin = source_pins.get(&resource.recipe.source_realization_handle);
        if is_live && source_pin.is_none_or(|pin| pin.lifecycle != SourcePinLifecycleV1::Active) {
            return Err(MountManagerStartupDerivationError::InconsistentLifecycle);
        }
        if let Some(pin) = source_pin {
            if resource.kernel_boot_id != pin.kernel_boot_id
                || resource.recipe.source_binding_digest != pin.binding_digest
                || resource.recipe.source_physical_proof_digest != pin.physical_proof_digest
                || resource.recipe.source_kernel_boot_id != pin.kernel_boot_id
                || resource.recipe.source_device != pin.device
                || resource.recipe.source_inode != pin.inode
                || resource.recipe.source_unique_mount_id != pin.unique_mount_id
                || resource.recipe.source_proof_class != pin.proof_class
                || resource.recipe.source_provider_authority_id != pin.provider_authority_id
                || resource.recipe.source_provider_authority_generation
                    != pin.provider_authority_generation
                || resource.recipe.source_provider_authority_digest != pin.provider_authority_digest
                || resource.recipe.source_provider_resource_id != pin.provider_resource_id
                || resource.recipe.source_provider_resource_generation
                    != pin.provider_resource_generation
                || resource.recipe.source_provider_resource_digest != pin.provider_resource_digest
                || resource.recipe.source_provider_catalog_generation
                    != pin.provider_catalog_generation
                || resource.recipe.source_provider_catalog_digest != pin.provider_catalog_digest
            {
                return Err(MountManagerStartupDerivationError::InconsistentLifecycle);
            }
        }
        if resource.kernel_boot_id != current_boot {
            continue;
        }
        let Some((presence, mount_id)) = mount_descriptor_expectation(&resource.state) else {
            continue;
        };
        count = count
            .checked_add(1)
            .ok_or(MountManagerStartupDerivationError::LimitExceeded)?;
        if count > policy.maximum_mount_count {
            return Err(MountManagerStartupDerivationError::LimitExceeded);
        }
        expected.push(ExpectedStartupDescriptorV1 {
            role: StartupDescriptorRoleV1::RetainedMount,
            presence,
            name: Some(digest_name(MOUNT_NAME_PREFIX, resource.fd_store_key)),
            logical_identity: resource.handle,
            kernel_boot_id: Some(resource.kernel_boot_id),
            device: None,
            inode: None,
            unique_mount_id: Some(mount_id),
            descriptor_commitment: None,
            source_acquisition_id: None,
            source_acquisition_revision: None,
            source_acquisition_record_digest: None,
            socket: None,
        });
    }
    Ok(())
}

fn mount_descriptor_expectation(
    state: &MountResourceStateV1,
) -> Option<(StartupDescriptorPresenceV1, u64)> {
    use StartupDescriptorPresenceV1::{Conditional, Required};

    match state {
        MountResourceStateV1::Prepared { detached, .. }
        | MountResourceStateV1::Publishing { detached, .. }
        | MountResourceStateV1::Installed { detached, .. }
        | MountResourceStateV1::Draining { detached, .. } => {
            Some((Required, detached.unique_mount_id))
        }
        MountResourceStateV1::Detaching { detached, .. }
        | MountResourceStateV1::Releasing { detached, .. } => {
            Some((Conditional, detached.unique_mount_id))
        }
        MountResourceStateV1::Faulted { from, detached, .. } => {
            let detached = detached.as_ref()?;
            let presence = match from {
                MountFaultPhaseV1::Prepared
                | MountFaultPhaseV1::Publishing
                | MountFaultPhaseV1::Installed
                | MountFaultPhaseV1::Draining => Required,
                MountFaultPhaseV1::Detaching | MountFaultPhaseV1::Releasing => Conditional,
                MountFaultPhaseV1::Allocated => return None,
            };
            Some((presence, detached.unique_mount_id))
        }
        MountResourceStateV1::Allocated { .. } | MountResourceStateV1::Released { .. } => None,
    }
}

fn derive_source_subjects(
    graph: &crate::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
    source_pins: &BTreeMap<[u8; 32], crate::mount_source_consumption_state::SourcePinRowV1>,
    mount_resources: &BTreeMap<[u8; 32], crate::mount_source_consumption_state::MountResourceV1>,
) -> Result<Vec<StartupSourceSubjectV1>, MountManagerStartupDerivationError> {
    let mut subjects = derive_cleanup_subjects(graph)?;
    subjects.extend(derive_terminal_subjects(
        graph,
        source_pins,
        mount_resources,
    )?);
    Ok(subjects)
}

fn derive_cleanup_subjects(
    graph: &crate::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
) -> Result<Vec<StartupSourceSubjectV1>, MountManagerStartupDerivationError> {
    let mut subjects = Vec::new();
    for row in graph.acquisitions.values() {
        let phase = match effective_acquisition_phase(row) {
            Some(SourceAcquisitionPhaseV2::PendingQuery) => StartupCleanupPhaseV1::PendingQuery,
            Some(SourceAcquisitionPhaseV2::DescriptorCustodied) => {
                StartupCleanupPhaseV1::DescriptorCustodied
            }
            Some(SourceAcquisitionPhaseV2::Active) => StartupCleanupPhaseV1::Active,
            Some(SourceAcquisitionPhaseV2::Consumed) => StartupCleanupPhaseV1::Consumed,
            Some(SourceAcquisitionPhaseV2::Releasing | SourceAcquisitionPhaseV2::Released)
            | Some(SourceAcquisitionPhaseV2::Faulted)
            | None => continue,
        };
        let attempt_ref = match row.acquire_terminal_attempt {
            Some(attempt) => attempt,
            None if phase == StartupCleanupPhaseV1::PendingQuery => continue,
            None => return Err(MountManagerStartupDerivationError::InconsistentLifecycle),
        };
        let attempt = graph
            .provider_attempts
            .get(&attempt_ref.id)
            .filter(|attempt| {
                attempt.revision == attempt_ref.revision
                    && attempt.record_digest == attempt_ref.record_digest
                    && attempt.method == ProviderMethodV2::Acquire
                    && matches!(
                        &attempt.state,
                        ProviderAttemptStateV2::DispositionConsumed {
                            status: ProviderStatusV2::Complete,
                            ..
                        }
                    )
            })
            .ok_or(MountManagerStartupDerivationError::InconsistentLifecycle)?;
        let session = graph
            .provider_sessions
            .get(&attempt.session_id)
            .filter(|session| {
                session.record_digest == attempt.session_record_digest && session.scope == row.scope
            })
            .ok_or(MountManagerStartupDerivationError::InconsistentLifecycle)?;
        let evidence = row
            .evidence
            .as_ref()
            .map(|evidence| StartupCleanupEvidenceV1 {
                source_realization_handle: evidence.source_realization_handle,
                descriptor_commitment: evidence.descriptor_commitment,
                source_kernel_boot_id: evidence.source_kernel_boot_id,
                source_device: evidence.source_device,
                source_inode: evidence.source_inode,
                source_unique_mount_id: evidence.source_unique_mount_id,
            });
        let last_custody_owner = evidence.map(|_| {
            let writer = session.actual_writer_root_mount_process;
            StartupPersistedCustodyOwnerV1 {
                attempt_id: attempt_ref.id,
                attempt_revision: attempt_ref.revision,
                attempt_record_digest: attempt_ref.record_digest,
                session_id: session.session_id,
                session_record_digest: session.record_digest,
                kernel_boot_id: session.kernel_boot_id,
                tgid: writer.tgid,
                start_time_ticks: writer.start_time_ticks,
                cgroup_digest: writer.cgroup_digest,
            }
        });
        subjects.push(StartupSourceSubjectV1::Cleanup(
            StartupCleanupSourceSubjectV1 {
                acquisition_id: row.acquisition_id,
                acquisition_revision: row.revision,
                acquisition_record_digest: row.record_digest,
                phase,
                acquire_attempt_id: attempt_ref.id,
                acquire_attempt_revision: attempt_ref.revision,
                acquire_attempt_record_digest: attempt_ref.record_digest,
                evidence,
                last_custody_owner,
            },
        ));
    }
    Ok(subjects)
}

fn derive_terminal_subjects(
    graph: &crate::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
    source_pins: &BTreeMap<[u8; 32], crate::mount_source_consumption_state::SourcePinRowV1>,
    mount_resources: &BTreeMap<[u8; 32], crate::mount_source_consumption_state::MountResourceV1>,
) -> Result<Vec<StartupSourceSubjectV1>, MountManagerStartupDerivationError> {
    let mut subjects = Vec::new();
    for row in graph.acquisitions.values() {
        let releasing = row.phase == SourceAcquisitionPhaseV2::Releasing
            || (row.phase == SourceAcquisitionPhaseV2::Faulted
                && row.faulted_from == Some(SourceAcquisitionPhaseV2::Releasing));
        if !releasing
            || !matches!(row.recovery, AcquisitionRecoveryV2::Ready)
            || row.negative_custody_digest.is_some()
        {
            continue;
        }
        let evidence = row
            .evidence
            .as_ref()
            .ok_or(MountManagerStartupDerivationError::InconsistentLifecycle)?;
        let pin_matches_terminality = match (
            &row.consumption,
            source_pins.get(&evidence.source_realization_handle),
        ) {
            (Some(_), Some(pin)) => pin.lifecycle == SourcePinLifecycleV1::Released,
            (None, None) => true,
            _ => false,
        };
        let no_live_mount_references = mount_resources.values().all(|resource| {
            resource.recipe.source_realization_handle != evidence.source_realization_handle
                || matches!(resource.state, MountResourceStateV1::Released { .. })
        });
        if !pin_matches_terminality || !no_live_mount_references {
            return Err(MountManagerStartupDerivationError::InconsistentLifecycle);
        }
        let attempt_ref = match row
            .release_proof
            .as_ref()
            .ok_or(MountManagerStartupDerivationError::InconsistentLifecycle)?
        {
            ReleaseProofV2::ProviderReceipt { attempt, .. }
            | ReleaseProofV2::ProviderInventory { attempt, .. } => *attempt,
        };
        let attempt = graph
            .provider_attempts
            .get(&attempt_ref.id)
            .filter(|attempt| {
                attempt.revision == attempt_ref.revision
                    && attempt.record_digest == attempt_ref.record_digest
                    && matches!(
                        &attempt.state,
                        ProviderAttemptStateV2::DispositionConsumed {
                            status: ProviderStatusV2::Complete,
                            ..
                        }
                    )
            })
            .ok_or(MountManagerStartupDerivationError::InconsistentLifecycle)?;
        if graph
            .provider_heads
            .get(&(
                row.scope.holder_authority_id,
                row.scope.provider_authority_id,
            ))
            .is_none_or(|head| head.pending_attempt.is_some())
            || graph.provider_attempts.values().any(|candidate| {
                matches!(&candidate.state, ProviderAttemptStateV2::Reserved)
                    && candidate.owner == attempt.owner
            })
        {
            return Err(MountManagerStartupDerivationError::InconsistentLifecycle);
        }
        subjects.push(StartupSourceSubjectV1::Terminal(
            StartupTerminalSourceSubjectV1 {
                acquisition_id: row.acquisition_id,
                acquisition_revision: row.revision,
                acquisition_record_digest: row.record_digest,
                provider_acquisition_id: row.provider_acquisition.acquisition_id,
                provider_acquisition_sequence: row.provider_acquisition.acquisition_sequence,
                source_realization_handle: evidence.source_realization_handle,
                descriptor_commitment: evidence.descriptor_commitment,
                source_kernel_boot_id: evidence.source_kernel_boot_id,
                source_device: evidence.source_device,
                source_inode: evidence.source_inode,
                source_unique_mount_id: evidence.source_unique_mount_id,
                lease_id: evidence.lease_id,
                lease_digest: evidence.signed_lease_digest,
                terminal_attempt_id: attempt_ref.id,
                terminal_attempt_revision: attempt_ref.revision,
                terminal_attempt_digest: attempt_ref.record_digest,
            },
        ));
    }
    Ok(subjects)
}

fn validate_expected_table(
    policy: &MountManagerStartupPolicyV1,
    expected: &[ExpectedStartupDescriptorV1],
) -> Result<(), MountManagerStartupDerivationError> {
    if expected.len() > MAXIMUM_STARTUP_DESCRIPTORS_V1
        || u32::try_from(expected.len())
            .map_or(true, |count| count > policy.maximum_descriptor_count)
        || expected.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(MountManagerStartupDerivationError::LimitExceeded);
    }
    let mut names = BTreeSet::new();
    let mut name_bytes = 0usize;
    for entry in expected {
        if let Some(name) = &entry.name {
            if !names.insert(name.as_str()) {
                return Err(MountManagerStartupDerivationError::InconsistentLifecycle);
            }
            name_bytes = name_bytes
                .checked_add(name.len())
                .ok_or(MountManagerStartupDerivationError::LimitExceeded)?;
            if name.len() > policy.maximum_name_bytes as usize
                || name_bytes > policy.maximum_names_bytes as usize
            {
                return Err(MountManagerStartupDerivationError::LimitExceeded);
            }
        }
    }
    Ok(())
}

fn record_count(records: &[(Vec<u8>, Vec<u8>)]) -> Result<u32, MountManagerStartupDerivationError> {
    u32::try_from(records.len()).map_err(|_| MountManagerStartupDerivationError::LimitExceeded)
}

fn exact_record_set_digest(domain: &[u8], records: &[(Vec<u8>, Vec<u8>)]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((records.len() as u64).to_be_bytes());
    for (key, value) in records {
        hasher.update((key.len() as u64).to_be_bytes());
        hasher.update(key);
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    hasher.finalize().into()
}

fn digest_name(prefix: &str, digest: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut name = String::with_capacity(prefix.len() + 64);
    name.push_str(prefix);
    for byte in digest {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name
}
