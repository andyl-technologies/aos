//! Joins current17 header roles to their actual signed parent inventory.
//!
//! These checks preserve immutable ancestry and each exact owner receipt. The
//! parent's native MACs and Source/Node causal history remain separate readers.

use super::*;
use crate::node_state::native::{complete_original_index, lineage_capture};
use crucible_node_format::{HashRef, Position, U64};
use serde::Serialize;

const INVENTORY_DOMAIN: &str = "crucible.native-owner-inventory.v1";
const HASH_BACKING: usize = "blake3-256".len() + 64;

#[derive(Serialize)]
struct HashProjection {
    algorithm: &'static str,
    domain: &'static str,
    digest: &'static str,
}

#[derive(Serialize)]
struct ReceiptProjection<'a> {
    schema_version: u16,
    owner: &'a Id,
    inventory: HashProjection,
    coordinator: &'a ContentRef,
    cut: Position,
    ordinal: U64,
    domains: &'a [Id],
}

impl ParentCurrent17HeaderAttempt {
    pub(super) fn join_data(
        &self,
        parent: &ParentArchive17ReadScope<'_, '_>,
        terminal: &ParentHeaderTerminal17<'_, '_>,
        additional: usize,
    ) -> Result<(), StateError> {
        // All decoded Bytes originated in these exact closed input bodies. Their
        // quote-time formatter strings fit within the actual encoded body
        // extent; this is not a decoder-heap or lifetime-allowance estimate.
        let mut encoded_body = 0usize;
        for record in &self.records {
            if let Some(bytes) = &record.canonical {
                encoded_body = encoded_body.max(bytes.len());
            }
        }
        let formatter = encoded_body
            .checked_add(20)
            .ok_or_else(|| refused("parent header quote formatter overflow"))?
            .max(20 + HASH_BACKING + INVENTORY_DOMAIN.len());
        terminal.begin_data(Work::Join, formatter)?;
        let transient = self.join_storage_data(parent)?;
        self.admit_data(parent, additional, 0, transient)?;
        terminal.construct_data(0, transient, counter_scratch_data())?;

        let host = self
            .host
            .as_ref()
            .ok_or_else(|| refused("parent Host absent"))?;
        let checkpoint = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| refused("parent coordinator absent"))?;
        let administrative = self
            .administrative
            .as_ref()
            .ok_or_else(|| refused("parent administrative history absent"))?;
        let manifest = parent.manifest_data()?;
        let current = administrative
            .attempts
            .last()
            .ok_or_else(|| refused("parent administrative cut absent"))?;
        let host_owner = parent.current17_host_owner_data()?;
        host.validate_matching_checkpoint_data(
            &checkpoint.safe_point.runtime,
            &checkpoint.safe_point.scheduling,
            checkpoint,
        )
        .map_err(schema)?;
        if checkpoint.safe_point.runtime.media_type
            != crate::node_state::ORIGINAL_LINEAGE_RUNTIME_MEDIA
            || checkpoint.safe_point.scheduling.media_type != "application/json"
            || host.runtime.source_activation != current.source_activation
            || host.runtime.capture_cut != manifest.cut
            || host.runtime.capture_ordinal != manifest.event_ordinal
            || host.runtime.capture_cut != current.cut
            || host.runtime.capture_ordinal != current.ordinal
            || host.runtime.source_activation.world_binding_hash != manifest.world_binding_hash
            || host_owner.owner != host.source.owner.owner.id
            || host_owner.participants.as_slice()
                != std::slice::from_ref(&host.source.descriptor.id)
            || host
                .source
                .binding
                .compatibility
                .implementation
                .implementation_id
                != host_owner.key.implementation
            || !host
                .source
                .binding
                .compatibility
                .implementation
                .formats
                .contains(&host_owner.key.schema)
            || !host
                .source
                .binding
                .compatibility
                .operating_contract
                .facets
                .iter()
                .any(|facet| facet.id == host_owner.key.profile && facet.version == 2)
            || host
                .runtime
                .operations
                .iter()
                .any(|operation| !matches!(operation.result, SavedRuntimeResult::Acknowledged(_)))
        {
            return Err(refused(
                "current17 parent Host/administrative/owner cut differs",
            ));
        }
        authenticate_serialized_data(parent, &host.runtime, &checkpoint.safe_point.runtime)?;
        authenticate_serialized_data(parent, &host.scheduling, &checkpoint.safe_point.scheduling)?;
        complete_original_index::authenticate_current17_parent_parts_data(
            manifest,
            parent.current17_owners_data()?,
            administrative,
            checkpoint,
            parent.dependency_data(parent.original_capture_journal_reference_data()?)?,
            allocation::record_maximum_data(parent)?,
        )?;
        for reference in
            parent.dependency_data(parent.original_capture_journal_reference_data()?)?
        {
            parent.body_data(reference)?;
        }
        for object in &host.objects {
            if parent.body_data(&object.reference)? != object.bytes.as_slice() {
                return Err(refused(
                    "parent Host original body differs from its inventory",
                ));
            }
        }
        parent.body_data(&host.ancestry.parent_archive_index)?;
        parent.body_data(&host.ancestry.first_host)?;
        for row in &host.ancestry.first_semantic {
            parent.body_data(&row.object)?;
        }
        self.authenticate_owner_receipts_data(parent)?;
        self.authenticate_parent_data(parent)?;
        terminal.finish_data(self, parent)
    }

    fn join_storage_data(
        &self,
        parent: &ParentArchive17ReadScope<'_, '_>,
    ) -> Result<usize, StateError> {
        let host = self
            .host
            .as_ref()
            .ok_or_else(|| refused("parent Host absent"))?;
        let checkpoint = self
            .checkpoint
            .as_ref()
            .ok_or_else(|| refused("parent coordinator absent"))?;
        let administrative = self
            .administrative
            .as_ref()
            .ok_or_else(|| refused("parent administrative history absent"))?;
        let mut peak = serialization_data(&host.runtime, self.maximum)?
            .max(serialization_data(&host.scheduling, self.maximum)?)
            .max(serialization_data(checkpoint, self.maximum)?);
        let identities = administrative
            .attempts
            .len()
            .checked_add(5)
            .and_then(|count| count.checked_mul(NodeRuntime::capture_map_node_storage::<&Id, ()>()))
            .ok_or_else(|| refused("parent administrative identity extent overflow"))?;
        peak = peak.max(
            identities
                .checked_add(20)
                .ok_or_else(|| refused("parent identity formatter overflow"))?,
        );
        let manifest = parent.manifest_data()?;
        let owners = parent.current17_owners_data()?;
        if owners.len() != 4 || manifest.owners.len() != 4 {
            return Err(refused("current17 parent owner roster is not closed four"));
        }
        for (native, captured) in owners.iter().zip(&manifest.owners) {
            let projection = ReceiptProjection {
                schema_version: 1,
                owner: &native.owner,
                inventory: HashProjection {
                    algorithm: "blake3-256",
                    domain: INVENTORY_DOMAIN,
                    digest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                },
                coordinator: &manifest.coordinator_state_ref,
                cut: manifest.cut,
                ordinal: manifest.event_ordinal,
                domains: &captured.state_domain_ids,
            };
            let receipt = allocation::sum_data(
                [
                    serialization_data(native, self.maximum)?,
                    serialization_data(&projection, self.maximum)?,
                    HASH_BACKING + INVENTORY_DOMAIN.len(),
                ],
                self.maximum,
            )?;
            peak = peak.max(receipt);
        }
        peak.checked_add(HASH_BACKING + "cnp.blob.v1".len())
            .filter(|total| *total <= self.maximum)
            .ok_or_else(|| refused("parent header validation construction exceeds its bound"))
    }

    fn authenticate_owner_receipts_data(
        &self,
        parent: &ParentArchive17ReadScope<'_, '_>,
    ) -> Result<(), StateError> {
        let manifest = parent.manifest_data()?;
        let owners = parent.current17_owners_data()?;
        let host = self
            .host
            .as_ref()
            .ok_or_else(|| refused("parent Host absent"))?;
        if owners.len() != 4 || manifest.owners.len() != 4 {
            return Err(refused("current17 parent owner roster differs"));
        }
        let mut native_count = 0usize;
        let mut host_count = 0usize;
        for (native, captured) in owners.iter().zip(&manifest.owners) {
            if native.owner != captured.capture_owner_id
                || native.participants != captured.participant_ids
                || native.cut != manifest.cut
                || Some(&native.state) != captured.state_ref.as_ref()
                || native.key.schema != captured.state_schema
                || captured.retained_source_ref.is_some()
                || native.participants.len() != 1
                || !native.artifacts.is_empty()
            {
                return Err(refused("parent native and manifest owner roles differ"));
            }
            match (
                native.key.implementation.as_str(),
                native.key.profile.as_str(),
            ) {
                (
                    "source-owned.packet-native/5",
                    "source-owned.packet-complete-original-lineage/5",
                ) => {
                    crucible_node_transport::reference_packet::service::native_snapshot::authenticate_native_restored_settled17_snapshot_schema_data(&native.key.schema).map_err(schema)?;
                    native_count += 1;
                    if !host
                        .ancestry
                        .first_semantic
                        .iter()
                        .any(|row| &row.node == &native.participants[0])
                    {
                        return Err(refused(
                            "parent native participant differs from Host ancestry",
                        ));
                    }
                }
                (
                    "source-owned.host-scheduling-owner/2",
                    "source-owned.host-scheduling-original-lineage/2",
                ) => {
                    crate::node_contract::authenticate_host_scheduling_restored_continuation_schema17_data(&native.key.schema).map_err(schema)?;
                    host_count += 1;
                }
                _ => return Err(refused("parent native codec family differs")),
            }
            parent.body_data(&native.state)?;
            for reference in &native.evidence {
                parent.body_data(reference)?;
            }
            let receipt = lineage_capture::OwnerReceipt {
                schema_version: 1,
                owner: &native.owner,
                inventory: canonical::json_hash(INVENTORY_DOMAIN, native).map_err(schema)?,
                coordinator: &manifest.coordinator_state_ref,
                cut: manifest.cut,
                ordinal: manifest.event_ordinal,
                domains: &captured.state_domain_ids,
            };
            crate::node_state::closure::bounded_record(
                &receipt,
                allocation::record_maximum_data(parent)?,
            )?;
            let expected =
                canonical::canonical_json(&serde_json::to_value(receipt).map_err(schema)?)
                    .map_err(schema)?;
            if parent.body_data(&captured.capture_receipt)? != expected.as_slice()
                || !same_dependencies_data(
                    parent.dependency_data(&captured.capture_receipt)?,
                    native,
                    &manifest.coordinator_state_ref,
                )
            {
                return Err(refused(
                    "parent owner receipt or complete dependency roles differ",
                ));
            }
        }
        if native_count != 3 || host_count != 1 {
            return Err(refused("parent native/Host cohort differs"));
        }
        Ok(())
    }
}

fn serialization_data(value: &impl Serialize, maximum: usize) -> Result<usize, StateError> {
    allocation::sum_data(
        [
            NodeRuntime::capture_serialization_storage(value, maximum).map_err(schema)?,
            NodeRuntime::capture_encoded_output_storage(value, maximum).map_err(schema)?,
        ],
        maximum,
    )
}

fn authenticate_serialized_data(
    parent: &ParentArchive17ReadScope<'_, '_>,
    value: &impl Serialize,
    reference: &ContentRef,
) -> Result<(), StateError> {
    let expected =
        canonical::canonical_json(&serde_json::to_value(value).map_err(schema)?).map_err(schema)?;
    if parent.body_data(reference)? != expected.as_slice() {
        return Err(refused(
            "current17 parent coordinator body differs from Host state",
        ));
    }
    reference.verify(&expected).map_err(schema)
}

fn same_dependencies_data(
    dependencies: &[ContentRef],
    native: &NativeOwnerState,
    coordinator: &ContentRef,
) -> bool {
    if dependencies.windows(2).any(|pair| pair[0] >= pair[1])
        || native.evidence.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return false;
    }
    let extra_state = usize::from(native.evidence.binary_search(&native.state).is_err());
    let extra_coordinator = usize::from(
        coordinator != &native.state && native.evidence.binary_search(coordinator).is_err(),
    );
    native
        .evidence
        .len()
        .checked_add(extra_state)
        .and_then(|n| n.checked_add(extra_coordinator))
        == Some(dependencies.len())
        && dependencies.binary_search(&native.state).is_ok()
        && dependencies.binary_search(coordinator).is_ok()
        && native
            .evidence
            .iter()
            .all(|reference| dependencies.binary_search(reference).is_ok())
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<ReceiptProjection<'static>>()
        + size_of::<HashProjection>()
        + size_of::<lineage_capture::OwnerReceipt<'static>>()
        + size_of::<HashRef>()
        + size_of::<Result<HashRef, crucible_node_format::ContractError>>()
        + size_of::<[usize; 3]>()
        + size_of::<std::array::IntoIter<usize, 3>>()
        + size_of::<std::slice::Iter<'static, crate::node_contract::OriginalCaptureAttemptRecord>>()
        + size_of::<std::collections::BTreeSet<&'static Id>>()
        + size_of::<std::slice::Iter<'static, NativeOwnerState>>()
        + size_of::<std::slice::Iter<'static, ContentRef>>()
        + size_of::<Result<(), StateError>>()
}
