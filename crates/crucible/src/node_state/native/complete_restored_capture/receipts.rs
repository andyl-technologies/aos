//! Checks actual current17 owner receipts without conflating schema and facet.

use super::*;
use crate::node_state::{closure::bounded_record, schema};
use crucible_node_contract::{BindingCompatibility, ContentRef, HashRef, Id, canonical};
use serde::Serialize;

const INVENTORY_DOMAIN: &str = "crucible.native-owner-inventory.v1";

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
    cut: crucible_node_contract::Position,
    ordinal: crucible_node_contract::U64,
    domains: &'a [Id],
}

impl NativeArchiveRecord {
    pub(super) fn validate_restored_settled_owner_receipts(
        &self,
        graph: &crate::node_admission::AdmittedGraph,
        attempt: &CompleteRestoredSettledArchiveValidationAttempt,
        additional_retained_bytes: usize,
    ) -> Result<(), StateError> {
        let content = attempt
            .content
            .as_ref()
            .ok_or_else(|| refused("settled17 content absent"))?;
        for (native, captured) in self.owners().iter().zip(&self.manifest.owners) {
            if native.owner != captured.capture_owner_id
                || native.participants != captured.participant_ids
                || native.cut != self.manifest.cut
                || Some(&native.state) != captured.state_ref.as_ref()
                || native.key.schema != captured.state_schema
                || captured.retained_source_ref.is_some()
                || native
                    .evidence
                    .iter()
                    .any(|reference| content.get(reference).is_none())
            {
                return Err(refused("settled17 native and manifest owner scopes differ"));
            }
            for participant in &native.participants {
                let binding = graph
                    .binding(participant)
                    .ok_or_else(|| refused("settled17 owner binding absent"))?;
                if !selected_current_profile(&native.key, &binding.compatibility) {
                    return Err(refused(
                        "settled17 owner crossed installed implementation or profile",
                    ));
                }
            }

            let projection = ReceiptProjection {
                schema_version: 1,
                owner: &native.owner,
                inventory: HashProjection {
                    algorithm: "blake3-256",
                    domain: INVENTORY_DOMAIN,
                    digest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                },
                coordinator: &self.manifest.coordinator_state_ref,
                cut: self.manifest.cut,
                ordinal: self.manifest.event_ordinal,
                domains: &captured.state_domain_ids,
            };
            let maximum = self
                .limits
                .state
                .maximum_total_content_bytes
                .min(self.limits.native.maximum_total_record_bytes);
            let work = [
                NodeRuntime::capture_serialization_storage(native, maximum).map_err(schema)?,
                NodeRuntime::capture_encoded_output_storage(native, maximum).map_err(schema)?,
                NodeRuntime::capture_serialization_storage(&projection, maximum).map_err(schema)?,
                NodeRuntime::capture_encoded_output_storage(&projection, maximum).map_err(schema)?,
                std::mem::size_of::<HashRef>() + "blake3-256".len() + INVENTORY_DOMAIN.len() + 64,
                super::validation::fixed_scratch(),
                crucible_node_provider::reference_packet::service::native_snapshot::native_restored_settled17_snapshot_schema_counter_scratch_data(),
            ].into_iter().try_fold(0usize, |sum, bytes| sum.checked_add(bytes)
                .ok_or_else(|| refused("settled17 receipt work overflow")))?;
            super::validation::admit(self, attempt, additional_retained_bytes, work)?;
            let receipt = lineage_capture::OwnerReceipt {
                schema_version: 1,
                owner: &native.owner,
                inventory: canonical::json_hash(INVENTORY_DOMAIN, native).map_err(schema)?,
                coordinator: &self.manifest.coordinator_state_ref,
                cut: self.manifest.cut,
                ordinal: self.manifest.event_ordinal,
                domains: &captured.state_domain_ids,
            };
            bounded_record(&receipt, self.limits.state.maximum_record_bytes)?;
            let expected =
                canonical::canonical_json(&serde_json::to_value(receipt).map_err(schema)?)
                    .map_err(schema)?;
            let bytes = content
                .get(&captured.capture_receipt)
                .ok_or_else(|| refused("settled17 owner receipt absent"))?;
            let row = self
                .index
                .objects
                .iter()
                .find(|row| row.reference == captured.capture_receipt)
                .ok_or_else(|| refused("settled17 owner receipt row absent"))?;
            if bytes != expected
                || !same_dependencies(
                    &row.dependencies,
                    native,
                    &self.manifest.coordinator_state_ref,
                )
            {
                return Err(refused("settled17 receipt or complete adjacency differs"));
            }
        }
        Ok(())
    }
}

fn selected_current_profile(
    key: &crate::node_contract::NativeStateKey,
    binding: &BindingCompatibility,
) -> bool {
    let expected_facet_version = match (key.implementation.as_str(), key.profile.as_str()) {
        ("source-owned.packet-native/5", "source-owned.packet-complete-original-lineage/5") => {
            if crucible_node_provider::reference_packet::service::native_snapshot::authenticate_native_restored_settled17_snapshot_schema_data(&key.schema).is_err() {
                return false;
            }
            5
        }
        (
            "source-owned.host-scheduling-owner/2",
            "source-owned.host-scheduling-original-lineage/2",
        ) => {
            if crate::node_contract::authenticate_host_scheduling_restored_continuation_schema17_data(&key.schema).is_err() {
                return false;
            }
            2
        }
        _ => return false,
    };
    key.implementation == binding.implementation.implementation_id
        && binding.implementation.formats.contains(&key.schema)
        && binding
            .operating_contract
            .facets
            .iter()
            .any(|facet| facet.id == key.profile && facet.version == expected_facet_version)
}

fn same_dependencies(
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
        .and_then(|count| count.checked_add(extra_coordinator))
        == Some(dependencies.len())
        && native
            .evidence
            .iter()
            .all(|reference| dependencies.binary_search(reference).is_ok())
        && dependencies.binary_search(&native.state).is_ok()
        && dependencies.binary_search(coordinator).is_ok()
}
