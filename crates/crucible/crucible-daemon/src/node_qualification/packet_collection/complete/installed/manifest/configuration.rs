//! Constructs local operational coordinator state from a closed logical recipe.
//!
//! Unlike installation/7 and installation/8, this input contains no coordinator
//! snapshot or Host prepared token. The actor creates the original Host before
//! deriving coordinator bytes, initial references or any launch commitment.
//!
//! ```text
//! {schema:"crucible.complete-scene.configuration/1",
//!  mechanism:"SourceSignedImport18", restoration:{...complete7 selection...},
//!  measurements:[...;3], participants:[...;3], host:selection, world:binding,
//!  requirements:scenario, initial:{activation_id, generation,
//!  native_prepared_tokens:[expected_id;3]}, content:[...], resources:limits,
//!  maximum_initial_bytes, maximum_native_rows, maximum_operations,
//!  maximum_retained_outputs, maximum_coordinator_records, write_watchdog_ms}
//! ```

#[path = "configuration/coordinator.rs"]
mod coordinator;

use super::*;
use crucible_engine::node_contract::HostSchedulingOwner;
use crucible_node_transport::reference_packet::service::complete_restore::import18::PacketNativeImport18Selection;

const SCHEMA: &str = "crucible.complete-scene.configuration/1";

pub(in crate::node_qualification::packet_collection::complete::installed) enum FundedSelection {
    Installation(Manifest, PacketNativeImport18Selection),
    Configuration(Configuration),
}

/// Selects a closed recipe only on the already selected operational route.
/// Legacy callers continue to use their original installation-only decoders.
pub(in crate::node_qualification::packet_collection::complete::installed) fn load_funded(
    pin: &InstalledCompleteSceneManifest,
) -> Result<FundedSelection, QualificationError> {
    let value = read_pinned_value(pin)?;
    match value.get("schema").and_then(serde_json::Value::as_str) {
        Some("crucible.complete-scene.installation/8") => {
            let (selected, mechanism) = import18::decode_import18(value)?;
            Ok(FundedSelection::Installation(selected, mechanism))
        }
        Some(SCHEMA) => Ok(FundedSelection::Configuration(decode(value)?)),
        _ => Err(refused()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::node_qualification::packet_collection::complete::installed) struct Configuration {
    schema: String,
    mechanism: PacketNativeImport18Selection,
    restoration: CompleteMechanism,
    measurements: [Measurement; 3],
    participants: [Participant; 3],
    host: HostSchedulingSelection,
    world: WorldBinding,
    requirements: ScenarioRequirements,
    initial: Initial,
    content: Vec<Content>,
    resources: ResourceLimits,
    maximum_initial_bytes: usize,
    maximum_native_rows: usize,
    maximum_operations: usize,
    maximum_retained_outputs: usize,
    maximum_coordinator_records: usize,
    write_watchdog_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Initial {
    activation_id: Id,
    generation: U64,
    // These are expected correlation DATA. No native preparation or permission
    // is inferred; the original Source/receiver path still checks them.
    native_prepared_tokens: [Id; 3],
}

fn decode(value: serde_json::Value) -> Result<Configuration, QualificationError> {
    let selected: Configuration = serde_json::from_value(value).map_err(ContractError::from)?;
    selected.validate_recipe()?;
    Ok(selected)
}

impl Configuration {
    fn validate_recipe(&self) -> Result<(), QualificationError> {
        if self.schema != SCHEMA
            || self.mechanism != PacketNativeImport18Selection::SourceSignedImport18
            || self.initial.generation.get() == 0
            || !(1..=64).contains(&self.maximum_operations)
            || self.maximum_retained_outputs != 3
            || self.maximum_coordinator_records < 2
            || u64::try_from(self.maximum_coordinator_records).is_err()
            || self.content.len() > 128
        {
            return Err(refused());
        }
        self.initial.activation_id.validate()?;
        for token in &self.initial.native_prepared_tokens {
            token.validate()?;
        }
        // Verify each original content row before it can influence a derived
        // coordinator. No replacement body or repaired reference is accepted.
        let mut total = 0usize;
        for (index, row) in self.content.iter().enumerate() {
            row.reference.verify(row.bytes.as_slice())?;
            total = total
                .checked_add(row.bytes.as_slice().len())
                .ok_or_else(refused)?;
            if row.bytes.as_slice().len() > 1024 * 1024
                || total > 2 * 1024 * 1024
                || self.content[..index]
                    .iter()
                    .any(|prior| prior.reference == row.reference)
            {
                return Err(refused());
            }
        }
        Ok(())
    }

    /// Produces a new local coordinator and its original owning Host together.
    /// No snapshot is rewritten, and no second Host is constructed by the caller.
    pub(in crate::node_qualification::packet_collection::complete::installed) fn materialize(
        self,
    ) -> Result<(Manifest, HostSchedulingOwner, PacketNativeImport18Selection), QualificationError>
    {
        self.validate_recipe()?;
        let host = HostSchedulingOwner::new_complete_original_continuation(
            self.host.clone(),
            self.world.identity()?,
        )
        .map_err(|_| refused())?;
        let coordinator = coordinator::build(&self, &host)?;
        let Self {
            schema: _,
            mechanism,
            restoration,
            measurements,
            participants,
            host: selection,
            world,
            requirements,
            initial: _,
            content,
            resources,
            maximum_initial_bytes,
            maximum_native_rows,
            maximum_operations,
            maximum_retained_outputs,
            maximum_coordinator_records,
            write_watchdog_ms,
        } = self;
        // This newly constructed private value selects the existing compiled
        // complete7 family. It is not decoded/relabelled installation bytes.
        let selected = Manifest {
            schema: "crucible.complete-scene.installation/7".into(),
            mechanism: Some(restoration),
            measurements,
            participants,
            host: selection,
            world,
            requirements,
            coordinator,
            content,
            resources,
            maximum_initial_bytes,
            maximum_native_rows,
            maximum_operations,
            maximum_retained_outputs,
            maximum_coordinator_records: Some(maximum_coordinator_records),
            write_watchdog_ms,
        };
        validate_declaration(&selected)?;
        Ok((selected, host, mechanism))
    }

    fn object(&self, reference: &ContentRef) -> Result<serde_json::Value, QualificationError> {
        let row = self
            .content
            .iter()
            .find(|row| &row.reference == reference)
            .ok_or_else(refused)?;
        reference.verify(row.bytes.as_slice())?;
        Ok(canonical::parse_json(row.bytes.as_slice(), 1024 * 1024)?)
    }
}

#[cfg(test)]
#[path = "configuration/tests.rs"]
mod tests;
