//! Counts every retained operator declaration field before Host17 construction.
//!
//! This borrowed census follows actual typed capacities. Inline numeric policy
//! occupies the enclosing Manifest/Participant roots; selected limits are never
//! substituted for allocated backing or granted as construction permission.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;
use crucible::node_contract::{HostSchedulingOwner, RuntimeError};
use crucible_node_provider::retained_metadata::{
    RetainedArchivedSourceInstallation17, RetainedProtocolMetadataFacts,
    observe_retained_native_coordinator,
};
use std::mem::size_of;

impl Manifest {
    pub(in crate::node_qualification::packet_collection::complete::installed) fn charge_host_setup17_data(
        &self,
        counter: &mut Counter,
    ) -> Result<(), RuntimeError> {
        let Self {
            schema,
            mechanism,
            measurements,
            participants,
            host,
            world,
            requirements,
            coordinator,
            content,
            resources,
            maximum_initial_bytes: _,
            maximum_native_rows: _,
            maximum_operations: _,
            maximum_retained_outputs: _,
            maximum_coordinator_records: _,
            write_watchdog_ms: _,
        } = self;
        counter.charge(schema).map_err(limit)?;
        if let Some(mechanism) = mechanism {
            mechanism.check_inline_setup17_data();
        }
        for measurement in measurements {
            measurement.charge_host_setup17_data(counter)?;
        }
        for participant in participants {
            participant.charge_host_setup17_data(counter)?;
        }
        counter
            .add(HostSchedulingOwner::restored_source17_selection_storage_data(host)?)
            .map_err(limit)?;
        counter.charge(world).map_err(limit)?;
        counter.charge(requirements).map_err(limit)?;
        let facts = observe_retained_native_coordinator(coordinator)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter.metadata(&facts).map_err(limit)?;
        counter
            .add(
                content
                    .capacity()
                    .checked_mul(size_of::<Content>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(limit)?;
        for row in content {
            let Content { reference, bytes } = row;
            counter.charge(reference).map_err(limit)?;
            counter.charge(bytes).map_err(limit)?;
        }
        counter.charge(resources).map_err(limit)
    }

    pub(in crate::node_qualification::packet_collection::complete::installed) fn host_setup17_counter_scratch_data()
    -> usize {
        RetainedArchivedSourceInstallation17::counter_scratch_data()
            + crucible_node_provider::retained_metadata::original_metadata_observer_layout_bytes()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, crucible_node_provider::ProviderError>>(
            )
            + size_of::<&Self>()
            + size_of::<&Participant>()
            + size_of::<&Measurement>()
            + size_of::<&FileSelection>()
            + size_of::<&Content>()
            + size_of::<&Counter>()
            + size_of::<std::slice::Iter<'static, Participant>>()
            + size_of::<std::slice::Iter<'static, Measurement>>()
            + size_of::<std::slice::Iter<'static, FileSelection>>()
            + size_of::<std::slice::Iter<'static, Content>>()
            + size_of::<Result<(), RuntimeError>>()
    }
}

impl Measurement {
    fn charge_host_setup17_data(&self, counter: &mut Counter) -> Result<(), RuntimeError> {
        let Self {
            peer,
            host,
            sources,
        } = self;
        peer.charge_host_setup17_data(counter)?;
        counter.charge(host).map_err(limit)?;
        counter
            .add(
                sources
                    .capacity()
                    .checked_mul(size_of::<FileSelection>())
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(limit)?;
        for file in sources {
            file.charge_host_setup17_data(counter)?;
        }
        Ok(())
    }
}

impl FileSelection {
    fn charge_host_setup17_data(&self, counter: &mut Counter) -> Result<(), RuntimeError> {
        let Self {
            role,
            path,
            content,
        } = self;
        counter.charge(role).map_err(limit)?;
        counter.charge(path).map_err(limit)?;
        counter.charge(content).map_err(limit)
    }
}

impl NativeSelection {
    fn charge_host_setup17_data(&self, counter: &mut Counter) -> Result<(), RuntimeError> {
        let Self {
            provider,
            profile,
            descriptor,
            binding,
            capabilities,
            exact_facet,
            guarantees,
            owner,
            realize,
            admission,
            transaction,
            gate,
            admission_receipt,
            world_binding_hash,
            receipt_schema,
            maximum_operations: _,
            maximum_result_bytes: _,
            maximum_authorization_bytes: _,
            maximum_semantic_bytes: _,
        } = self;
        // This defining Provider loan observes these exact fifteen real fields.
        // Its historical name gives this live operator DATA no archive authority.
        let loan = RetainedArchivedSourceInstallation17 {
            provider,
            profile,
            descriptor,
            binding,
            capabilities,
            exact_facet,
            guarantees,
            owner,
            realize,
            admission,
            transaction,
            gate,
            admission_receipt,
            world_binding_hash,
            receipt_schema,
        };
        let facts = loan
            .observe_retained_metadata()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        counter.metadata(&facts).map_err(limit)
    }
}

impl Participant {
    fn charge_host_setup17_data(&self, counter: &mut Counter) -> Result<(), RuntimeError> {
        let Self {
            installation,
            program,
            storage,
            capture_profile,
            protocol_metadata,
        } = self;
        installation.charge_host_setup17_data(counter)?;
        counter.charge(program).map_err(limit)?;
        check_fixed_storage(storage);
        match capture_profile {
            PacketNative5CaptureProfile::OriginalArrays6 => {}
            PacketNative5CaptureProfile::CompactBytes7 {
                native_before_protocol_bytes: _,
                native_after_protocol_bytes: _,
                host_protocol_bytes: _,
            }
            | PacketNative5CaptureProfile::OwnedProtocol11 {
                native_before_protocol_bytes: _,
                native_after_protocol_bytes: _,
                host_protocol_bytes: _,
            } => {}
        }
        let PacketNative5ProtocolMetadataLimits {
            native_before_rows: _,
            native_after_rows: _,
        } = protocol_metadata;
        Ok(())
    }
}

fn check_fixed_storage(storage: &PacketNative5StorageSelection) {
    use crucible_node_provider::{
        handshake::Limits, reference_packet::service::PacketNative5StorageLimits,
    };
    let PacketNative5StorageSelection { storage, limits } = storage;
    let PacketNative5StorageLimits {
        snapshot_bytes: _,
        control_snapshot_bytes: _,
        protocol_snapshot_bytes: _,
        frame_bank_bytes: _,
        frames_per_direction: _,
        hello_bytes: _,
        settlement_bytes: _,
    } = storage;
    let Limits {
        frame_bytes: _,
        nesting: _,
        requests: _,
        journal_entries: _,
        blob_chunk_bytes: _,
    } = limits;
}

impl CompleteMechanism {
    fn check_inline_setup17_data(&self) {
        use crucible_node_provider::reference_packet::service::{
            complete_restore::{
                PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
            },
            fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
        };
        let Self {
            complete_restore,
            restore_input_emitter,
            fresh_restore_allocation,
        } = self;
        match complete_restore {
            PacketNative5CompleteRestoreSelection::SourceSignedOwned11
            | PacketNative5CompleteRestoreSelection::SourceSignedTransfer12 => {}
        }
        match restore_input_emitter {
            PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12 => {}
        }
        match fresh_restore_allocation {
            PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13 => {}
        }
    }
}

fn limit(_: QualificationError) -> RuntimeError {
    RuntimeError::ResourceLimit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_qualification::packet_collection::complete::retained::Owned;

    #[test]
    fn measurement_counts_actual_spare_capacity_and_refuses_one_byte_short() {
        let reference = canonical::content_ref(b"actual data", "application/json").unwrap();
        let mut role = String::with_capacity(83);
        role.push_str("peer");
        let mut path = PathBuf::with_capacity(109);
        path.push("/operator/selected");
        let mut sources = Vec::with_capacity(7);
        sources.push(FileSelection {
            role: role.clone(),
            path: path.clone(),
            content: reference.clone(),
        });
        let measurement = Measurement {
            peer: FileSelection {
                role,
                path,
                content: reference.clone(),
            },
            host: reference,
            sources,
        };
        let mut expected = Counter::new(usize::MAX);
        expected.charge(&measurement.peer.role).unwrap();
        expected.charge(&measurement.peer.path).unwrap();
        expected.charge(&measurement.peer.content).unwrap();
        expected.charge(&measurement.host).unwrap();
        expected
            .add(measurement.sources.capacity() * size_of::<FileSelection>())
            .unwrap();
        for row in &measurement.sources {
            row.role.charge(&mut expected).unwrap();
            row.path.charge(&mut expected).unwrap();
            row.content.charge(&mut expected).unwrap();
        }
        let demand = expected.bytes();
        let mut exact = Counter::new(demand);
        measurement.charge_host_setup17_data(&mut exact).unwrap();
        assert_eq!(exact.bytes(), demand);
        let before_capacity = measurement.sources.capacity();
        let before_pointer = measurement.sources.as_ptr();
        let mut short = Counter::new(demand - 1);
        assert!(measurement.charge_host_setup17_data(&mut short).is_err());
        assert_eq!(measurement.sources.len(), 1);
        assert_eq!(measurement.sources.capacity(), before_capacity);
        assert_eq!(measurement.sources.as_ptr(), before_pointer);
    }

    #[test]
    fn independently_retained_measurement_copy_keeps_its_own_backing() {
        let reference = canonical::content_ref(b"actual data", "application/json").unwrap();
        let row = FileSelection {
            role: String::from("peer"),
            path: PathBuf::from("/operator/selected"),
            content: reference.clone(),
        };
        let measurement = Measurement {
            peer: row.clone(),
            host: reference,
            sources: vec![row],
        };
        let duplicate = Measurement {
            peer: measurement.peer.clone(),
            host: measurement.host.clone(),
            sources: measurement.sources.clone(),
        };
        assert_ne!(measurement.sources.as_ptr(), duplicate.sources.as_ptr());
        assert_ne!(measurement.peer.role.as_ptr(), duplicate.peer.role.as_ptr());
        let mut other = Counter::new(usize::MAX);
        duplicate.charge_host_setup17_data(&mut other).unwrap();
        let mut counter = Counter::new(usize::MAX);
        measurement.charge_host_setup17_data(&mut counter).unwrap();
        let first = counter.bytes();
        duplicate.charge_host_setup17_data(&mut counter).unwrap();
        assert_eq!(counter.bytes(), first + other.bytes());
    }
}
