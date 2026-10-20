//! Prices borrowed launch validation independently of launch decoding.
//!
//! The two passes have different prerequisites. The first observes native
//! containers without invoking Serialize. Its formatter window must be admitted
//! before the second pass invokes the existing closed serialization counters.
//! Neither pass validates a launch or supplies Source/native authority.

use super::*;
use crate::retained_metadata::{
    RetainedProtocolMetadataFacts, observe_retained_native_launch,
    serialization_storage::{
        OriginalSerializationStorageData, OriginalSerializationStorageProjection,
        original_serialization_counter_scratch_data,
        original_serialization_formatter_temporary_storage_data,
    },
};
use crucible_node_format::SchemaRef;

type ConstructionAxes = (usize, usize);

impl PacketNative5SourceLaunch {
    /// Quotes formatter work before counting the complete launch validator.
    ///
    /// Returns temporary requested bytes and fixed counter scratch. This first
    /// pass only observes actual native containers; it creates no serialization,
    /// DOM, decoded coordinator, policy, effect or permission. The caller first
    /// admits [`Self::validation_construction_counter_scratch_data`], then adds
    /// these axes beside every still-live owner before requesting the full row.
    ///
    /// # Errors
    /// Refuses overflow or an unsupported actual typed metadata traversal.
    pub fn validation_construction_projection_storage_data(
        &self,
    ) -> Result<ConstructionAxes, ProviderError> {
        let actual = observe_retained_native_launch(self)?;
        Ok((
            original_serialization_formatter_temporary_storage_data(&actual)?,
            Self::validation_construction_counter_scratch_data(),
        ))
    }

    /// Quotes all temporary constructors used by the unchanged launch validator.
    ///
    /// Returns temporary requested bytes and fixed scratch; there is no retained
    /// result from `validate`. The caller must already admit the projection row
    /// from [`Self::validation_construction_projection_storage_data`], including
    /// all live caches, because closed Serialize counters may format Bytes.
    /// Before invoking `validate`, the caller independently admits the complete
    /// returned axes beside those same live caches. This row grants neither
    /// constructor execution nor native installation, and never raises a cap.
    ///
    /// The decoded coordinator, cloned policy fields, program DOM, ingress
    /// schema and schema references remain charged across subordinate calls.
    /// Returning factory/validator phases reuse their work window, but no live
    /// owner is subtracted at such a boundary. Existing coordinator geometry
    /// follows its actual raw typed subtrees and compiled contract definitions.
    ///
    /// # Errors
    /// Refuses incomplete coordinator geometry, checked overflow or a complete
    /// temporary-plus-scratch row above `maximum_requested_bytes`. It neither
    /// changes the accepted launch grammar nor substitutes for `validate`.
    pub fn validation_construction_storage_data(
        &self,
        maximum_requested_bytes: usize,
    ) -> Result<ConstructionAxes, ProviderError> {
        let maximum = maximum_requested_bytes;
        let scratch = Self::validation_construction_counter_scratch_data();
        let actual = observe_retained_native_launch(self)?;
        let formatter = original_serialization_formatter_temporary_storage_data(&actual)?;

        let mut configuration = OriginalSerializationStorageProjection::new(maximum)?;
        match &self.program {
            PacketConnectedSourceProgram::Producer { program } => {
                configuration.add_value(program)?
            }
            PacketConnectedSourceProgram::Reactive { program } => {
                configuration.add_value(program)?
            }
        }
        let configuration = configuration.finish(maximum)?;
        let definitions = schemas::project(self, maximum)?;
        let schema_children = schema_owners(self, maximum)?;

        // One complete coordinator decode/validator window covers both the
        // top-level call and each later sequential immutable-policy check.
        // The policy's decoded coordinator stays live during those checks and
        // therefore has a separate backing term below.
        let coordinator = coordinator_decode::construction_storage_data(
            self.initial_coordinator.bytes.as_slice(),
            maximum,
        )?;
        let coordinator_work = coordinator.transient;
        let connected_backing = coordinator.retained;
        // Static prewalk controls are already in the defining counter. Nested
        // reset parsers have an input-dependent extra S admitted with this row.
        let scratch = sum(&[scratch, coordinator.additional_scratch], maximum)?;
        let selection_backing = metadata_backing(&self.selection)?;

        // Provider/realization validators construct sorted-key clones and
        // OwnerBinding participant lists. Sorted comparisons hold two keys,
        // each selected from the original String/Id fields. Participant collect
        // has an exact size hint; its Id slots fit the same original
        // node_bindings Vec's larger NodeBindingRef slots, and its strings come
        // from those original node IDs. Two full original backings therefore
        // cover both keys and that independent vector without a map-node or
        // encoded-size assumption. Policy's real selection clone is separate.
        let selection_validation = sum(&[selection_backing, selection_backing], maximum)?;
        let temporary = sum(
            &[
                formatter,
                configuration.requested_total()?,
                coordinator_work,
                connected_backing,
                selection_backing,
                selection_validation,
                self.initial_coordinator.bytes.as_slice().len(),
                metadata_backing(&self.initial_coordinator.reference)?,
                definitions.transient,
                definitions.retained_reference_children,
                schema_children,
            ],
            maximum,
        )?;
        sum(&[temporary, scratch], maximum)?;
        Ok((temporary, scratch))
    }

    /// Names the concrete observer, projection and constructor header windows.
    ///
    /// This value is admitted before the first metadata walk. It includes the
    /// actual temporary policy and coordinator headers and returned schema
    /// arrays, independently of their heap backing. It describes explicit
    /// constructor values and counter views, not compiler frames or residency.
    pub fn validation_construction_counter_scratch_data() -> usize {
        use crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation;
        use crate::reference_packet::service::Native5Policy;

        Self::VALIDATION_INPUT_COUNTER_SCRATCH_DATA
            + crate::retained_metadata::retained_native_launch_counter_scratch_data()
            + original_serialization_counter_scratch_data()
            + crate::connection::original_serialized_credit_counter_scratch_data()
            + coordinator_decode::counter_scratch_data()
            + decoded::counter_scratch_data()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<schemas::InitialSchemaStorage>()
            + size_of::<Result<schemas::InitialSchemaStorage, ProviderError>>()
            + size_of::<Native5Policy>()
            + size_of::<Result<Native5Policy, ProviderError>>()
            + size_of::<PacketNative5CoordinatorInstallation>()
            + size_of::<Result<PacketNative5CoordinatorInstallation, ProviderError>>()
            + size_of::<SchemaRef>()
            + size_of::<Result<SchemaRef, ProviderError>>()
            + size_of::<[SchemaRef; 7]>()
            + size_of::<[SchemaRef; 5]>()
            + size_of::<[SchemaRef; 3]>()
            + size_of::<[SchemaRef; 2]>()
            + size_of::<crate::reference_packet::service::PacketNative5CaptureProfile>()
            + size_of::<[(String, String); 2]>()
            + size_of::<Vec<crucible_node_format::Id>>()
            + size_of::<std::slice::Iter<'static, crucible_node_format::NodeBindingRef>>()
            + size_of::<OriginalSerializationStorageProjection>()
            + size_of::<OriginalSerializationStorageData>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
            + size_of::<ConstructionAxes>()
            + size_of::<Result<ConstructionAxes, ProviderError>>()
            + size_of::<[usize; 12]>()
            + size_of::<[(bool, usize); 7]>()
            + size_of::<std::array::IntoIter<(bool, usize), 7>>()
            + size_of::<[u8; 20]>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            + size_of::<String>()
            + 10 * size_of::<usize>()
    }
}

fn schema_owners(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<usize, ProviderError> {
    use crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection;

    // A factory SchemaRef owns one bounded Id and the four ContentRef strings.
    // Id's defining accepted maximum is 128 bytes; all definition hashes use
    // the fixed CNP BLAKE3 domain and JSON media. This is reference backing,
    // separate from the actual compiled contract DOM/canonical factory rows.
    let reference = sum(
        &[
            128,
            "blake3-256".len(),
            "cnp.blob.v1".len(),
            2 * blake3::OUT_LEN,
            "application/json".len(),
        ],
        maximum,
    )?;
    let mut count = 1usize;
    for (selected, references) in [
        (launch.confirmation_selection.is_some(), 1usize),
        (launch.ack_emitter_selection.is_some(), 2),
        (launch.complete_restore_selection.is_some(), 3),
        (
            launch.complete_restore_selection
                == Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12),
            7,
        ),
        (launch.restore_input_emitter_selection.is_some(), 1),
        (launch.capture_allocation_selection.is_some(), 2),
        (launch.fresh_restore_allocation_selection.is_some(), 5),
    ] {
        if selected {
            count = count.checked_add(references).ok_or_else(refused)?;
        }
    }

    // Keep both a constructor's selected schema set and a validator's fresh
    // set beside the top-level ingress schema. Policy's moved definition refs
    // have their own separate InitialSchemaStorage backing above.
    count
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
        .and_then(|count| count.checked_mul(reference))
        .filter(|bytes| *bytes <= maximum)
        .ok_or_else(refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::Bytes;
    use serde_json::json;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn launch() -> Result<PacketNative5SourceLaunch, Box<dyn std::error::Error>> {
        let (_, _, selection, coordinator) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        // This is an inert DTO with a deliberately unsupported event population.
        // Computing a row must never be confused with successful validation.
        Ok(serde_json::from_value(json!({
            "schema_version":5,
            "selection":selection,
            "program":{"kind":"producer","program":{
                "schema":"source-owned.packet-program.v1","events":[]
            }},
            "controller_pid":"1","controller_uid":"0",
            "controller_executable":coordinator.reference,
            "admission_token":Bytes::new(vec![7;32]),
            "initial_coordinator":coordinator,
            "limits":{"frame_bytes":"65536","nesting":"64","requests":"64",
                "journal_entries":"256","blob_chunk_bytes":"1024"},
            "storage":{"snapshot_bytes":"16384","control_snapshot_bytes":"8192",
                "protocol_snapshot_bytes":"65536","frame_bank_bytes":"65536",
                "frames_per_direction":"256","hello_bytes":"131080",
                "settlement_bytes":"65536"},
            "effects":"/not-opened-by-construction-data"
        }))?)
    }

    #[test]
    fn whole_validator_axes_have_an_exact_independent_admission_boundary() -> TestResult {
        let launch = launch()?;
        let (formatter, counter) = launch.validation_construction_projection_storage_data()?;
        let (temporary, scratch) = launch.validation_construction_storage_data(usize::MAX)?;
        let exact = temporary.checked_add(scratch).ok_or("row overflow")?;

        assert_eq!(counter, scratch);
        assert!(temporary >= formatter);
        assert_eq!(
            launch.validation_construction_storage_data(exact)?,
            (temporary, scratch)
        );
        assert!(
            launch
                .validation_construction_storage_data(exact - 1)
                .is_err()
        );
        assert!(launch.validation_construction_storage_data(0).is_err());
        assert!(launch.validate().is_err());
        Ok(())
    }

    #[test]
    fn formatter_preflight_preserves_actual_spare_native_byte_backing() -> TestResult {
        let mut launch = launch()?;
        let (initial, scratch) = launch.validation_construction_projection_storage_data()?;
        let bytes = launch.initial_coordinator.bytes.as_slice().to_vec();
        let mut reserved = Vec::with_capacity(bytes.len() + 4096);
        reserved.extend_from_slice(&bytes);
        let capacity = reserved.capacity();
        launch.initial_coordinator.bytes = Bytes::new(reserved);
        let pointer = launch.initial_coordinator.bytes.as_slice().as_ptr();

        let (formatter, repeated_scratch) =
            launch.validation_construction_projection_storage_data()?;
        assert!(formatter >= capacity.div_ceil(3) * 4);
        assert!(formatter >= initial);
        assert_eq!(repeated_scratch, scratch);
        assert_eq!(launch.initial_coordinator.bytes.as_slice(), bytes);
        assert_eq!(
            launch.initial_coordinator.bytes.as_slice().as_ptr(),
            pointer
        );
        Ok(())
    }

    #[test]
    fn incomplete_coordinator_quote_never_becomes_a_validation_result() -> TestResult {
        let mut launch = launch()?;
        launch.initial_coordinator.bytes = Bytes::new(br#"{"schema":"partial"}"#.to_vec());
        let pointer = launch.initial_coordinator.bytes.as_slice().as_ptr();

        assert!(
            launch
                .validation_construction_projection_storage_data()
                .is_ok()
        );
        assert!(
            launch
                .validation_construction_storage_data(usize::MAX)
                .is_err()
        );
        assert_eq!(
            launch.initial_coordinator.bytes.as_slice().as_ptr(),
            pointer
        );
        assert_eq!(
            launch.initial_coordinator.bytes.as_slice(),
            br#"{"schema":"partial"}"#
        );
        Ok(())
    }
}
