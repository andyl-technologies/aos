//! Checks original Source execution backing without installing native authority.
//!
//! Declaration/reservation paths create genuine unassociated Sources. Populated
//! public DTOs and failed slots are capacity DATA only; no child, completed
//! Initial, native witness, Source action or capture ticket is constructed.

use super::super::super::tests::{
    coordinator, installation, producer, reactive, storage_selection,
};
use super::*;

const BACKEND_BYTES: usize = 4096;
const ADMITTED_BYTES: usize = 4 * 1024 * 1024;

fn source(member: usize) -> PacketCompleteSemanticSource {
    let coordinator = coordinator();
    let installation = installation(&coordinator, member);
    let mut source = if member == 0 {
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            installation,
            producer(),
            coordinator,
            storage_selection(),
        )
        .unwrap()
    } else {
        let definition = reactive(&coordinator, member);
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            installation,
            definition,
            coordinator,
            storage_selection(),
        )
        .unwrap()
    };
    source
        .bind_original_capture_profile(PacketNative5CaptureProfile::OwnedProtocol11 {
            native_before_protocol_bytes: U64::new(1024 * 1024),
            native_after_protocol_bytes: U64::new(1024 * 1024),
            host_protocol_bytes: U64::new(2 * 1024 * 1024),
        })
        .unwrap();
    source
}

fn reserve(source: &mut PacketCompleteSemanticSource) {
    source
        .reserve_original_complete_capture_execution(BACKEND_BYTES, ADMITTED_BYTES)
        .unwrap();
}

fn payload(bytes: &[u8], spare: usize) -> InputPayload {
    let reference = canonical::content_ref(bytes, "application/json").unwrap();
    let mut retained = Vec::with_capacity(spare.max(bytes.len()));
    retained.extend_from_slice(bytes);
    InputPayload {
        reference,
        bytes: retained,
    }
}

// Preserve the former separate byte formula as an independent regression oracle.
impl OriginalCompleteCaptureExecution {
    fn original_bytes_for_capacity_test(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let bank = match (&self.backend_bank, &self.backend) {
            (Some(bank), None) => bank.allocated_bytes(),
            (None, Some(body)) => body.bytes.capacity(),
            (None, None) if self.failed || self.transferred => 0,
            _ => {
                return Err(RuntimeError::refused(
                    "original backend bank association differs",
                ));
            }
        };
        let references = self
            .backend
            .as_ref()
            .map(|body| {
                NodeRuntime::capture_reference_storage(&body.reference)
                    .map_err(RuntimeError::unknown)
            })
            .transpose()?
            .unwrap_or(0);
        let mut bytes = retained_values::sum_with_error::<RuntimeError, _>(
            [
                bank,
                references,
                self.allocation_bank.capacity(),
                self.allocation
                    .as_ref()
                    .map_or(0, |body| body.bytes.capacity()),
                self.allocation
                    .as_ref()
                    .map(|body| {
                        NodeRuntime::capture_reference_storage(&body.reference)
                            .map_err(RuntimeError::unknown)
                    })
                    .transpose()?
                    .unwrap_or(0),
                self.evidence
                    .capacity()
                    .checked_mul(size_of::<InputPayload>())
                    .ok_or_else(|| RuntimeError::refused("original evidence slots overflow"))?,
                self.born
                    .capacity()
                    .checked_mul(size_of::<born::OriginalBornObject>())
                    .ok_or_else(|| RuntimeError::refused("original creation slots overflow"))?,
            ],
            maximum,
        )?;
        if let Some(plan) = &self.dependency_plan {
            bytes = retained_values::sum_with_error::<RuntimeError, _>(
                [
                    bytes,
                    NodeRuntime::capture_reference_storage(&plan.runtime)
                        .map_err(RuntimeError::unknown)?,
                ],
                maximum,
            )?;
        }
        for original in &self.born {
            bytes = retained_values::sum_with_error::<RuntimeError, _>(
                [
                    bytes,
                    original.retained_storage_with_error::<RuntimeError>(maximum)?,
                ],
                maximum,
            )?;
        }
        for request in self
            .capture_request
            .iter()
            .chain(self.confirmation_request.iter())
        {
            bytes = retained_values::sum_with_error::<RuntimeError, _>(
                [bytes, request.allocated_capacity()],
                maximum,
            )?;
        }
        if let Some(host) = &self.host_protocol {
            bytes = retained_values::sum_with_error::<RuntimeError, _>(
                [
                    bytes,
                    host.bytes.capacity(),
                    NodeRuntime::capture_reference_storage(&host.reference)
                        .map_err(RuntimeError::unknown)?,
                ],
                maximum,
            )?;
        }
        for object in &self.evidence {
            bytes = retained_values::sum_with_error::<RuntimeError, _>(
                [
                    bytes,
                    object.bytes.capacity(),
                    NodeRuntime::capture_reference_storage(&object.reference)
                        .map_err(RuntimeError::unknown)?,
                ],
                maximum,
            )?;
        }
        match (&self.owner, &self.key) {
            (Some(owner), Some(key)) => {
                bytes = retained_values::sum_with_error::<RuntimeError, _>(
                    [
                        bytes,
                        NodeRuntime::capture_native_output_metadata_storage_data(
                            owner,
                            &self.participants,
                            key,
                        )
                        .map_err(RuntimeError::unknown)?,
                    ],
                    maximum,
                )?;
            }
            (None, None) if self.participants.is_empty() => {}
            _ => {
                return Err(RuntimeError::refused(
                    "original output metadata association differs",
                ));
            }
        }
        if let Some(owner) = &self.retained_protocol_owner {
            let metadata = owner
                .original_retained_metadata_facts()
                .map_err(RuntimeError::unknown)?;
            let allocation = owner
                .original_allocation_facts()
                .map_err(RuntimeError::unknown)?;
            let records = owner
                .original_metadata_record_allocation_facts()
                .map_err(RuntimeError::unknown)?;
            let aliases = owner
                .original_alias_allocation_facts()
                .map_err(RuntimeError::unknown)?;
            bytes = retained_values::sum_with_error::<RuntimeError, _>(
                [
                    bytes,
                    PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<
                        RuntimeError,
                    >(&metadata, maximum)?,
                    allocation.literal.map_or(0, |bank| bank.allocated_bytes),
                    records.map_or(0, |bank| bank.allocated_bytes),
                    aliases
                        .map(|bank| bank.row_bytes.checked_add(bank.lookup_bytes))
                        .unwrap_or(Some(0))
                        .ok_or_else(|| {
                            RuntimeError::refused("original moved host alias banks overflow")
                        })?,
                ],
                maximum,
            )?;
        }
        Ok(bytes)
    }
}

#[test]
fn execution_capacity_reservations_keep_all_three_original_sources_and_exact_credit() {
    for member in 0..3 {
        let mut source = source(member);
        assert_eq!(
            source
                .original_complete_capture_execution_capacity_data(None)
                .unwrap()
                .capacity_records,
            0
        );
        reserve(&mut source);
        let execution = source.capture_execution.borrow();
        let execution = execution.as_ref().unwrap();
        let bytes = execution
            .original_bytes_for_capacity_test(usize::MAX)
            .unwrap();

        let facts = source
            .original_complete_capture_execution_capacity_data(None)
            .unwrap();

        assert_eq!(facts.capacity_records, 5);
        assert_eq!(facts.vector_banks, 5);
        assert_eq!(facts.vector_capacity_bytes, bytes);
        // Five empty reserved Vecs and six independently absent optional owners.
        // Eleven common owner visits, five execution fields and two bank flags.
        assert_eq!(facts.observed_nodes, 18);
        assert_eq!(
            execution.retained_storage_with_error::<RuntimeError>(bytes),
            Ok(bytes)
        );
        assert_eq!(
            execution.retained_storage_with_error::<RuntimeError>(bytes - 1),
            Err(RuntimeError::ResourceLimit)
        );
        assert!(source.authenticate_current_native().is_err());
        assert!(source.ack_peer_birth.borrow().is_none());
    }
}

#[test]
fn execution_capacity_keeps_populated_bodies_born_edges_and_schema_extensions() {
    let mut source = source(0);
    reserve(&mut source);
    let mut schema = source.installation().receipt_schema.clone();
    schema.extensions.insert(
        "retained".into(),
        serde_json::json!({"body":["original",17]}),
    );
    let mut slot = source.capture_execution.borrow_mut();
    let execution = slot.as_mut().unwrap();
    execution
        .evidence
        .push(payload(b"actual original evidence", 173));
    let born_payload = payload(b"actual born body", 257);
    let dependency = canonical::content_ref(b"actual dependency", "application/json").unwrap();
    OriginalCompleteCaptureExecution::record_born(
        &mut execution.born,
        born::OriginalBornRole::Semantic,
        &born_payload,
        [&dependency].into_iter(),
        8,
        ADMITTED_BYTES,
    )
    .unwrap();
    execution.allocation_bank.reserve_exact(31);
    execution.allocation = Some(payload(b"retained allocation DATA", 73));
    execution.capture_request = Some(Id::new("capture/data").unwrap());
    execution.confirmation_request = Some(Id::new("confirmation/data").unwrap());
    execution.host_protocol = Some(payload(b"retained protocol DATA", 193));
    execution.owner = Some(Id::new("owner/data").unwrap());
    execution.participants.reserve_exact(7);
    execution
        .participants
        .push(Id::new("participant/one").unwrap());
    execution.key = Some(NativeStateKey {
        implementation: Id::new("implementation/data").unwrap(),
        profile: Id::new("profile/data").unwrap(),
        schema,
    });
    let prior = execution
        .original_bytes_for_capacity_test(usize::MAX)
        .unwrap();
    let pointers = (
        execution.evidence.as_ptr(),
        execution.evidence[0].bytes.as_ptr(),
        execution.born.as_ptr(),
    );
    drop(slot);

    let facts = source
        .original_complete_capture_execution_capacity_data(None)
        .unwrap();
    let bytes = PacketCompleteSemanticSource::complete_retained_metadata_storage_with_error::<
        RuntimeError,
    >(&facts, usize::MAX)
    .unwrap();

    assert!(facts.vector_banks > 5);
    assert!(facts.string_banks > 20);
    assert_eq!(facts.tree_containers, 2);
    assert_eq!(facts.tree_entries, 2);
    // The complete tree envelope is deliberately wider than the former byte
    // formula; the actual key/value layouts stay in the physical census.
    assert!(bytes >= prior);
    let slot = source.capture_execution.borrow();
    let execution = slot.as_ref().unwrap();
    assert_eq!(
        execution.retained_storage_with_error::<RuntimeError>(bytes),
        Ok(bytes)
    );
    assert_eq!(
        execution.retained_storage_with_error::<RuntimeError>(bytes - 1),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(
        (
            execution.evidence.as_ptr(),
            execution.evidence[0].bytes.as_ptr(),
            execution.born.as_ptr()
        ),
        pointers
    );
    assert_eq!(execution.born[0].dependencies(), &[dependency]);
    assert!(
        !execution.started
            && !execution.wire_attempted
            && !execution.failed
            && !execution.transferred
    );
    assert!(source.authenticate_current_native().is_err());
}

#[test]
fn execution_capacity_charges_empty_participant_spare_storage_in_production_admission() {
    let mut source = source(0);
    reserve(&mut source);
    let mut slot = source.capture_execution.borrow_mut();
    let execution = slot.as_mut().unwrap();
    execution.participants.reserve_exact(7);
    let omitted = execution.participants.capacity() * size_of::<Id>();
    let before = execution
        .original_bytes_for_capacity_test(usize::MAX)
        .unwrap();
    let pointer = execution.participants.as_ptr();
    drop(slot);

    let facts = source
        .original_complete_capture_execution_capacity_data(None)
        .unwrap();
    let bytes = before + omitted;
    let slot = source.capture_execution.borrow();
    let execution = slot.as_ref().unwrap();

    assert_eq!(facts.vector_capacity_bytes, bytes);
    assert_eq!(
        execution.retained_storage_with_error::<RuntimeError>(bytes),
        Ok(bytes)
    );
    assert_eq!(
        execution.retained_storage_with_error::<RuntimeError>(bytes - 1),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(execution.participants.as_ptr(), pointer);
    assert!(execution.participants.is_empty());
    assert!(execution.owner.is_none() && execution.key.is_none());
}

#[test]
fn execution_capacity_failed_coexisting_slots_preserve_data_and_association_refusal() {
    let mut source = source(0);
    reserve(&mut source);
    let before = source
        .original_complete_capture_execution_capacity_data(None)
        .unwrap();
    let body = payload(b"failed backend DATA", 193);
    let bytes =
        body.bytes.capacity() + NodeRuntime::capture_reference_storage(&body.reference).unwrap();
    let mut slot = source.capture_execution.borrow_mut();
    let execution = slot.as_mut().unwrap();
    execution.backend = Some(body);
    execution.failed = true;
    drop(slot);

    let facts = source
        .original_complete_capture_execution_capacity_data(None)
        .unwrap();

    assert_eq!(facts.capacity_records, before.capacity_records + 5);
    assert_eq!(
        facts.vector_capacity_bytes + facts.string_capacity_bytes,
        before.vector_capacity_bytes + bytes
    );
    let slot = source.capture_execution.borrow();
    let execution = slot.as_ref().unwrap();
    assert_eq!(
        execution.retained_storage_with_error::<RuntimeError>(usize::MAX),
        Err(RuntimeError::UnsupportedFacet)
    );
    assert!(execution.backend_bank.is_some() && execution.backend.is_some());
    assert!(execution.failed && !execution.transferred);
}

#[test]
fn execution_capacity_short_rows_keep_prior_component_and_refused_prefix() {
    let mut source = source(0);
    reserve(&mut source);
    let slot = source.capture_execution.borrow();
    let execution = slot.as_ref().unwrap();
    let prior = String::with_capacity(173);
    let mut census = OriginalOwnerCapacityMetadataData::new(3, None);
    census.observe(&prior).unwrap();

    assert_eq!(
        execution.record_capacity_data(&mut census),
        Err(RuntimeError::ResourceLimit)
    );
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 3);
    assert_eq!(facts.string_capacity_bytes, prior.capacity());
    assert_eq!(facts.vector_banks, 2);
    assert_eq!(facts.vector_capacity_bytes, BACKEND_BYTES);
    assert!(!execution.started && !execution.failed && !execution.transferred);
}

#[test]
fn execution_capacity_busy_or_foreign_source_refuses_before_child_observation() {
    for member in 0..3 {
        let mut source = source(member);
        reserve(&mut source);
        let lock = source.capture_execution.borrow_mut();
        assert_eq!(
            source.original_complete_capture_execution_capacity_data(None),
            Err(RuntimeError::OwnerBusy)
        );
        drop(lock);
        source.process = source.process.wrapping_add(1);

        assert_eq!(
            source.original_complete_capture_execution_capacity_data(None),
            Err(RuntimeError::ForeignAuthority)
        );
        assert!(source.ack_peer_birth.borrow().is_none());
    }
}
