//! Reads inert Source Producer fields without creating a live admission.
//!
//! These checked fields are one component of the settled reader. The owning
//! reader must additionally join the defining historical SDK pairs, completed
//! and retired native proofs, exact mapped Outcome and historical MAC verifier.
//! This module cannot mark a Source or archive complete on its own.

use crate::{
    node_contract::{NodeRoute, OperationOutcome, OperationRequest, RuntimeError},
    node_scheduling::{InputPayload, NativeSchedulingObservation},
};
use crucible_node_contract::{ContentRef, Id, canonical};
use crucible_node_provider::{
    bodies::{BeginRequest, ExactRunArguments, ObserveRequest, PollRequest, RetireRequest},
    reference_packet::{
        control::PacketNativeRecord, service::complete_restore::PacketNativeRestoredRecord,
    },
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use std::io::{self, Write};

pub(super) const ATTEMPT_FIELDS: [&str; 35] = [
    "row",
    "slot",
    "admission",
    "authorization",
    "arguments",
    "begin_body",
    "poll_body",
    "retire_body",
    "observe_body",
    "begin",
    "poll",
    "retire",
    "observe",
    "uploads",
    "upload_bodies",
    "request_ids",
    "record_values",
    "record_canonical",
    "completed_record",
    "completed_producer",
    "completed_measurement",
    "outcome",
    "report_value",
    "report_bytes",
    "report_reference",
    "durable_root",
    "consumption",
    "consumption_value",
    "checkpoint_record",
    "checkpoint_producer",
    "checkpoint_measurement",
    "scheduling",
    "previous",
    "signature",
    "stage",
];

/// Keeps owning decoder temporaries separate from any live Runtime handle.
///
/// The enclosing reader retains its exact input and partial DOM before calling
/// this function and independently admits these typed and canonical owners.
/// None of the fields can reconstruct an operation token or World authority.
pub(super) struct ProducerAttemptFields17<'a> {
    pub(super) original: &'a Map<String, Value>,
    pub(super) slot: usize,
    pub(super) admission: &'a Value,
    pub(super) operation: Id,
    pub(super) route: NodeRoute,
    pub(super) request: OperationRequest,
    pub(super) arguments: ExactRunArguments,
    pub(super) begin_body: BeginRequest,
    pub(super) poll_body: PollRequest,
    pub(super) retire_body: RetireRequest,
    pub(super) observe_body: ObserveRequest,
    pub(super) authorization: InputPayload,
    pub(super) completed_record: PacketNativeRestoredRecord,
    pub(super) completed_producer: PacketNativeRecord,
    pub(super) completed_measurement: ContentRef,
    pub(super) checkpoint_record: PacketNativeRestoredRecord,
    pub(super) checkpoint_producer: PacketNativeRecord,
    pub(super) checkpoint_measurement: ContentRef,
    pub(super) outcome: OperationOutcome,
    pub(super) scheduling: NativeSchedulingObservation,
    pub(super) report_reference: ContentRef,
    pub(super) durable_root: ContentRef,
    pub(super) consumption: InputPayload,
    pub(super) previous: [u8; 32],
    pub(super) signature: [u8; 32],
}

impl<'a> ProducerAttemptFields17<'a> {
    pub(super) fn read_data(value: &'a Value) -> Result<Self, RuntimeError> {
        let original = object(value, &ATTEMPT_FIELDS)?;
        if field(original, "stage")?.as_str() != Some("verified") {
            // Failed and unresolved owners remain present in the written state.
            // They cannot be adopted through this settled, fully retired branch.
            return Err(RuntimeError::OutstandingObligations);
        }
        preflight_record_values_data(original)?;
        let admission = field(original, "admission")?;
        let wrapper = object(admission, &["kind", "value"])?;
        if field(wrapper, "kind")?.as_str() != Some("admission") {
            return Err(invalid());
        }
        let admitted = object(
            field(wrapper, "value")?,
            &["operation", "route", "request", "activation", "inputs"],
        )?;
        if !field(admitted, "inputs")?.is_null() {
            return Err(invalid());
        }
        let route_fields = object(field(admitted, "route")?, &["node", "owners"])?;
        array(field(route_fields, "owners")?, 1)?;
        let operation: Id = read(field(admitted, "operation")?)?;
        let route: NodeRoute = read(field(admitted, "route")?)?;
        let request: OperationRequest = read(field(admitted, "request")?)?;
        if !matches!(
            request,
            OperationRequest::ExactRun { .. } | OperationRequest::BoundarySettle { .. }
        ) {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let arguments = typed_owner(field(original, "arguments")?, "arguments")?;
        let begin_body = typed_owner(field(original, "begin_body")?, "begin")?;
        let poll_body = typed_owner(field(original, "poll_body")?, "poll")?;
        let retire_body = typed_owner(field(original, "retire_body")?, "retire")?;
        let observe_body = typed_owner(field(original, "observe_body")?, "observe")?;
        let authorization: InputPayload = read(field(original, "authorization")?)?;
        let completed_record = read(field(original, "completed_record")?)?;
        let completed_producer = producer(field(original, "completed_producer")?)?;
        let completed_measurement = read(field(original, "completed_measurement")?)?;
        let checkpoint_record = read(field(original, "checkpoint_record")?)?;
        let checkpoint_producer = producer(field(original, "checkpoint_producer")?)?;
        let checkpoint_measurement = read(field(original, "checkpoint_measurement")?)?;
        let outcome: OperationOutcome = read(field(original, "outcome")?)?;
        let scheduling: NativeSchedulingObservation = read(field(original, "scheduling")?)?;
        let consumption: InputPayload = read(field(original, "consumption")?)?;
        for payload in [&authorization, &consumption] {
            payload
                .reference
                .verify(&payload.bytes)
                .map_err(|_| invalid())?;
        }
        if operation != outcome.operation
            || route.node != outcome.node
            || route.owners != outcome.owners
            || route.node != scheduling.node
            || route.owners != scheduling.owners
        {
            return Err(invalid());
        }
        let output = Self {
            original,
            slot: read(field(original, "slot")?)?,
            admission,
            operation,
            route,
            request,
            arguments,
            begin_body,
            poll_body,
            retire_body,
            observe_body,
            authorization,
            completed_record,
            completed_producer,
            completed_measurement,
            checkpoint_record,
            checkpoint_producer,
            checkpoint_measurement,
            outcome,
            scheduling,
            report_reference: read(field(original, "report_reference")?)?,
            durable_root: read(field(original, "durable_root")?)?,
            consumption,
            previous: read(field(original, "previous")?)?,
            signature: read(field(original, "signature")?)?,
        };
        output.authenticate_record_banks_data()?;
        output.authenticate_source_payloads_data()?;
        Ok(output)
    }

    fn authenticate_record_banks_data(&self) -> Result<(), RuntimeError> {
        let banks = array(field(self.original, "record_canonical")?, 4)?;
        let completed_bytes: Vec<u8> = read(&banks[0])?;
        let completed_producer_bytes: Vec<u8> = read(&banks[1])?;
        let checkpoint_bytes: Vec<u8> = read(&banks[2])?;
        let checkpoint_producer_bytes: Vec<u8> = read(&banks[3])?;
        self.completed_measurement
            .verify(&completed_bytes)
            .map_err(|_| invalid())?;
        self.completed_record
            .native_receipt
            .native_record
            .verify(&completed_producer_bytes)
            .map_err(|_| invalid())?;
        self.checkpoint_measurement
            .verify(&checkpoint_bytes)
            .map_err(|_| invalid())?;
        self.checkpoint_record
            .native_receipt
            .native_record
            .verify(&checkpoint_producer_bytes)
            .map_err(|_| invalid())?;
        // The allocation-free preflight already joined these exact Value fields
        // to all four banks before their single typed decode. Rebuilding four
        // duplicate native owners here would require another independent row.
        Ok(())
    }

    fn authenticate_source_payloads_data(&self) -> Result<(), RuntimeError> {
        let report_bytes: Vec<u8> = read(field(self.original, "report_bytes")?)?;
        self.report_reference
            .verify(&report_bytes)
            .map_err(|_| invalid())?;
        if canonical::canonical_json(field(self.original, "report_value")?)
            .map_err(|_| invalid())?
            != report_bytes
            || canonical::canonical_json(field(self.original, "consumption_value")?)
                .map_err(|_| invalid())?
                != self.consumption.bytes
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn preflight_record_values_data(original: &Map<String, Value>) -> Result<(), RuntimeError> {
    let row = object(
        field(original, "row")?,
        &[
            "provider",
            "maximum_restored_record_bytes",
            "maximum_underlying_record_bytes",
            "retained",
            "transient",
            "scratch",
            "maximum",
            "runtime_work",
            "complete_scratch",
        ],
    )?;
    let restored: usize = read(field(row, "maximum_restored_record_bytes")?)?;
    let underlying: usize = read(field(row, "maximum_underlying_record_bytes")?)?;
    if restored != 65_536 || underlying != 65_536 {
        return Err(invalid());
    }
    let values = array(field(original, "record_values")?, 4)?;
    let banks = array(field(original, "record_canonical")?, 4)?;
    for ((value, bank), maximum) in values
        .iter()
        .zip(banks)
        .zip([restored, underlying, restored, underlying])
    {
        let bank = bank.as_array().ok_or_else(invalid)?;
        if value.is_null() || bank.len() > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        // Stream against the already retained byte-array owner. A malformed
        // Value cannot allocate a new canonical buffer before failing its bound.
        let mut writer = CanonicalBankComparison { bank, offset: 0 };
        canonical::canonical_json_to_writer(value, &mut writer).map_err(|_| invalid())?;
        if writer.offset != bank.len() {
            return Err(invalid());
        }
    }
    // Establish equality with the bounded canonical-bank owners before typed
    // decoding; a separately expanded typed field is not an extra allowance.
    if field(original, "completed_record")? != &values[0]
        || field(original, "checkpoint_record")? != &values[2]
    {
        return Err(invalid());
    }
    for (name, expected) in [
        ("completed_producer", &values[1]),
        ("checkpoint_producer", &values[3]),
    ] {
        let value = object(field(original, name)?, &["kind", "value"])?;
        if field(value, "kind")?.as_str() != Some("producer") || field(value, "value")? != expected
        {
            return Err(invalid());
        }
        preflight_producer_population_data(expected)?;
    }
    Ok(())
}

fn preflight_producer_population_data(record: &Value) -> Result<(), RuntimeError> {
    let record = record.as_object().ok_or_else(invalid)?;
    preflight_inventory_data(field(record, "inventory")?)?;
    let grant = field(record, "grant")?;
    if !grant.is_null() {
        let grant = grant.as_object().ok_or_else(invalid)?;
        preflight_inventory_data(field(grant, "inventory")?)?;
        if field(grant, "newborn")?
            .as_array()
            .ok_or_else(invalid)?
            .len()
            > 1
        {
            return Err(RuntimeError::ResourceLimit);
        }
    }
    Ok(())
}

fn preflight_inventory_data(inventory: &Value) -> Result<(), RuntimeError> {
    let inventory = inventory.as_object().ok_or_else(invalid)?;
    if field(inventory, "pending")?
        .as_array()
        .ok_or_else(invalid)?
        .len()
        > 2
        || field(inventory, "retained_outputs")?
            .as_array()
            .ok_or_else(invalid)?
            .len()
            > 1
    {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(())
}

pub(super) fn object<'a>(
    value: &'a Value,
    names: &[&str],
) -> Result<&'a Map<String, Value>, RuntimeError> {
    let value = value.as_object().ok_or_else(invalid)?;
    if value.len() != names.len() || names.iter().any(|name| !value.contains_key(*name)) {
        return Err(invalid());
    }
    Ok(value)
}

pub(super) fn field<'a>(
    value: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a Value, RuntimeError> {
    value.get(name).ok_or_else(invalid)
}

pub(super) fn array(value: &Value, length: usize) -> Result<&[Value], RuntimeError> {
    let value = value.as_array().ok_or_else(invalid)?;
    if value.len() != length {
        return Err(invalid());
    }
    Ok(value)
}

pub(super) fn read<T: DeserializeOwned + Serialize>(value: &Value) -> Result<T, RuntimeError> {
    let decoded = T::deserialize(value).map_err(|_| invalid())?;
    // Typed decoders can ignore unknown fields or accept alternate shapes.
    // Archived logical values must preserve the exact defining writer grammar.
    if serde_json::to_value(&decoded).map_err(|_| invalid())? != *value {
        return Err(invalid());
    }
    Ok(decoded)
}

fn typed_owner<T: DeserializeOwned + Serialize>(
    value: &Value,
    kind: &str,
) -> Result<T, RuntimeError> {
    let value = object(value, &["kind", "data"])?;
    if field(value, "kind")?.as_str() != Some(kind) {
        return Err(invalid());
    }
    read(field(value, "data")?)
}

fn producer(value: &Value) -> Result<PacketNativeRecord, RuntimeError> {
    let value = object(value, &["kind", "value"])?;
    if field(value, "kind")?.as_str() != Some("producer") {
        return Err(invalid());
    }
    read(field(value, "value")?)
}

fn invalid() -> RuntimeError {
    RuntimeError::InvalidReceipt
}

/// Compares canonical output directly with a retained JSON byte-array bank.
struct CanonicalBankComparison<'a> {
    bank: &'a [Value],
    offset: usize,
}

impl Write for CanonicalBankComparison<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .offset
            .checked_add(bytes.len())
            .ok_or(io::ErrorKind::InvalidData)?;
        let expected = self
            .bank
            .get(self.offset..end)
            .ok_or(io::ErrorKind::InvalidData)?;
        if bytes
            .iter()
            .zip(expected)
            .any(|(actual, expected)| expected.as_u64() != Some(u64::from(*actual)))
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.offset = end;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_record_canonical_comparison_rejects_changed_or_short_banks()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = serde_json::json!({"original": "escaped\"request", "inventory": [1, 2]});
        let canonical = canonical::canonical_json(&value)?;
        let mut bank: Vec<Value> = canonical.iter().copied().map(Value::from).collect();
        let mut writer = CanonicalBankComparison {
            bank: &bank,
            offset: 0,
        };

        canonical::canonical_json_to_writer(&value, &mut writer)?;
        assert_eq!(writer.offset, bank.len());

        bank[0] = Value::from(0);
        let mut changed = CanonicalBankComparison {
            bank: &bank,
            offset: 0,
        };
        assert!(canonical::canonical_json_to_writer(&value, &mut changed).is_err());

        let mut short = CanonicalBankComparison {
            bank: &[],
            offset: 0,
        };
        assert!(canonical::canonical_json_to_writer(&value, &mut short).is_err());
        assert_eq!(short.offset, 0);
        Ok(())
    }

    #[test]
    fn source_typed_values_refuse_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct ClosedValue {
            operation: String,
        }

        let value = serde_json::json!({"operation": "actual"});
        assert_eq!(read::<ClosedValue>(&value)?.operation, "actual");

        let changed = serde_json::json!({"operation": "actual", "ignored": true});
        assert!(matches!(
            read::<ClosedValue>(&changed),
            Err(RuntimeError::InvalidReceipt)
        ));
        Ok(())
    }

    #[test]
    fn source_record_preflight_refuses_unbounded_population_before_typed_decode() {
        let inventory = serde_json::json!({"pending": [null, null, null], "retained_outputs": []});
        assert!(matches!(
            preflight_inventory_data(&inventory),
            Err(RuntimeError::ResourceLimit)
        ));

        let inventory = serde_json::json!({"pending": [], "retained_outputs": [null, null]});
        assert!(matches!(
            preflight_inventory_data(&inventory),
            Err(RuntimeError::ResourceLimit)
        ));
    }
}
