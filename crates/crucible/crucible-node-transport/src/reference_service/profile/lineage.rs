//! Distinct selected source semantics and original-consumption proof codecs.

use super::{ProfileContent, ProviderError, SchemaRef, schema};

pub(super) fn add_formats(
    content: &mut Vec<ProfileContent>,
    formats: &mut Vec<SchemaRef>,
) -> Result<(), ProviderError> {
    formats.push(schema(content, "reference-device/lineage-stage-v1",
                "crucible.reference.lineage-native.v1 stage: closed version1; unchanged DeviceGrant, original canonical accepted InputBatch ContentRef, ordered event_index/payload/byte_start/byte_end entries and original input bytes. All ranges exactly cover at most4096 octets and64 events including explicit zero-byte ranges. Pure decoding conveys no source authority.")?);
    formats.push(schema(content, "reference-device/lineage-native-receipt-v1",
                "Native lineage Close version1: unchanged original grant, stage typed ContentRef, required nullable preceding closed receipt, checksum_before, complete ordered actual consumed transitions, unchanged DeviceOutput and application park. The owning actual driver validates original native state and raw command/response custody before source adoption.")?);
    formats.push(schema(content, "reference-device/consumption-relation-v1",
                "crucible.reference.consumption-relation.v1: selected typed relation containing actual original native kernel/owner/window, original accepted InputBatch, native stage/receipt, exact initialized and closed wire bodies, preceding own checksum closure and ACK disposition, measured operational duration, ordered original event body/producer/local ID/native FIFO/index/range/zero/checksum tuples. Every typed object has an explicit dependency row; parent payload/provenance and preceding closure bodies are mandatory original source dependencies. Quantized ancestry is separate from same-time Event causal_parent_ids. Parsing does not mint adoption or coordinator identity.")?);
    formats.push(schema(content, "reference-device/lineage-measurement-v1",
                "crucible.reference.lineage-measurement.v1: closed JSON body with actual native DeviceReceipt, exact typed consumption_relation ContentRef, accepted original InputCustody control receipt, and required nullable previous_publication. Null is permitted only for quantum0. Later records preserve original prior measurement, Stop, ObservationBatch, committed observation and separately authenticated PublicationConsumption body, linking preceding native checksum to complete original public ACK custody. That selected relation must be authenticated against original native Close and accepted public input before observation adoption. Whole source relation body credit614400 and72 roles is reserved before native execution; public window credit is separately finite. Loss or failure retains original unknown source custody.")?);
    formats.push(schema(content, "reference-device/lineage-origin-v1",
        "crucible.reference.lineage-origin.v1: actual original native kernel PID/start, owner/incarnation/generation, explicit lineage-native dialect, exact native executable measurement and accepted Initialize request/Ready wire ContentRefs. The whole source owns the pre-spawn supervision slot, actual initialized driver and private native group. Original kernel census and host installation authentication are mandatory; this data alone grants no readiness or authority.")?);
    Ok(())
}

pub(super) const MODEL_SPECIFICATION: &str = concat!(
    "Source-owned quantized checksum ordered-consumption candidate. Rolling checksum and original ",
    "checksum-N public IDs remain unchanged. Every accepted original InputBatch event index and exact ",
    "payload range including zero-byte entries is staged to the distinct lineage-native.v1 companion. ",
    "Actual native Close retains complete consumed transitions and preceding closed checksum state. ",
    "Original public input/control receipts and native/public output/ACK custody remain with one owner. ",
    "Quantized earlier-input ancestry is a paired source relation; baseline Event.causal_parent_ids ",
    "still means same-time reactions. Source qualification and coordinator identity association are ",
    "independent. Physical preservation and unconditional repeatability are unsupported.",
);

pub(super) const WINDOW_SPECIFICATION: &str = concat!(
    "A positive phase-zero window consumes the exact ordered original accepted InputBatch under an ",
    "immutable native grant. Native stage, relation object/byte/frame credit and complete source ",
    "supervision are reserved before effects. One actual native Close records every event range and ",
    "zero-byte disposition, original predecessor checksum state, unchanged output and separately ",
    "measured elapsed host activation. Public observation references a separately selected source ",
    "measurement codec with an explicit consumption relation dependency. Native publication ACK follows ",
    "authentic public publication consumption, never receipt copying. Transport loss leaves original ",
    "command/source custody unknown. No same-time parent ID is inferred from a coordinate or earlier ",
    "quantized input.",
);

pub(super) const CONFIGURATION_SCHEMA: &str = concat!(
    "reference-device/configuration-public-lineage-v1: closed source-owned quantized checksum ",
    "configuration with original positive canonical quantum_ps/host_budget_ns, phase_ps 0, superdense-v1 ",
    "ordering, raw-byte interface, admitted-causal-source or closed-no-ingress policy, native_dialect ",
    "crucible.reference.lineage-native.v1, native_consumption_schema ",
    "crucible.reference.consumption-relation.v1, maximum_input_events 64, maximum_native_windows 64, ",
    "maximum_native_commands 512, maximum_native_journal_bytes 8388608, relation_reserved_bytes 614400, ",
    "checksum multiplier257 modulo18446744073709551616. Source implementation and all paired codecs ",
    "require distinct installed qualification.",
);
