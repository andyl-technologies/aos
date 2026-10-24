//! Reads exact retained Observe17 partials without constructing live owners.
//!
//! The eleventh Input/Reactive field uses this closed internal object grammar:
//!
//! ```json
//! {"checkpoint":null,"production":null,"publication_record":null}
//! ```
//!
//! Actual completed, failed and partial banks retain independent capacities.
//! Parsed booleans and record indices never create live native completion.

use super::*;
use crate::reference_packet::control::PacketNative5Record;

/// Retains the exact inert fields of the defining ObservationAction17 owner.
pub(crate) struct CurrentObservationAction17 {
    pub(crate) checkpoint: Option<CurrentObservationCheckpoint17>,
    pub(crate) production: Option<CurrentObservationProduction17>,
    pub(crate) publication_record: Option<usize>,
}

impl HistoricalType for CurrentObservationAction17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let checkpoint_raw = fields.named("checkpoint")?;
        let production_raw = fields.named("production")?;
        let publication_record_raw = fields.named("publication_record")?;
        fields.finish()?;

        let checkpoint =
            ledger.read::<Option<CurrentObservationCheckpoint17>>(checkpoint_raw, build)?;
        let production =
            ledger.read::<Option<CurrentObservationProduction17>>(production_raw, build)?;
        let publication_record = ledger.read::<Option<usize>>(publication_record_raw, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            checkpoint: checkpoint.ok_or_else(invalid)?,
            production: production.ok_or_else(invalid)?,
            publication_record: publication_record.ok_or_else(invalid)?,
        }))
    }
}

/// Retains the exact inert fields of the defining ObservationCheckpoint17 owner.
pub(crate) struct CurrentObservationCheckpoint17 {
    pub(crate) model_bytes: Vec<u8>,
    pub(crate) receipt: Option<PacketNative5Record>,
    pub(crate) restored: Option<PacketNativeRestoredRecord>,
    pub(crate) restored_bytes: Vec<u8>,
    pub(crate) validated: bool,
}

impl HistoricalType for CurrentObservationCheckpoint17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let model_bytes_raw = fields.named("model_bytes")?;
        let receipt_raw = fields.named("receipt")?;
        let restored_raw = fields.named("restored")?;
        let restored_bytes_raw = fields.named("restored_bytes")?;
        let validated_raw = fields.named("validated")?;
        fields.finish()?;

        let model_bytes = ledger.read::<Vec<u8>>(model_bytes_raw, build)?;
        let receipt = <Optional17<CurrentDto17<PacketNative5Record>> as CurrentField17>::read(
            receipt_raw,
            ledger,
            build,
        )?;
        let restored =
            <Optional17<CurrentDto17<PacketNativeRestoredRecord>> as CurrentField17>::read(
                restored_raw,
                ledger,
                build,
            )?;
        let restored_bytes = ledger.read::<Vec<u8>>(restored_bytes_raw, build)?;
        let validated = ledger.read::<bool>(validated_raw, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            model_bytes: model_bytes.ok_or_else(invalid)?,
            receipt: receipt.ok_or_else(invalid)?,
            restored: restored.ok_or_else(invalid)?,
            restored_bytes: restored_bytes.ok_or_else(invalid)?,
            validated: validated.ok_or_else(invalid)?,
        }))
    }
}

/// Retains the exact inert fields of the defining ObservationProduction17 owner.
pub(crate) struct CurrentObservationProduction17 {
    pub(crate) model_bytes: Vec<u8>,
    pub(crate) model_reference: Option<crucible_node_format::ContentRef>,
    pub(crate) receipt: Option<PacketNative5Record>,
    pub(crate) restored: Option<PacketNativeRestoredRecord>,
    pub(crate) restored_bytes: Vec<u8>,
    pub(crate) restored_reference: Option<crucible_node_format::ContentRef>,
    pub(crate) body: Option<Map<String, Value>>,
    pub(crate) evidence: Vec<(crucible_node_format::ContentRef, Vec<u8>)>,
    pub(crate) started: bool,
    pub(crate) complete: bool,
}

impl HistoricalType for CurrentObservationProduction17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let model_bytes_raw = fields.named("model_bytes")?;
        let model_reference_raw = fields.named("model_reference")?;
        let receipt_raw = fields.named("receipt")?;
        let restored_raw = fields.named("restored")?;
        let restored_bytes_raw = fields.named("restored_bytes")?;
        let restored_reference_raw = fields.named("restored_reference")?;
        let body_raw = fields.named("body")?;
        let evidence_raw = fields.named("evidence")?;
        let started_raw = fields.named("started")?;
        let complete_raw = fields.named("complete")?;
        fields.finish()?;

        let model_bytes = ledger.read::<Vec<u8>>(model_bytes_raw, build)?;
        let model_reference =
            ledger.read::<Option<crucible_node_format::ContentRef>>(model_reference_raw, build)?;
        let receipt = <Optional17<CurrentDto17<PacketNative5Record>> as CurrentField17>::read(
            receipt_raw,
            ledger,
            build,
        )?;
        let restored =
            <Optional17<CurrentDto17<PacketNativeRestoredRecord>> as CurrentField17>::read(
                restored_raw,
                ledger,
                build,
            )?;
        let restored_bytes = ledger.read::<Vec<u8>>(restored_bytes_raw, build)?;
        let restored_reference = ledger
            .read::<Option<crucible_node_format::ContentRef>>(restored_reference_raw, build)?;
        let body = ledger.read::<Option<Map<String, Value>>>(body_raw, build)?;
        let evidence =
            ledger.read::<Vec<(crucible_node_format::ContentRef, Vec<u8>)>>(evidence_raw, build)?;
        let started = ledger.read::<bool>(started_raw, build)?;
        let complete = ledger.read::<bool>(complete_raw, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            model_bytes: model_bytes.ok_or_else(invalid)?,
            model_reference: model_reference.ok_or_else(invalid)?,
            receipt: receipt.ok_or_else(invalid)?,
            restored: restored.ok_or_else(invalid)?,
            restored_bytes: restored_bytes.ok_or_else(invalid)?,
            restored_reference: restored_reference.ok_or_else(invalid)?,
            body: body.ok_or_else(invalid)?,
            evidence: evidence.ok_or_else(invalid)?,
            started: started.ok_or_else(invalid)?,
            complete: complete.ok_or_else(invalid)?,
        }))
    }
}
