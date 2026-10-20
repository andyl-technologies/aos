//! Reads the complete spent Capture/InputReactive union without live rights.
//!
//! Each failed/raw/typed owner is independently retained. Source-order framing
//! and actual source metadata ordering are separate and both remain exact.

use super::{
    current_contracts::*, current_fixed::*, current_ordinary::*,
    current_suffix::CurrentAttemptStage17,
};
use crate::{
    ProviderError,
    bodies::{CaptureArguments, ExactRunArguments},
    envelope::Envelope,
    protocol_snapshot::owned11::typed::{Fields, HistoricalType, Ledger, invalid, plain_string},
    reference_packet::{
        connected::PacketConnectedNativeRecord,
        service::{
            complete_restore::PacketNativeRestoredRecord, restored_input_reactive17::*,
            restored_settled_capture::upload::*, restored_settled_capture::*,
            restored_settled_confirmation::*,
        },
    },
    retained_metadata::records::MetadataRecordKind,
};
use serde_json::{Map, Value};
use std::mem::{align_of, size_of};

#[derive(Clone, Copy)]
pub(crate) enum CurrentCaptureStage17 {
    Receiving,
    Raw,
    Typed,
    Failed,
}

pub(crate) struct CurrentCaptureAttempt17 {
    pub(crate) ordinal: u64,
    pub(crate) original: Option<Envelope>,
    pub(crate) body: Option<CurrentOrdinaryBody17>,
    pub(crate) arguments: Option<CaptureArguments>,
    pub(crate) capture: Option<PacketRestoredSettledCaptureArtifact>,
    pub(crate) capture_context: Option<PacketRestoredSettledCaptureContext>,
    pub(crate) upload: Option<PacketRestoredSettledCaptureUploadArtifact>,
    pub(crate) upload_context: Option<PacketRestoredSettledCaptureUploadContext>,
    pub(crate) continuation: Option<PacketRestoredSettledCaptureUploadContinuation>,
    pub(crate) confirmation: Option<PacketRestoredSettledAfterConfirmationRequest>,
    pub(crate) stage: CurrentCaptureStage17,
}
impl HistoricalType for CurrentCaptureAttempt17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        // Full current Capture is immutable evidence in the narrowed decoder.
        // A historical host capsule is never reconstructed from these fields.
        if build {
            return Err(invalid());
        }
        let _ =
            super::current_capture17_borrowed::read_current_capture17_borrowed_data(input, ledger)?;
        Ok(None)
    }
}

pub(crate) struct CurrentInputAttempt17 {
    pub(crate) ordinal: u64,
    pub(crate) original: Option<Envelope>,
    pub(crate) body: Option<CurrentOrdinaryBody17>,
    pub(crate) arguments: Option<ExactRunArguments>,
    pub(crate) artifact: Option<PacketRestoredInputReactive17Artifact>,
    pub(crate) context: Option<PacketRestoredInputReactive17Context>,
    pub(crate) checkpoint: Option<CurrentInputCheckpoint17>,
    pub(crate) terminal: Option<Envelope>,
    pub(crate) prepared_reply: Option<Map<String, Value>>,
    pub(crate) stage: CurrentAttemptStage17,
    pub(crate) observation: Option<CurrentObservationAction17>,
}
impl HistoricalType for CurrentInputAttempt17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let ordinal_raw = fields.named("ordinal")?;
        let original_raw = fields.named("original")?;
        let body_raw = fields.named("body")?;
        let arguments_raw = fields.named("arguments")?;
        let artifact_raw = fields.named("artifact")?;
        let context_raw = fields.named("context")?;
        let checkpoint_raw = fields.named("checkpoint")?;
        let terminal_raw = fields.named("terminal")?;
        let prepared_reply_raw = fields.named("prepared_reply")?;
        let stage_raw = fields.named("stage")?;
        let observation_raw = fields.named("observation")?;
        fields.finish()?;
        let original = ledger.read::<Option<Envelope>>(original_raw, build)?;
        let terminal = ledger.read::<Option<Envelope>>(terminal_raw, build)?;
        let prepared_reply =
            ledger.read::<Option<Map<String, Value>>>(prepared_reply_raw, build)?;
        let body = read_tagged_body17(
            body_raw,
            ledger,
            build,
            &[
                "input",
                "begin",
                "poll",
                "retire",
                "observe",
                "blob_begin",
                "blob_chunk",
                "blob_finish",
            ],
        )?;
        let artifact=<Optional17<CurrentDto17<PacketRestoredInputReactive17Artifact>> as CurrentField17>::read(artifact_raw,ledger,build)?;
        let context=<Optional17<CurrentDto17<PacketRestoredInputReactive17Context>> as CurrentField17>::read(context_raw,ledger,build)?;
        let checkpoint = ledger.read::<Option<CurrentInputCheckpoint17>>(checkpoint_raw, build)?;
        let arguments = <Optional17<CurrentDto17<ExactRunArguments>> as CurrentField17>::read(
            arguments_raw,
            ledger,
            build,
        )?;
        let ordinal = ledger.read::<u64>(ordinal_raw, build)?;
        let stage = inline17::<CurrentAttemptStage17>(stage_raw, build)?;
        let observation =
            ledger.read::<Option<CurrentObservationAction17>>(observation_raw, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            ordinal: ordinal.ok_or_else(invalid)?,
            original: original.ok_or_else(invalid)?,
            body: body.ok_or_else(invalid)?,
            arguments: arguments.ok_or_else(invalid)?,
            artifact: artifact.ok_or_else(invalid)?,
            context: context.ok_or_else(invalid)?,
            checkpoint: checkpoint.ok_or_else(invalid)?,
            terminal: terminal.ok_or_else(invalid)?,
            prepared_reply: prepared_reply.ok_or_else(invalid)?,
            stage: stage.ok_or_else(invalid)?,
            observation: observation.ok_or_else(invalid)?,
        }))
    }
}

fn read_tagged_body17(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    allowed: &[&str],
) -> Result<Option<Option<CurrentOrdinaryBody17>>, ProviderError> {
    if input == b"null" {
        return Ok(build.then_some(None));
    }
    let mut fields = Fields::object(input)?;
    let kind = plain_string(fields.named("kind")?)?;
    if !allowed.contains(&kind) {
        return Err(invalid());
    }
    let raw = fields.named("data")?;
    fields.finish()?;
    read_ordinary17(kind, raw, ledger, build).map(|value| value.map(Some))
}

pub(crate) struct CurrentInputCheckpoint17 {
    pub(crate) restored: Option<PacketNativeRestoredRecord>,
    pub(crate) underlying: Option<Box<PacketConnectedNativeRecord>>,
    pub(crate) expected_lineage: Option<PacketNativeRestoredRecord>,
    pub(crate) previous_artifact: Option<PacketRestoredInputReactive17Artifact>,
    pub(crate) previous_context: Option<PacketRestoredInputReactive17Context>,
    pub(crate) validated: bool,
}
impl HistoricalType for CurrentInputCheckpoint17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let restored =
            <Optional17<CurrentDto17<PacketNativeRestoredRecord>> as CurrentField17>::read(
                fields.named("restored")?,
                ledger,
                build,
            )?;
        let raw = fields.named("underlying")?;
        let underlying = if raw == b"null" {
            Some(None)
        } else {
            let value = <CurrentDto17<PacketConnectedNativeRecord> as CurrentField17>::read(
                raw, ledger, build,
            )?;
            if ledger.row_aligned(
                MetadataRecordKind::Boxed,
                1,
                align_of::<PacketConnectedNativeRecord>(),
            )? != size_of::<PacketConnectedNativeRecord>()
            {
                return Err(invalid());
            }
            ledger.native17_target_box_data::<PacketConnectedNativeRecord>()?;
            value.map(|value| Some(Box::new(value)))
        };
        let expected_lineage =
            <Optional17<CurrentDto17<PacketNativeRestoredRecord>> as CurrentField17>::read(
                fields.named("expected_lineage")?,
                ledger,
                build,
            )?;
        let previous_artifact=<Optional17<CurrentDto17<PacketRestoredInputReactive17Artifact>> as CurrentField17>::read(fields.named("previous_artifact")?,ledger,build)?;
        let previous_context=<Optional17<CurrentDto17<PacketRestoredInputReactive17Context>> as CurrentField17>::read(fields.named("previous_context")?,ledger,build)?;
        let validated = ledger.read::<bool>(fields.named("validated")?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            restored: restored.ok_or_else(invalid)?,
            underlying: underlying.ok_or_else(invalid)?,
            expected_lineage: expected_lineage.ok_or_else(invalid)?,
            previous_artifact: previous_artifact.ok_or_else(invalid)?,
            previous_context: previous_context.ok_or_else(invalid)?,
            validated: validated.ok_or_else(invalid)?,
        }))
    }
}

pub(crate) enum CurrentSelectedAction17 {
    Capture(CurrentCaptureAttempt17),
    InputReactive(CurrentInputAttempt17),
}
impl HistoricalType for CurrentSelectedAction17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let family = plain_string(fields.named("family")?)?;
        let raw = fields.named("data")?;
        fields.finish()?;
        match family {
            "capture" => ledger
                .read::<CurrentCaptureAttempt17>(raw, build)
                .map(|value| value.map(Self::Capture)),
            "capture_upload17" => {
                // The complete source is borrowed below; no operational upload
                // enum payload or dummy owner is constructed by this reader.
                if build {
                    return Err(invalid());
                }
                let _ = super::current_capture17_upload_ingress::read_current_capture17_upload_ingress_data(raw, ledger)?;
                Ok(None)
            }
            "input_reactive" => ledger
                .read::<CurrentInputAttempt17>(raw, build)
                .map(|value| value.map(Self::InputReactive)),
            _ => Err(invalid()),
        }
    }
}

/// Retains the actual raw-first wrapper even if later family decoding failed.
pub(crate) struct HistoricalRestoredAction17 {
    pub(crate) ordinal: u64,
    pub(crate) original: Option<Envelope>,
    pub(crate) selected: Option<CurrentSelectedAction17>,
    pub(crate) decoded: bool,
    pub(crate) failed: bool,
}
impl HistoricalType for HistoricalRestoredAction17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let ordinal_raw = fields.named("ordinal")?;
        let original_raw = fields.named("original")?;
        let selected_raw = fields.named("selected")?;
        let decoded_raw = fields.named("decoded")?;
        let failed_raw = fields.named("failed")?;
        fields.finish()?;
        let ordinal = ledger.read::<u64>(ordinal_raw, build)?;
        let original = ledger.read::<Option<Envelope>>(original_raw, build)?;
        let decoded = ledger.read::<bool>(decoded_raw, build)?;
        let failed = ledger.read::<bool>(failed_raw, build)?;
        let selected = ledger.read::<Option<CurrentSelectedAction17>>(selected_raw, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            ordinal: ordinal.ok_or_else(invalid)?,
            original: original.ok_or_else(invalid)?,
            selected: selected.ok_or_else(invalid)?,
            decoded: decoded.ok_or_else(invalid)?,
            failed: failed.ok_or_else(invalid)?,
        }))
    }
}

#[path = "current_actions/observation17.rs"]
mod observation17;
pub(crate) use observation17::{
    CurrentObservationAction17, CurrentObservationCheckpoint17, CurrentObservationProduction17,
};
