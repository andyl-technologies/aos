//! Reads all current activation, upload and first-observation partials as DATA.
//!
//! The enclosing graph supplies the existing ledger. There is no nested bank,
//! cursor reset, permit reconstruction or omission of failed stage ownership.

use super::current_contracts::*;
use super::current_shared::{CurrentShared17, read_shared17};
use crate::ProviderError;
use crate::bodies::ObserveRequest;
use crate::envelope::{Envelope, Method};
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string, unsigned,
};
use crate::reference_packet::service::ack_emitter::NativeAckBoot;
use crate::reference_packet::service::complete_restore::activation::upload::*;
use crate::reference_packet::service::complete_restore::activation::*;
use crate::reference_packet::service::complete_restore::restoration_observe::*;
use crate::retained_metadata::aliases::MetadataSharedKind;
use crucible_node_format::{ActivationManifest, Id};
use serde_json::Value;

fn role(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) struct CurrentActivation17 {
    pub(crate) creator: u32,
    pub(crate) phase: PacketRestorationActivationPhase,
    pub(crate) original: Option<Envelope>,
    pub(crate) incoming_slot: Option<usize>,
    pub(crate) artifact: Option<PacketRestorationActivationArtifact>,
    pub(crate) context: Option<PacketRestorationActivationContext>,
    pub(crate) coordinator: Option<Value>,
    pub(crate) manifest: Option<ActivationManifest>,
    pub(crate) terminal: Option<Envelope>,
    pub(crate) verified: bool,
    pub(crate) dispatched: bool,
    pub(crate) published: bool,
}

impl HistoricalType for CurrentActivation17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let creator_raw = fields.named("creator")?;
        let thread_raw = fields.named("thread")?;
        let phase_raw = fields.named("phase")?;
        let original_raw = fields.named("original")?;
        let incoming_slot_raw = fields.named("incoming_slot")?;
        let artifact_raw = fields.named("artifact")?;
        let context_raw = fields.named("context")?;
        let coordinator_raw = fields.named("coordinator")?;
        let manifest_raw = fields.named("manifest")?;
        let terminal_raw = fields.named("terminal")?;
        let verified_raw = fields.named("verified")?;
        let dispatched_raw = fields.named("dispatched")?;
        let published_raw = fields.named("published")?;
        fields.finish()?;
        role(
            schema_raw,
            "source-private.native-restoration-activation-history/1",
        )?;
        role(thread_raw, "same-original-thread-history-only")?;
        if unsigned(creator_raw)? == 0 {
            return Err(invalid());
        }

        let creator = <Plain17<u32> as CurrentField17>::read(creator_raw, ledger, build)?;
        let phase = <Inline17<PacketRestorationActivationPhase> as CurrentField17>::read(
            phase_raw, ledger, build,
        )?;
        let original =
            <Plain17<Option<Envelope>> as CurrentField17>::read(original_raw, ledger, build)?;
        let incoming_slot =
            <Plain17<Option<usize>> as CurrentField17>::read(incoming_slot_raw, ledger, build)?;
        let artifact = <Optional17<CurrentDto17<PacketRestorationActivationArtifact>> as CurrentField17>::read(artifact_raw, ledger, build)?;
        let context =
            <Optional17<CurrentDto17<PacketRestorationActivationContext>> as CurrentField17>::read(
                context_raw,
                ledger,
                build,
            )?;
        let coordinator =
            <Plain17<Option<Value>> as CurrentField17>::read(coordinator_raw, ledger, build)?;
        let manifest = <Optional17<CurrentDto17<ActivationManifest>> as CurrentField17>::read(
            manifest_raw,
            ledger,
            build,
        )?;
        let terminal =
            <Plain17<Option<Envelope>> as CurrentField17>::read(terminal_raw, ledger, build)?;
        let verified = <Plain17<bool> as CurrentField17>::read(verified_raw, ledger, build)?;
        let dispatched = <Plain17<bool> as CurrentField17>::read(dispatched_raw, ledger, build)?;
        let published = <Plain17<bool> as CurrentField17>::read(published_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            creator: creator.ok_or_else(invalid)?,
            phase: phase.ok_or_else(invalid)?,
            original: original.ok_or_else(invalid)?,
            incoming_slot: incoming_slot.ok_or_else(invalid)?,
            artifact: artifact.ok_or_else(invalid)?,
            context: context.ok_or_else(invalid)?,
            coordinator: coordinator.ok_or_else(invalid)?,
            manifest: manifest.ok_or_else(invalid)?,
            terminal: terminal.ok_or_else(invalid)?,
            verified: verified.ok_or_else(invalid)?,
            dispatched: dispatched.ok_or_else(invalid)?,
            published: published.ok_or_else(invalid)?,
        }))
    }
}

pub(crate) struct CurrentUpload17 {
    pub(crate) creator: u32,
    pub(crate) ordinal: usize,
    pub(crate) original: Option<Envelope>,
    pub(crate) artifact: Option<PacketRestorationActivationUploadArtifact>,
    pub(crate) context: Option<PacketRestorationActivationUploadContext>,
    pub(crate) pending: Option<Envelope>,
    pub(crate) terminal: Option<Envelope>,
    pub(crate) seen: Vec<Id>,
    pub(crate) bytes: Vec<u8>,
    pub(crate) content_attempted: bool,
    pub(crate) next_offset: usize,
    pub(crate) published_requests: usize,
    pub(crate) verified: bool,
    pub(crate) begun: bool,
    pub(crate) complete: bool,
    pub(crate) next_progress: Option<(usize, bool)>,
}

impl HistoricalType for CurrentUpload17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let creator_raw = fields.named("creator")?;
        let thread_raw = fields.named("thread")?;
        let ordinal_raw = fields.named("ordinal")?;
        let original_raw = fields.named("original")?;
        let artifact_raw = fields.named("artifact")?;
        let context_raw = fields.named("context")?;
        let pending_raw = fields.named("pending")?;
        let terminal_raw = fields.named("terminal")?;
        let seen_raw = fields.named("seen")?;
        let seen_capacity_raw = fields.named("seen_capacity")?;
        let bytes_raw = fields.named("bytes")?;
        let bytes_capacity_raw = fields.named("bytes_capacity")?;
        let content_attempted_raw = fields.named("content_attempted")?;
        let next_offset_raw = fields.named("next_offset")?;
        let published_requests_raw = fields.named("published_requests")?;
        let verified_raw = fields.named("verified")?;
        let begun_raw = fields.named("begun")?;
        let complete_raw = fields.named("complete")?;
        let next_progress_raw = fields.named("next_progress")?;
        fields.finish()?;
        role(
            schema_raw,
            "source-private.native-restoration-upload-history/1",
        )?;
        role(thread_raw, "same-original-thread-history-only")?;
        if unsigned(creator_raw)? == 0 {
            return Err(invalid());
        }

        let creator = <Plain17<u32> as CurrentField17>::read(creator_raw, ledger, build)?;
        let ordinal = <Plain17<usize> as CurrentField17>::read(ordinal_raw, ledger, build)?;
        let original =
            <Plain17<Option<Envelope>> as CurrentField17>::read(original_raw, ledger, build)?;
        let artifact = <Optional17<CurrentDto17<PacketRestorationActivationUploadArtifact>> as CurrentField17>::read(artifact_raw, ledger, build)?;
        let context = <Optional17<CurrentDto17<PacketRestorationActivationUploadContext>> as CurrentField17>::read(context_raw, ledger, build)?;
        let pending =
            <Plain17<Option<Envelope>> as CurrentField17>::read(pending_raw, ledger, build)?;
        let terminal =
            <Plain17<Option<Envelope>> as CurrentField17>::read(terminal_raw, ledger, build)?;
        let seen_capacity = usize::try_from(unsigned(seen_capacity_raw)?).map_err(|_| invalid())?;
        let seen_row = ledger.rows.clone().next().ok_or_else(invalid)??;
        if seen_row.extent != seen_capacity {
            return Err(invalid());
        }
        let seen = <Plain17<Vec<Id>> as CurrentField17>::read(seen_raw, ledger, build)?;
        let bytes_capacity =
            usize::try_from(unsigned(bytes_capacity_raw)?).map_err(|_| invalid())?;
        let bytes = crate::connection::settled17::read_byte_bank_parts17(
            bytes_raw,
            bytes_capacity,
            ledger,
            build,
        )?;
        let content_attempted =
            <Plain17<bool> as CurrentField17>::read(content_attempted_raw, ledger, build)?;
        let next_offset = <Plain17<usize> as CurrentField17>::read(next_offset_raw, ledger, build)?;
        let published_requests =
            <Plain17<usize> as CurrentField17>::read(published_requests_raw, ledger, build)?;
        let verified = <Plain17<bool> as CurrentField17>::read(verified_raw, ledger, build)?;
        let begun = <Plain17<bool> as CurrentField17>::read(begun_raw, ledger, build)?;
        let complete = <Plain17<bool> as CurrentField17>::read(complete_raw, ledger, build)?;
        let next_progress = read_progress17(next_progress_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            creator: creator.ok_or_else(invalid)?,
            ordinal: ordinal.ok_or_else(invalid)?,
            original: original.ok_or_else(invalid)?,
            artifact: artifact.ok_or_else(invalid)?,
            context: context.ok_or_else(invalid)?,
            pending: pending.ok_or_else(invalid)?,
            terminal: terminal.ok_or_else(invalid)?,
            seen: seen.ok_or_else(invalid)?,
            bytes: bytes.ok_or_else(invalid)?,
            content_attempted: content_attempted.ok_or_else(invalid)?,
            next_offset: next_offset.ok_or_else(invalid)?,
            published_requests: published_requests.ok_or_else(invalid)?,
            verified: verified.ok_or_else(invalid)?,
            begun: begun.ok_or_else(invalid)?,
            complete: complete.ok_or_else(invalid)?,
            next_progress: next_progress.ok_or_else(invalid)?,
        }))
    }
}

pub(crate) struct CurrentFirstObservation17 {
    pub(crate) creator: u32,
    pub(crate) original: Option<Envelope>,
    pub(crate) body: Option<ObserveRequest>,
    pub(crate) artifact: Option<PacketRestorationObservationArtifact>,
    pub(crate) context: Option<PacketRestorationObservationContext>,
    pub(crate) terminal: Option<Envelope>,
    pub(crate) received: bool,
    pub(crate) verified: bool,
    pub(crate) dispatched: bool,
    pub(crate) published: bool,
}

impl HistoricalType for CurrentFirstObservation17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let creator_raw = fields.named("creator")?;
        let thread_raw = fields.named("thread")?;
        let original_raw = fields.named("original")?;
        let body_raw = fields.named("body")?;
        let artifact_raw = fields.named("artifact")?;
        let context_raw = fields.named("context")?;
        let terminal_raw = fields.named("terminal")?;
        let received_raw = fields.named("received")?;
        let verified_raw = fields.named("verified")?;
        let dispatched_raw = fields.named("dispatched")?;
        let published_raw = fields.named("published")?;
        fields.finish()?;
        role(
            schema_raw,
            "source-private.native-restoration-observation-history/1",
        )?;
        role(thread_raw, "same-original-thread-history-only")?;
        if unsigned(creator_raw)? == 0 {
            return Err(invalid());
        }

        let creator = <Plain17<u32> as CurrentField17>::read(creator_raw, ledger, build)?;
        let original =
            <Plain17<Option<Envelope>> as CurrentField17>::read(original_raw, ledger, build)?;
        let body = <Optional17<CurrentDto17<ObserveRequest>> as CurrentField17>::read(
            body_raw, ledger, build,
        )?;
        let artifact = <Optional17<CurrentDto17<PacketRestorationObservationArtifact>> as CurrentField17>::read(artifact_raw, ledger, build)?;
        let context = <Optional17<CurrentDto17<PacketRestorationObservationContext>> as CurrentField17>::read(context_raw, ledger, build)?;
        let terminal =
            <Plain17<Option<Envelope>> as CurrentField17>::read(terminal_raw, ledger, build)?;
        let received = <Plain17<bool> as CurrentField17>::read(received_raw, ledger, build)?;
        let verified = <Plain17<bool> as CurrentField17>::read(verified_raw, ledger, build)?;
        let dispatched = <Plain17<bool> as CurrentField17>::read(dispatched_raw, ledger, build)?;
        let published = <Plain17<bool> as CurrentField17>::read(published_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            creator: creator.ok_or_else(invalid)?,
            original: original.ok_or_else(invalid)?,
            body: body.ok_or_else(invalid)?,
            artifact: artifact.ok_or_else(invalid)?,
            context: context.ok_or_else(invalid)?,
            terminal: terminal.ok_or_else(invalid)?,
            received: received.ok_or_else(invalid)?,
            verified: verified.ok_or_else(invalid)?,
            dispatched: dispatched.ok_or_else(invalid)?,
            published: published.ok_or_else(invalid)?,
        }))
    }
}

fn read_progress17(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<Option<(usize, bool)>>, ProviderError> {
    if input == b"null" {
        return Ok(build.then_some(None));
    }
    let mut pair = Fields::array(input)?;
    let offset = ledger.read::<usize>(pair.next()?.ok_or_else(invalid)?, build)?;
    let complete = ledger.read::<bool>(pair.next()?.ok_or_else(invalid)?, build)?;
    pair.finish()?;
    if !build {
        return Ok(None);
    }
    Ok(Some(Some((
        offset.ok_or_else(invalid)?,
        complete.ok_or_else(invalid)?,
    ))))
}

/// Retains each actual shared stage root and its historical aggregate identity.
pub(crate) struct CurrentStages17 {
    pub(crate) activation: [Option<CurrentShared17<CurrentActivation17>>; 2],
    pub(crate) uploads: [Option<CurrentShared17<CurrentUpload17>>; 2],
    pub(crate) first_observation: Option<CurrentShared17<CurrentFirstObservation17>>,
}

impl HistoricalType for CurrentStages17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        role(
            fields.named("schema")?,
            "source-private.native-current-restoration-stages/17",
        )?;
        let activation_raw = fields.named("activation")?;
        let uploads_raw = fields.named("uploads")?;
        let first_raw = fields.named("first_observation")?;
        fields.finish()?;
        let layouts = NativeAckBoot::current_stage_layouts17_data();
        let activation = read_slots17::<CurrentActivation17>(
            activation_raw,
            ledger,
            build,
            MetadataSharedKind::NativeRestorationActivationAttempt,
            layouts[0],
        )?;
        let uploads = read_slots17::<CurrentUpload17>(
            uploads_raw,
            ledger,
            build,
            MetadataSharedKind::NativeRestorationUploadAttempt,
            layouts[1],
        )?;
        let first_observation = if first_raw == b"null" {
            Some(None)
        } else {
            read_shared17::<CurrentFirstObservation17>(
                first_raw,
                ledger,
                build,
                MetadataSharedKind::NativeRestorationObservationAttempt,
                layouts[2],
            )?
            .map(Some)
        };
        if !build {
            return Ok(None);
        }
        let value = Self {
            activation: activation.ok_or_else(invalid)?,
            uploads: uploads.ok_or_else(invalid)?,
            first_observation: first_observation.ok_or_else(invalid)?,
        };
        value.authenticate_data()?;
        Ok(Some(value))
    }
}

fn read_slots17<T: HistoricalType>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    kind: MetadataSharedKind,
    layout: (usize, usize),
) -> Result<Option<[Option<CurrentShared17<T>>; 2]>, ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut output = [None, None];
    for slot in &mut output {
        let raw = fields.next()?.ok_or_else(invalid)?;
        if raw != b"null" {
            *slot = read_shared17::<T>(raw, ledger, build, kind, layout)?;
        }
    }
    fields.finish()?;
    Ok(build.then_some(output))
}

impl CurrentStages17 {
    /// Checks intrinsic stage ordering while preserving unfinished owner fields.
    pub(crate) fn authenticate_data(&self) -> Result<(), ProviderError> {
        for (ordinal, stage) in self.activation.iter().enumerate() {
            let Some(stage) = stage else {
                continue;
            };
            let stage = &stage.payload;
            let phase = if ordinal == 0 {
                PacketRestorationActivationPhase::Arm
            } else {
                PacketRestorationActivationPhase::WorldActivate
            };
            if stage.phase != phase
                || stage.dispatched && !stage.verified
                || stage.published
                    && (!stage.dispatched || stage.artifact.is_none() || stage.context.is_none())
            {
                return Err(invalid());
            }
            pair17(
                &stage.original,
                &stage.terminal,
                stage.published,
                phase.method(),
            )?;
        }
        for (ordinal, stage) in self.uploads.iter().enumerate() {
            let Some(stage) = stage else {
                continue;
            };
            let stage = &stage.payload;
            if stage.ordinal != ordinal
                || stage.next_offset > stage.bytes.len()
                || stage.published_requests > stage.seen.len()
                || stage.seen.len() > 4096
                || stage.begun && !stage.verified
                || stage.complete
                    && (!stage.verified
                        || !stage.begun
                        || stage.content_attempted
                        || stage.pending.is_some()
                        || stage.next_progress.is_some()
                        || stage.artifact.is_none()
                        || stage.context.is_none()
                        || stage.terminal.is_none())
            {
                return Err(invalid());
            }
            for (index, id) in stage.seen.iter().enumerate() {
                if stage.seen[..index].contains(id) {
                    return Err(invalid());
                }
            }
            if stage
                .original
                .as_ref()
                .is_some_and(|original| original.method != Method::BlobBegin)
            {
                return Err(invalid());
            }
        }
        if let Some(stage) = &self.first_observation {
            let stage = &stage.payload;
            if stage.verified && !stage.received
                || stage.dispatched && !stage.verified
                || stage.published
                    && (!stage.dispatched || stage.artifact.is_none() || stage.context.is_none())
            {
                return Err(invalid());
            }
            pair17(
                &stage.original,
                &stage.terminal,
                stage.published,
                Method::Observe,
            )?;
        }
        Ok(())
    }
}

fn pair17(
    original: &Option<Envelope>,
    terminal: &Option<Envelope>,
    published: bool,
    method: Method,
) -> Result<(), ProviderError> {
    if original
        .as_ref()
        .is_some_and(|original| original.method != method)
    {
        return Err(invalid());
    }
    if published {
        original
            .as_ref()
            .ok_or_else(invalid)?
            .matches_response(terminal.as_ref().ok_or_else(invalid)?)?;
    }
    Ok(())
}
