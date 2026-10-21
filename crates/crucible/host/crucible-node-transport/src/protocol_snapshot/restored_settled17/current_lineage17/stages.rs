//! Borrows signed stage fields during the original full alias/capacity walk.

use super::*;
use crate::reference_packet::service::complete_restore::{
    activation::{upload::*, *},
    restoration_observe::*,
};

pub(crate) struct BorrowedActivationLineage17<'body, 'rows> {
    pub(crate) owner:
        BorrowedLineageField17<'body, 'rows, super::super::current_stages::CurrentActivation17>,
    pub(crate) group: usize,
    pub(crate) definition: &'body [u8],
    pub(crate) creator: u32,
    pub(crate) phase: PacketRestorationActivationPhase,
    pub(crate) original: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) incoming_slot: Option<usize>,
    pub(crate) artifact: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketRestorationActivationArtifact>>,
    >,
    pub(crate) context: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketRestorationActivationContext>>,
    >,
    pub(crate) coordinator: BorrowedLineageField17<'body, 'rows, Option<Value>>,
    pub(crate) manifest: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<crucible_node_format::ActivationManifest>>,
    >,
    pub(crate) terminal: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) verified: bool,
    pub(crate) dispatched: bool,
    pub(crate) published: bool,
}

pub(crate) struct BorrowedUploadLineage17<'body, 'rows> {
    pub(crate) group: usize,
    pub(crate) definition: &'body [u8],
    pub(crate) creator: u32,
    pub(crate) ordinal: usize,
    pub(crate) original: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) artifact: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketRestorationActivationUploadArtifact>>,
    >,
    pub(crate) context: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketRestorationActivationUploadContext>>,
    >,
    pub(crate) pending: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) terminal: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) seen: &'body [u8],
    pub(crate) bytes: &'body [u8],
    pub(crate) content_attempted: bool,
    pub(crate) next_offset: usize,
    pub(crate) published_requests: usize,
    pub(crate) verified: bool,
    pub(crate) begun: bool,
    pub(crate) complete: bool,
    pub(crate) next_progress: Option<(usize, bool)>,
}

pub(crate) struct BorrowedObservationLineage17<'body, 'rows> {
    pub(crate) owner: BorrowedLineageField17<
        'body,
        'rows,
        super::super::current_stages::CurrentFirstObservation17,
    >,
    pub(crate) group: usize,
    pub(crate) definition: &'body [u8],
    pub(crate) creator: u32,
    pub(crate) original: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) body:
        BorrowedLineageField17<'body, 'rows, Option<CurrentDto17<crate::bodies::ObserveRequest>>>,
    pub(crate) artifact: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketRestorationObservationArtifact>>,
    >,
    pub(crate) context: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketRestorationObservationContext>>,
    >,
    pub(crate) terminal: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) received: bool,
    pub(crate) verified: bool,
    pub(crate) dispatched: bool,
    pub(crate) published: bool,
}

pub(crate) struct BorrowedStagesLineage17<'body, 'rows> {
    pub(crate) activation: [Option<BorrowedActivationLineage17<'body, 'rows>>; 2],
    pub(crate) uploads: [Option<BorrowedUploadLineage17<'body, 'rows>>; 2],
    pub(crate) first_observation: Option<BorrowedObservationLineage17<'body, 'rows>>,
}

fn activation<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<Option<BorrowedActivationLineage17<'body, 'rows>>, ProviderError> {
    if input == b"null" {
        return Ok(None);
    }
    let start = ledger.rows.encoded_position();
    let layout = NativeAckBoot::current_stage_layouts17_data()[0];
    shared_row17(ledger, layout)?;
    let group = ledger.shared_begin(MetadataSharedKind::NativeRestorationActivationAttempt)?;
    let owner_rows = ledger.rows.clone();
    let mut f = Fields::object(input)?;
    role(
        f.named("schema")?,
        "source-private.native-restoration-activation-history/1",
    )?;
    let creator = scalar::<u32>(f.named("creator")?, ledger)?;
    if creator == 0 {
        return Err(invalid());
    }
    role(f.named("thread")?, "same-original-thread-history-only")?;
    let phase = match plain_string(f.named("phase")?)? {
        "arm" => PacketRestorationActivationPhase::Arm,
        "world_activate" => PacketRestorationActivationPhase::WorldActivate,
        _ => return Err(invalid()),
    };
    let original = loan(f.named("original")?, ledger)?;
    let incoming_slot = scalar::<Option<usize>>(f.named("incoming_slot")?, ledger)?;
    let artifact = loan(f.named("artifact")?, ledger)?;
    let context = loan(f.named("context")?, ledger)?;
    let coordinator = loan(f.named("coordinator")?, ledger)?;
    let manifest = loan(f.named("manifest")?, ledger)?;
    let terminal = loan(f.named("terminal")?, ledger)?;
    let verified = scalar::<bool>(f.named("verified")?, ledger)?;
    let dispatched = scalar::<bool>(f.named("dispatched")?, ledger)?;
    let published = scalar::<bool>(f.named("published")?, ledger)?;
    f.finish()?;
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout.0, input, rows)?;
    Ok(Some(BorrowedActivationLineage17 {
        owner: BorrowedLineageField17 {
            raw: input,
            rows: owner_rows,
            end: ledger.rows.encoded_position(),
            field_type: PhantomData,
        },
        group,
        definition: input,
        creator,
        phase,
        original,
        incoming_slot,
        artifact,
        context,
        coordinator,
        manifest,
        terminal,
        verified,
        dispatched,
        published,
    }))
}

fn upload<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<Option<BorrowedUploadLineage17<'body, 'rows>>, ProviderError> {
    if input == b"null" {
        return Ok(None);
    }
    let start = ledger.rows.encoded_position();
    let layout = NativeAckBoot::current_stage_layouts17_data()[1];
    shared_row17(ledger, layout)?;
    let group = ledger.shared_begin(MetadataSharedKind::NativeRestorationUploadAttempt)?;
    let mut f = Fields::object(input)?;
    role(
        f.named("schema")?,
        "source-private.native-restoration-upload-history/1",
    )?;
    let creator = scalar::<u32>(f.named("creator")?, ledger)?;
    if creator == 0 {
        return Err(invalid());
    }
    role(f.named("thread")?, "same-original-thread-history-only")?;
    let ordinal = scalar::<usize>(f.named("ordinal")?, ledger)?;
    let original = loan(f.named("original")?, ledger)?;
    let artifact = loan(f.named("artifact")?, ledger)?;
    let context = loan(f.named("context")?, ledger)?;
    let pending = loan(f.named("pending")?, ledger)?;
    let terminal = loan(f.named("terminal")?, ledger)?;
    let seen = f.named("seen")?;
    let capacity = usize::try_from(unsigned(f.named("seen_capacity")?)?).map_err(|_| invalid())?;
    if ledger.rows.clone().next().ok_or_else(invalid)??.extent != capacity {
        return Err(invalid());
    }
    discard::<Vec<Id>>(seen, ledger)?;
    let bytes = f.named("bytes")?;
    let capacity = usize::try_from(unsigned(f.named("bytes_capacity")?)?).map_err(|_| invalid())?;
    if crate::connection::settled17::read_byte_bank_parts17(bytes, capacity, ledger, false)?
        .is_some()
    {
        return Err(invalid());
    }
    let content_attempted = scalar::<bool>(f.named("content_attempted")?, ledger)?;
    let next_offset = scalar::<usize>(f.named("next_offset")?, ledger)?;
    let published_requests = scalar::<usize>(f.named("published_requests")?, ledger)?;
    let verified = scalar::<bool>(f.named("verified")?, ledger)?;
    let begun = scalar::<bool>(f.named("begun")?, ledger)?;
    let complete = scalar::<bool>(f.named("complete")?, ledger)?;
    let raw = f.named("next_progress")?;
    let next_progress = if raw == b"null" {
        None
    } else {
        let mut pair = Fields::array(raw)?;
        let offset = scalar::<usize>(pair.next_value()?.ok_or_else(invalid)?, ledger)?;
        let complete = scalar::<bool>(pair.next_value()?.ok_or_else(invalid)?, ledger)?;
        pair.finish()?;
        Some((offset, complete))
    };
    f.finish()?;
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout.0, input, rows)?;
    Ok(Some(BorrowedUploadLineage17 {
        group,
        definition: input,
        creator,
        ordinal,
        original,
        artifact,
        context,
        pending,
        terminal,
        seen,
        bytes,
        content_attempted,
        next_offset,
        published_requests,
        verified,
        begun,
        complete,
        next_progress,
    }))
}

fn observation<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<Option<BorrowedObservationLineage17<'body, 'rows>>, ProviderError> {
    if input == b"null" {
        return Ok(None);
    }
    let start = ledger.rows.encoded_position();
    let layout = NativeAckBoot::current_stage_layouts17_data()[2];
    shared_row17(ledger, layout)?;
    let group = ledger.shared_begin(MetadataSharedKind::NativeRestorationObservationAttempt)?;
    let owner_rows = ledger.rows.clone();
    let mut f = Fields::object(input)?;
    role(
        f.named("schema")?,
        "source-private.native-restoration-observation-history/1",
    )?;
    let creator = scalar::<u32>(f.named("creator")?, ledger)?;
    if creator == 0 {
        return Err(invalid());
    }
    role(f.named("thread")?, "same-original-thread-history-only")?;
    let original = loan(f.named("original")?, ledger)?;
    let body = loan(f.named("body")?, ledger)?;
    let artifact = loan(f.named("artifact")?, ledger)?;
    let context = loan(f.named("context")?, ledger)?;
    let terminal = loan(f.named("terminal")?, ledger)?;
    let received = scalar::<bool>(f.named("received")?, ledger)?;
    let verified = scalar::<bool>(f.named("verified")?, ledger)?;
    let dispatched = scalar::<bool>(f.named("dispatched")?, ledger)?;
    let published = scalar::<bool>(f.named("published")?, ledger)?;
    f.finish()?;
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout.0, input, rows)?;
    Ok(Some(BorrowedObservationLineage17 {
        owner: BorrowedLineageField17 {
            raw: input,
            rows: owner_rows,
            end: ledger.rows.encoded_position(),
            field_type: PhantomData,
        },
        group,
        definition: input,
        creator,
        original,
        body,
        artifact,
        context,
        terminal,
        received,
        verified,
        dispatched,
        published,
    }))
}

pub(super) fn read<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<BorrowedStagesLineage17<'body, 'rows>, ProviderError> {
    let mut f = Fields::object(input)?;
    role(
        f.named("schema")?,
        "source-private.native-current-restoration-stages/17",
    )?;
    let mut slots = Fields::array(f.named("activation")?)?;
    let activation = [
        activation(slots.next_value()?.ok_or_else(invalid)?, ledger)?,
        activation(slots.next_value()?.ok_or_else(invalid)?, ledger)?,
    ];
    slots.finish()?;
    let mut slots = Fields::array(f.named("uploads")?)?;
    let uploads = [
        upload(slots.next_value()?.ok_or_else(invalid)?, ledger)?,
        upload(slots.next_value()?.ok_or_else(invalid)?, ledger)?,
    ];
    slots.finish()?;
    let first_observation = observation(f.named("first_observation")?, ledger)?;
    f.finish()?;
    for (index, stage) in activation.iter().enumerate() {
        if let Some(stage) = stage {
            let expected = if index == 0 {
                PacketRestorationActivationPhase::Arm
            } else {
                PacketRestorationActivationPhase::WorldActivate
            };
            if stage.phase != expected
                || stage.dispatched && !stage.verified
                || stage.published && !stage.dispatched
            {
                return Err(invalid());
            }
        }
    }
    for (index, stage) in uploads.iter().enumerate() {
        if let Some(stage) = stage
            && (stage.ordinal != index
                || stage.complete && !stage.begun
                || stage.begun && !stage.verified)
        {
            return Err(invalid());
        }
    }
    if let Some(stage) = &first_observation
        && (stage.verified && !stage.received
            || stage.dispatched && !stage.verified
            || stage.published && !stage.dispatched)
    {
        return Err(invalid());
    }
    Ok(BorrowedStagesLineage17 {
        activation,
        uploads,
        first_observation,
    })
}
