//! Reads every actual native Connection child in its emitted schema-first order.

use super::children::{
    HistoricalAssignedResponse17, HistoricalCompleteInstallation17, HistoricalInstalledInputs17,
};
use super::tokens::HistoricalAckToken17;
use super::*;
use crate::protocol_snapshot::owned11::{
    native::blob::HistoricalNativeBlobLedger, reader::HistoricalFrameReaderFacts,
    state::HistoricalCorrelations,
};
use crate::reference_packet::service::{HistoricalNativePolicy17, read_native17_policy_root_data};

/// Identifies exact original shared groups without reviving any original owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeConnection17GroupIds {
    pub(crate) actor: usize,
    pub(crate) supervisor: usize,
    pub(crate) codec: usize,
    pub(crate) policy: usize,
    pub(crate) frames: usize,
    pub(crate) blobs: Option<usize>,
    pub(crate) deadline: usize,
}

/// Retains the entire current native Connection as inert typed DATA.
pub(crate) struct HistoricalCurrentNativeConnection17 {
    pub(crate) authority: HistoricalAuthority17,
    pub(crate) correlations: HistoricalCorrelations,
    pub(crate) policy: HistoricalNativePolicy17,
    pub(crate) blobs: Option<HistoricalNativeBlobLedger>,
    pub(crate) blob_historical_payload_bytes: usize,
    pub(crate) restore_inputs: Option<HistoricalInstalledInputs17>,
    pub(crate) restore_responses: [Option<HistoricalAssignedResponse17>; 2],
    pub(crate) complete_restoration: Option<HistoricalCompleteInstallation17>,
    pub(crate) canonical_ack_admission: Option<HistoricalAckToken17>,
    pub(crate) frames: HistoricalNativeFrameRoot17,
    pub(crate) reader: HistoricalFrameReaderFacts,
    pub(crate) packet_schema: bool,
    pub(crate) connected_packet_schema: bool,
    pub(crate) fenced: bool,
    groups: NativeConnection17GroupIds,
}

impl HistoricalCurrentNativeConnection17 {
    /// Returns checked archive-local groups for the complete enclosing graph.
    pub(crate) const fn group_ids_data(&self) -> NativeConnection17GroupIds {
        self.groups
    }

    /// Checks all typed retained child registrations against this same Connection.
    ///
    /// # Errors
    /// Refuses different actor/frame/policy groups or complete registration DATA.
    pub(crate) fn authenticate_child_groups_data(&self) -> Result<(), ProviderError> {
        let groups = self.groups;
        self.policy.authenticate_correspondence_data()?;
        if self.correlations.session != self.authority.data.session
            || self.correlations.incarnation != self.authority.data.incarnation
        {
            return Err(invalid());
        }
        if let Some(slot) = self.reader.last_original_slot
            && self.frames.frames.frame(slot).is_none()
        {
            return Err(invalid());
        }
        if let Some(token) = &self.canonical_ack_admission {
            token.identity.authenticate_frames_data(&self.frames)?;
            let original_frame = self
                .frames
                .frames
                .frame(token.identity.literal_index)
                .ok_or_else(invalid)?;
            crate::protocol_snapshot::owned11::correspondence::envelope(
                &token.original,
                original_frame.bytes.get(4..).ok_or_else(invalid)?,
            )?;
            if token.original.request_id.0.as_ref() != Some(&token.identity.admit_id)
                || token.original.sequence != token.identity.admit_sequence
            {
                return Err(invalid());
            }
            let (actor, frames, _, policy) = token.group_ids_data();
            if (actor, frames, policy) != (groups.actor, groups.frames, groups.policy)
                || !token.authority.same_registration_data(&self.authority)
            {
                return Err(invalid());
            }
        }
        if let Some(inputs) = &self.restore_inputs {
            inputs
                .token
                .identity
                .authenticate_frames_data(&self.frames)?;
            let (actor, frames, _, policy, _) = inputs.token.group_ids_data();
            if (actor, frames, policy) != (groups.actor, groups.frames, groups.policy)
                || !inputs
                    .token
                    .authority
                    .same_registration_data(&self.authority)
            {
                return Err(invalid());
            }
        }
        if let Some(installed) = &self.complete_restoration {
            installed
                .token
                .identity
                .authenticate_frames_data(&self.frames)?;
            let (actor, frames, _, policy, _) = installed.token.group_ids_data();
            if (actor, frames, policy) != (groups.actor, groups.frames, groups.policy)
                || !installed
                    .token
                    .authority
                    .same_registration_data(&self.authority)
            {
                return Err(invalid());
            }
        }
        for response in self.restore_responses.iter().flatten() {
            response.authenticate_frames_data(&self.frames)?;
            if let Some(proof) = &response.completed_proof
                && (proof.actor_group, proof.frames_group) != (groups.actor, groups.frames)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

/// Reads the complete emitted-order native component, never a Host canonical DOM.
///
/// # Errors
/// Refuses malformed complete children, metadata/alias mismatch or backing limits.
pub(crate) fn read_native17_connection_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalCurrentNativeConnection17>, ProviderError> {
    read_native17_connection_fields_data(input, ledger, build).map(|fields| fields.0)
}

/// Returns complete same-pass group IDs even in the allocation-free pass.
///
/// # Errors
/// Refuses another edition/order/role, any invalid typed child or metadata extent.
pub(crate) fn read_native17_connection_fields_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<
    (
        Option<HistoricalCurrentNativeConnection17>,
        NativeConnection17GroupIds,
    ),
    ProviderError,
> {
    read_connection_fields(input, None, ledger, build)
}

/// Reads only the rooted variant using spans sealed by the whole-graph grammar.
///
/// # Errors
/// Refuses another edition/role, malformed substituted children or mismatched
/// source metadata/alias rows. Sealed spans supply data, never child validity.
pub(crate) fn read_rooted_native17_connection_fields_data(
    roots: &crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17RootSpans<'_>,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<
    (
        Option<HistoricalCurrentNativeConnection17>,
        NativeConnection17GroupIds,
    ),
    ProviderError,
> {
    read_connection_fields(roots.connection_data(), Some(roots), ledger, build)
}

fn read_connection_header(input: &[u8], rooted: bool) -> Result<Fields<'_>, ProviderError> {
    let mut fields = Fields::object(input)?;
    exact(
        fields.named("schema")?,
        if rooted {
            "source-private.native-rooted-connection/17"
        } else {
            "source-private.connection-restored-settled/17"
        },
    )?;
    Ok(fields)
}

fn read_connection_fields(
    input: &[u8],
    roots: Option<
        &crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17RootSpans<'_>,
    >,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<
    (
        Option<HistoricalCurrentNativeConnection17>,
        NativeConnection17GroupIds,
    ),
    ProviderError,
> {
    let mut fields = read_connection_header(input, roots.is_some())?;
    let authority =
        crate::handshake::read_settled17_authority_data(fields.named("authority")?, ledger, build)?;
    read_connection_after_authority(fields, authority, roots, ledger, build)
}

fn read_connection_after_authority(
    mut fields: Fields<'_>,
    authority: Option<HistoricalAuthority17>,
    roots: Option<
        &crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17RootSpans<'_>,
    >,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<
    (
        Option<HistoricalCurrentNativeConnection17>,
        NativeConnection17GroupIds,
    ),
    ProviderError,
> {
    let correlations =
        ledger.read::<HistoricalCorrelations>(fields.named("correlations")?, build)?;
    let actor = reference::<crate::protocol_snapshot::ProtocolCaptureOwner>(
        ledger,
        MetadataSharedKind::ProtocolOwner,
    )?;
    let supervisor_layout = crate::reference_packet::service::original_native_supervisor_layout();
    let supervisor_alignment =
        crate::reference_packet::service::original_native_supervisor_alignment17_data();
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, supervisor_alignment)? != supervisor_layout
    {
        return Err(invalid());
    }
    let supervisor =
        ledger.shared_reference(MetadataSharedKind::NativeSupervisor, supervisor_layout)?;
    let emitted_codec = fields.named("codec")?;
    let raw_codec = if let Some(roots) = roots {
        exact(emitted_codec, "native-connection-codec")?;
        roots.codec_data()
    } else {
        emitted_codec
    };
    let (policy, codec, policy_group) = read_native17_codec_root_data(raw_codec, ledger, build)?;
    // The typed codec and erased verifier are two genuine views of one owner.
    // Revalidate their complete fields/rows, then reuse only the completed first.
    let pause = ledger.suspend_native17_targets_data()?;
    let repeated_codec = read_native17_codec_root_data(raw_codec, ledger, false);
    ledger.resume_native17_targets_data(pause)?;
    let (_, second_codec, second_policy) = repeated_codec?;
    if (codec, policy_group) != (second_codec, second_policy) {
        return Err(invalid());
    }
    let emitted_blobs = fields.named("blobs")?;
    let raw_blobs = if let Some(roots) = roots {
        if emitted_blobs == b"null" {
            emitted_blobs
        } else {
            exact(emitted_blobs, "native-blob-ledger")?;
            receiver_ledger_span(roots.receiver_data())?
        }
    } else {
        emitted_blobs
    };
    let (blobs, blob_group, blob_historical_payload_bytes) = read_blobs(raw_blobs, ledger, build)?;
    let restore_inputs = ledger
        .read::<Option<HistoricalInstalledInputs17>>(fields.named("restore_inputs")?, build)?;
    let mut responses = Fields::array(fields.named("restore_responses")?)?;
    let mut restore_responses = [None, None];
    let mut response_deadlines = [None, None];
    for (response, response_deadline) in restore_responses.iter_mut().zip(&mut response_deadlines) {
        let raw = next(&mut responses)?;
        if raw != b"null" {
            let (value, deadline) = super::children::read_response_fields_data(raw, ledger, build)?;
            *response = value;
            *response_deadline = Some(deadline);
        }
    }
    responses.finish()?;
    let complete_restoration = ledger.read::<Option<HistoricalCompleteInstallation17>>(
        fields.named("complete_restoration")?,
        build,
    )?;
    let canonical_ack_admission = ledger
        .read::<Option<HistoricalAckToken17>>(fields.named("canonical_ack_admission")?, build)?;
    let emitted_frames = fields.named("frames")?;
    let raw_frames = if let Some(roots) = roots {
        exact(emitted_frames, "native-connection-frames")?;
        roots.frames_data()
    } else {
        emitted_frames
    };
    let (frames, frames_group) = read_native17_frame_root_data(raw_frames, ledger, build)?;
    let stream_deadline = deadline(ledger)?;
    if response_deadlines
        .into_iter()
        .flatten()
        .any(|deadline| deadline != stream_deadline)
    {
        return Err(invalid());
    }
    let reader = ledger.read::<HistoricalFrameReaderFacts>(fields.named("reader")?, build)?;
    let pause = ledger.suspend_native17_targets_data()?;
    let repeated_frames = read_native17_frame_root_data(raw_frames, ledger, false);
    ledger.resume_native17_targets_data(pause)?;
    let (_, reader_frames_group) = repeated_frames?;
    if frames_group != reader_frames_group {
        return Err(invalid());
    }
    let packet_schema = ledger.read::<bool>(fields.named("packet_schema")?, build)?;
    let connected_packet_schema =
        ledger.read::<bool>(fields.named("connected_packet_schema")?, build)?;
    let fenced = ledger.read::<bool>(fields.named("fenced")?, build)?;
    exact(fields.named("role")?, "provider")?;
    exact(
        fields.named("protocol_owner_role")?,
        "same-current-connection-actor",
    )?;
    exact(
        fields.named("supervisor_role")?,
        "actual-native-service-supervisor",
    )?;
    fields.finish()?;
    let groups = NativeConnection17GroupIds {
        actor,
        supervisor,
        codec,
        policy: policy_group,
        frames: frames_group,
        blobs: blob_group,
        deadline: stream_deadline,
    };
    if !build {
        return Ok((None, groups));
    }
    let data = HistoricalCurrentNativeConnection17 {
        authority: authority.ok_or_else(invalid)?,
        correlations: correlations.ok_or_else(invalid)?,
        policy: policy.ok_or_else(invalid)?,
        blobs,
        blob_historical_payload_bytes,
        restore_inputs: restore_inputs.ok_or_else(invalid)?,
        restore_responses,
        complete_restoration: complete_restoration.ok_or_else(invalid)?,
        canonical_ack_admission: canonical_ack_admission.ok_or_else(invalid)?,
        frames: frames.ok_or_else(invalid)?,
        reader: reader.ok_or_else(invalid)?,
        packet_schema: packet_schema.ok_or_else(invalid)?,
        connected_packet_schema: connected_packet_schema.ok_or_else(invalid)?,
        fenced: fenced.ok_or_else(invalid)?,
        groups,
    };
    // The caller retains this DATA before its enclosing Boot/mapping/current
    // correspondence fence; this reader performs no live-install conversion.
    Ok((Some(data), groups))
}

/// Reads the complete defining codec and nested native Policy root.
///
/// # Errors
/// Refuses incomplete payloads, changed rows/aliases or non-native codec kind.
pub(crate) fn read_native17_codec_root_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<HistoricalNativePolicy17>, usize, usize), ProviderError> {
    let start = ledger.rows.encoded_position();
    let layout = size_of::<Native5CodecOwner>();
    if ledger.row_aligned(
        MetadataRecordKind::Shared,
        1,
        align_of::<Native5CodecOwner>(),
    )? != layout
    {
        return Err(invalid());
    }
    let group = ledger.shared_begin(MetadataSharedKind::Codec)?;
    let mut fields = Fields::object(input)?;
    exact(
        fields.named("schema")?,
        "source-private.native5-codec-restored-settled/17",
    )?;
    exact(fields.named("kind")?, "native")?;
    let (policy, policy_group) =
        read_native17_policy_root_data(fields.named("data")?, ledger, build)?;
    fields.finish()?;
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout, input, rows)?;
    Ok((policy, group, policy_group))
}

pub(super) fn read_blobs(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<HistoricalNativeBlobLedger>, Option<usize>, usize), ProviderError> {
    if input == b"null" {
        return Ok((None, None, 0));
    }
    let start = ledger.rows.encoded_position();
    let layout = crate::blob::original_blob_layouts().state;
    let (alignment, _, _) = crate::blob::original_blob_alignment17_data();
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, alignment)? != layout {
        return Err(invalid());
    }
    let group = ledger.shared_begin(MetadataSharedKind::BlobLedger)?;
    let (blobs, payload) =
        crate::protocol_snapshot::owned11::native::blob::read_native17_blob_leaf_data(
            input, ledger, build,
        )?;
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout, input, rows)?;
    Ok((blobs, Some(group), payload))
}

impl HistoricalType for HistoricalCurrentNativeConnection17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_native17_connection_data(input, ledger, build)
    }
}

// The concrete root grammar lends a full receiver. Its ledger field is reread
// strictly under the same source rows and completed shared group by read_blobs.
fn receiver_ledger_span(input: &[u8]) -> Result<&[u8], ProviderError> {
    let mut fields = Fields::array(input)?;
    exact(next(&mut fields)?, "source-private.native-blob-receiver/11")?;
    for _ in 0..3 {
        next(&mut fields)?;
    }
    let ledger = next(&mut fields)?;
    exact(
        next(&mut fields)?,
        "source-private.native-supervisor-owner/11",
    )?;
    fields.finish()?;
    if ledger == b"null" {
        return Err(invalid());
    }
    Ok(ledger)
}

mod authority_selection17;
pub(crate) use authority_selection17::{
    preflight_rooted_native17_connection_authority_data,
    read_rooted_native17_connection_authority_into_data,
};
