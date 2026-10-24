//! Retains complete installed-input, response and installed-Commit field owners.

use super::tokens::HistoricalPrepareToken17;
use super::*;
use crate::connection::settled17::read_byte_bank_parts17;
use crate::reference_packet::service::ack_emitter::HistoricalCommitToken17;

/// Retains installed Prepare token DATA and its actual custody-group edge.
pub(crate) struct HistoricalInstalledInputs17 {
    pub(crate) token: HistoricalPrepareToken17,
    pub(crate) custody_group: usize,
}

impl HistoricalType for HistoricalInstalledInputs17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.installed-restore-input-history/17",
        )?;
        let token = ledger.read::<HistoricalPrepareToken17>(fields.named("token")?, build)?;
        exact(
            fields.named("custody_role")?,
            "native-restore-input-custody",
        )?;
        let custody_group = reference::<RefCell<OriginalCompleteRestoreInputCustody>>(
            ledger,
            MetadataSharedKind::NativeRestoreInputCustody,
        )?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            token: token.ok_or_else(invalid)?,
            custody_group,
        }))
    }
}

/// Retains complete installed Commit token DATA and its exact mapping edge.
pub(crate) struct HistoricalCompleteInstallation17 {
    pub(crate) token: HistoricalCommitToken17,
    pub(crate) mapping_group: usize,
}

impl HistoricalType for HistoricalCompleteInstallation17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.complete-installation-history/17",
        )?;
        let token =
            HistoricalCommitToken17::read_settled17_data(fields.named("token")?, ledger, build)?;
        exact(
            fields.named("mapping_role")?,
            "native-archived-protocol-mapping",
        )?;
        let mapping_group = reference::<
            RefCell<crate::protocol_snapshot::PreparedArchivedNativeProtocolMapping>,
        >(ledger, MetadataSharedKind::ArchivedMapping)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            token: token.ok_or_else(invalid)?,
            mapping_group,
        }))
    }
}

/// Retains held-proof DATA without constructing the native proof credential.
pub(crate) struct HistoricalCompletedHeldProof17 {
    pub(crate) actor_group: usize,
    pub(crate) frames_group: usize,
    pub(crate) prefix_slots: usize,
    pub(crate) prefix_digest: [u8; 32],
    pub(crate) commit_sequence: u64,
    pub(crate) next_received: u64,
    pub(crate) next_sent: u64,
}

impl HistoricalType for HistoricalCompletedHeldProof17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.restore-held-proof-history/17",
        )?;
        exact(fields.named("actor_role")?, "native-connection-actor")?;
        let actor_group = reference::<crate::protocol_snapshot::ProtocolCaptureOwner>(
            ledger,
            MetadataSharedKind::ProtocolOwner,
        )?;
        exact(fields.named("bank_role")?, "native-connection-frames")?;
        let frames_group = reference::<
            RefCell<crate::transport::original_frames::OriginalFrameReservation>,
        >(ledger, MetadataSharedKind::FrameBank)?;
        let prefix_slots = ledger.read::<usize>(fields.named("prefix_slots")?, build)?;
        let prefix_digest = inline_digest(fields.named("prefix_digest")?, ledger)?;
        let commit_sequence = ledger.read::<u64>(fields.named("commit_sequence")?, build)?;
        let next_received = ledger.read::<u64>(fields.named("next_received")?, build)?;
        let next_sent = ledger.read::<u64>(fields.named("next_sent")?, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            actor_group,
            frames_group,
            prefix_digest,
            prefix_slots: prefix_slots.ok_or_else(invalid)?,
            commit_sequence: commit_sequence.ok_or_else(invalid)?,
            next_received: next_received.ok_or_else(invalid)?,
            next_sent: next_sent.ok_or_else(invalid)?,
        }))
    }
}

/// Retains the actual sticky response phase without inferring completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HistoricalAssignedResponsePhase17 {
    Unsigned,
    Sealing,
    Sealed,
    Publishing,
    Complete,
}

/// Retains all independent raw, typed, partial and deadline-alias response fields.
pub(crate) struct HistoricalAssignedResponse17 {
    pub(crate) group: usize,
    pub(crate) original: crate::envelope::Envelope,
    pub(crate) canonical: Vec<u8>,
    pub(crate) literal_slot: Option<usize>,
    pub(crate) request_sequence: U64,
    pub(crate) completed_proof: Option<HistoricalCompletedHeldProof17>,
    pub(crate) deadline_group: usize,
    pub(crate) original_cut_matches_deadline: bool,
    pub(crate) phase: HistoricalAssignedResponsePhase17,
}

pub(super) fn read_response(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<HistoricalAssignedResponse17>, ProviderError> {
    read_response_fields_data(input, ledger, build).map(|value| value.0)
}

pub(super) fn read_response_fields_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<HistoricalAssignedResponse17>, usize), ProviderError> {
    let start = ledger.rows.encoded_position();
    type Payload = RefCell<crate::connection::restore_response::AssignedNativeRestoreResponse>;
    let layout = size_of::<Payload>();
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, align_of::<Payload>())? != layout {
        return Err(invalid());
    }
    let group = ledger.shared_begin(MetadataSharedKind::NativeRestoreResponse)?;
    let mut fields = Fields::object(input)?;
    exact(
        fields.named("schema")?,
        "source-private.restore-response-history/17",
    )?;
    let original = ledger.read::<crate::envelope::Envelope>(fields.named("original")?, build)?;
    let capacity = ledger.rows.clone().next().ok_or_else(invalid)??.extent;
    let canonical = read_byte_bank_parts17(fields.named("canonical")?, capacity, ledger, build)?;
    let literal_slot = ledger.read::<Option<usize>>(fields.named("literal_slot")?, build)?;
    let request_sequence = ledger.read::<U64>(fields.named("request_sequence")?, build)?;
    let completed_proof = ledger
        .read::<Option<HistoricalCompletedHeldProof17>>(fields.named("completed_proof")?, build)?;
    exact(
        fields.named("deadline_role")?,
        "native-shared-operational-deadline-history-only",
    )?;
    let deadline_group = deadline(ledger)?;
    let original_cut_matches_deadline =
        ledger.read::<bool>(fields.named("original_cut_matches_deadline")?, build)?;
    let phase = match plain_string(fields.named("phase")?)? {
        "unsigned" => HistoricalAssignedResponsePhase17::Unsigned,
        "sealing" => HistoricalAssignedResponsePhase17::Sealing,
        "sealed" => HistoricalAssignedResponsePhase17::Sealed,
        "publishing" => HistoricalAssignedResponsePhase17::Publishing,
        "complete" => HistoricalAssignedResponsePhase17::Complete,
        _ => return Err(invalid()),
    };
    fields.finish()?;
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout, input, rows)?;
    if !build {
        return Ok((None, deadline_group));
    }
    Ok((
        Some(HistoricalAssignedResponse17 {
            group,
            deadline_group,
            phase,
            original: original.ok_or_else(invalid)?,
            canonical: canonical.ok_or_else(invalid)?,
            literal_slot: literal_slot.ok_or_else(invalid)?,
            request_sequence: request_sequence.ok_or_else(invalid)?,
            completed_proof: completed_proof.ok_or_else(invalid)?,
            original_cut_matches_deadline: original_cut_matches_deadline.ok_or_else(invalid)?,
        }),
        deadline_group,
    ))
}

impl HistoricalAssignedResponse17 {
    /// Checks completed serialization phases against their exact original bank slot.
    ///
    /// Partial unsigned/sealing owners remain DATA. Later phases require the
    /// already constructed original canonical proposal, even after failed I/O.
    ///
    /// # Errors
    /// Refuses changed canonical/original bytes, missing planned slot or an
    /// incomplete transport slot carrying the successful Complete phase.
    pub(crate) fn authenticate_frames_data(
        &self,
        frames: &HistoricalNativeFrameRoot17,
    ) -> Result<(), ProviderError> {
        if matches!(
            self.phase,
            HistoricalAssignedResponsePhase17::Unsigned
                | HistoricalAssignedResponsePhase17::Sealing
        ) {
            return Ok(());
        }
        crate::protocol_snapshot::owned11::correspondence::envelope(
            &self.original,
            &self.canonical,
        )?;
        let frame = frames
            .frames
            .frame(self.literal_slot.ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        if frame.direction != crate::transport::original_frames::FrameDirection::Outgoing
            || frame.bytes.get(4..) != Some(self.canonical.as_slice())
        {
            return Err(invalid());
        }
        if self.phase == HistoricalAssignedResponsePhase17::Complete
            && (!frame.complete || frame.transferred != frame.bytes.len())
        {
            return Err(invalid());
        }
        Ok(())
    }
}
