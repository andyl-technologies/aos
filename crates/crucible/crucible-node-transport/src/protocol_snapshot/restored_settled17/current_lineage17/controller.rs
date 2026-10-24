//! Selects the actual launch controller triple while walking every launch field.

use super::super::current_launch::CurrentSourceProgram17;
use super::*;
use crate::reference_packet::{control::PacketControlSelection, service::*};

pub(crate) struct BorrowedControllerLineage17<'body, 'rows> {
    pub(crate) selection: BorrowedLineageField17<'body, 'rows, PacketControlSelection>,
    pub(crate) controller_pid: BorrowedLineageField17<'body, 'rows, U64>,
    pub(crate) controller_uid: BorrowedLineageField17<'body, 'rows, U64>,
    pub(crate) controller_executable: BorrowedLineageField17<'body, 'rows, ContentRef>,
}

pub(super) fn read<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<Option<BorrowedControllerLineage17<'body, 'rows>>, ProviderError> {
    if input == b"null" {
        return Ok(None);
    }
    let mut f = Fields::object(input)?;
    role(
        f.named("schema")?,
        "source-private.native-current-source-launch/17",
    )?;
    discard::<u16>(f.named("schema_version")?, ledger)?;
    let selection = loan(f.named("selection")?, ledger)?;
    discard::<CurrentSourceProgram17>(f.named("program")?, ledger)?;
    let controller_pid = loan(f.named("controller_pid")?, ledger)?;
    let controller_uid = loan(f.named("controller_uid")?, ledger)?;
    let controller_executable = loan(f.named("controller_executable")?, ledger)?;
    discard::<Bytes>(f.named("admission_token")?, ledger)?;
    discard::<CurrentDto17<crate::reference_service::InstalledContent>>(
        f.named("initial_coordinator")?,
        ledger,
    )?;
    discard::<crate::handshake::Limits>(f.named("limits")?, ledger)?;
    discard::<CurrentDto17<PacketNative5StorageLimits>>(f.named("storage")?, ledger)?;
    discard::<PacketNative5CaptureProfile>(f.named("capture_profile")?, ledger)?;
    discard::<Option<PacketNative5ConfirmationSelection>>(
        f.named("confirmation_selection")?,
        ledger,
    )?;
    discard::<Option<PacketNative5AckEmitterSelection>>(f.named("ack_emitter_selection")?, ledger)?;
    discard::<Option<crate::client::CanonicalAckCodecMetadataExtent>>(
        f.named("native_codec_metadata_extent")?,
        ledger,
    )?;
    discard::<Option<PacketNative5ProtocolMetadataLimits>>(
        f.named("protocol_metadata_limits")?,
        ledger,
    )?;
    discard::<Option<PacketNative5CompleteRestoreSelection>>(
        f.named("complete_restore_selection")?,
        ledger,
    )?;
    discard::<Option<PacketNative5RestoreInputEmitterSelection>>(
        f.named("restore_input_emitter_selection")?,
        ledger,
    )?;
    discard::<Option<crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection>>(f.named("capture_allocation_selection")?, ledger)?;
    discard::<Option<crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection>>(f.named("fresh_restore_allocation_selection")?, ledger)?;
    discard::<crate::connection::settled17::HistoricalByteBank17>(f.named("effects")?, ledger)?;
    f.finish()?;
    Ok(Some(BorrowedControllerLineage17 {
        selection,
        controller_pid,
        controller_uid,
        controller_executable,
    }))
}
