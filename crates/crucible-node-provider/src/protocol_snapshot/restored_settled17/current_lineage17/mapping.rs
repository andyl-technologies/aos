//! Borrows canonical mapping bytes during the complete actual mapping root walk.

use super::*;
use crate::protocol_snapshot::owned11::typed::Native17Build;
use crate::{
    protocol_snapshot::{
        ProtocolCaptureOwner,
        restored_settled17::current_import17::{HistoricalSealedNativeImport17, Import17},
    },
    retained_metadata::{MetadataObserver, records::MetadataRecordKind},
};

/// Retains only actual canonical normalization bytes, without an imported heap.
pub(crate) struct NativeMappingNormalization17(pub(crate) Vec<u8>);
impl NativeMappingNormalization17 {
    pub(crate) fn bytes_data(&self) -> &[u8] {
        &self.0
    }
}

fn parts<'a>(
    input: &'a [u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<(usize, &'a [u8]), ProviderError> {
    let mut f = Fields::array(input)?;
    let capacity =
        usize::try_from(unsigned(f.next()?.ok_or_else(invalid)?)?).map_err(|_| invalid())?;
    let raw = f.next()?.ok_or_else(invalid)?;
    f.finish()?;
    if ledger.row_aligned(MetadataRecordKind::Vector, 1, 1)? != capacity
        || capacity > ledger.limits.maximum_owned_backing_bytes
    {
        return Err(invalid());
    }
    Ok((capacity, raw))
}

fn bytes(input: &[u8], capacity: usize) -> Result<(), ProviderError> {
    let mut f = Fields::array(input)?;
    let mut length = 0usize;
    while let Some(raw) = f.next()? {
        length = length.checked_add(1).ok_or_else(invalid)?;
        if length > capacity || unsigned(raw)? > u64::from(u8::MAX) {
            return Err(invalid());
        }
    }
    f.finish()
}

impl HistoricalType for NativeMappingNormalization17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        // Immutable evidence is the only HistoricalType path. The retaining
        // builder installs its byte bank before the first fallible reservation.
        if build {
            return Err(invalid());
        }
        let (capacity, raw) = parts(input, ledger)?;
        bytes(raw, capacity)?;
        Ok(None)
    }
}

#[derive(Default)]
pub(crate) struct NativeMappingNormalization17ReadAttempt {
    bytes: Vec<u8>,
    started: bool,
    failed: bool,
    completed: Option<NativeMappingNormalization17>,
}

impl Native17Build for NativeMappingNormalization17 {
    type Attempt = NativeMappingNormalization17ReadAttempt;

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let (capacity, raw) = parts(input, ledger)?;
        bytes(raw, capacity)?;
        ledger.native17_target_vector_data::<u8>(capacity)
    }

    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if attempt.started || attempt.failed || attempt.completed.is_some() {
            return Err(invalid());
        }
        attempt.started = true;
        attempt.failed = true;

        let (capacity, raw) = parts(input, ledger)?;
        ledger.native17_target_vector_data::<u8>(capacity)?;
        attempt
            .bytes
            .try_reserve_exact(capacity)
            .map_err(|_| invalid())?;
        if attempt.bytes.capacity() != capacity {
            return Err(invalid());
        }

        let mut f = Fields::array(raw)?;
        while let Some(raw) = f.next()? {
            if attempt.bytes.len() >= capacity {
                return Err(invalid());
            }
            let byte = u8::try_from(unsigned(raw)?).map_err(|_| invalid())?;
            attempt.bytes.push(byte);
        }
        f.finish()?;

        attempt.completed = Some(NativeMappingNormalization17(std::mem::take(
            &mut attempt.bytes,
        )));
        attempt.failed = false;
        Ok(())
    }

    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        attempt.completed.as_ref()
    }

    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        attempt.completed.take()
    }

    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.vector::<u8>(attempt.bytes.capacity())?;
        if let Some(value) = &attempt.completed {
            Self::observe_output_data(value, observer)?;
        }
        Ok(())
    }

    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.vector::<u8>(value.0.capacity())
    }
}

/// Pins normalization and reference fields to the actual full mapping root.
pub(crate) struct BorrowedMappingLineage17<'body, 'rows> {
    group: usize,
    pub(crate) actor_group: usize,
    pub(crate) codec_group: usize,
    pub(crate) class: &'body str,
    pub(crate) reference: BorrowedLineageField17<'body, 'rows, ContentRef>,
    pub(crate) normalization: BorrowedLineageField17<'body, 'rows, NativeMappingNormalization17>,
}

impl BorrowedMappingLineage17<'_, '_> {
    pub(crate) fn group_data(&self) -> usize {
        self.group
    }
}

/// Checks the complete defining mapping while borrowing only needed lineage.
///
/// # Errors
/// Refuses incomplete source grammar, unknown class, wrong shared roots or any
/// capacity/alias disagreement. Historical import remains checked evidence.
pub(crate) fn read_shared_current_mapping_lineage17_data<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<BorrowedMappingLineage17<'body, 'rows>, ProviderError> {
    if ledger.has_native17_targets_data() && !ledger.native17_targets_suspended_data() {
        return Err(invalid());
    }

    let start = ledger.rows.encoded_position();
    let layout = (
        size_of::<RefCell<PreparedArchivedNativeProtocolMapping>>(),
        align_of::<RefCell<PreparedArchivedNativeProtocolMapping>>(),
    );
    shared_row17(ledger, layout)?;
    let group = ledger.shared_begin(MetadataSharedKind::ArchivedMapping)?;
    let mut f = Fields::object(input)?;
    role(
        f.named("format")?,
        "source-private.current-import-prepared-mapping/17",
    )?;
    let class = plain_string(f.named("class")?)?;
    if !matches!(
        class,
        "legacy11" | "startup_capture14" | "invocation_capture15"
    ) {
        return Err(invalid());
    }
    role(f.named("actor_role")?, "native-connection-actor")?;
    let actor_group = read_reference17(
        ledger,
        MetadataSharedKind::ProtocolOwner,
        (
            size_of::<ProtocolCaptureOwner>(),
            align_of::<ProtocolCaptureOwner>(),
        ),
    )?;
    if crate::handshake::read_settled17_authority_data(f.named("authority")?, ledger, false)?
        .is_some()
    {
        return Err(invalid());
    }
    role(f.named("codec_role")?, "native-connection-codec")?;
    let codec_group = read_reference17(
        ledger,
        MetadataSharedKind::Codec,
        (
            size_of::<crate::connection::Native5CodecOwner>(),
            align_of::<crate::connection::Native5CodecOwner>(),
        ),
    )?;
    let reference = loan(f.named("reference")?, ledger)?;
    if <[u8; 32]>::read_current(f.named("nonce")?, ledger, false)?.is_some() {
        return Err(invalid());
    }
    let normalization = loan(f.named("normalization")?, ledger)?;
    discard::<Option<HistoricalSealedNativeImport17>>(f.named("historical")?, ledger)?;
    f.finish()?;

    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(group, layout.0, input, rows)?;

    Ok(BorrowedMappingLineage17 {
        group,
        actor_group,
        codec_group,
        class,
        reference,
        normalization,
    })
}
