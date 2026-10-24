//! Defines the actual process/thread actor root as inert bounded creator data.

use super::{super::ProtocolCaptureOwner, next};
use crate::ProviderError;
use crate::protocol_snapshot::owned11::typed::{Fields, Ledger, invalid, plain_string, unsigned};
use crate::retained_metadata::{
    MetadataObserver, ObserveMetadata, aliases::MetadataSharedKind, records::MetadataRecordKind,
};
use serde::Serialize;
use std::{
    mem::{align_of, size_of},
    thread::ThreadId,
};

impl ProtocolCaptureOwner {
    pub(crate) fn borrowed_native_root17_data(&self) -> Result<impl Serialize + '_, ProviderError> {
        self.original_creator_view()
    }

    pub(crate) fn observe_native_root17_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.ensure_current()?;
        let Self { pid, thread } = self;
        observer.observe(pid)?;
        observer.observe(&InlineThread(thread))
    }
}

// The source's existing original_creator_view formats this actual ThreadId in
// a bounded stack buffer. No retained String exists and no String row is made.
struct InlineThread<'a>(&'a ThreadId);

impl ObserveMetadata for InlineThread<'_> {
    fn observe_metadata(&self, _: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let _ = self.0;
        Ok(())
    }
}

/// Retains bounded creator spelling without reconstructing any live actor.
pub(crate) struct HistoricalNativeActor17 {
    pub(crate) process: u32,
    thread: [u8; 64],
    thread_length: usize,
    pub(crate) group: usize,
}

impl HistoricalNativeActor17 {
    pub(crate) fn thread_data(&self) -> &[u8] {
        &self.thread[..self.thread_length]
    }
}

pub(super) fn read_actor17_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<HistoricalNativeActor17>, usize), ProviderError> {
    let layout = size_of::<ProtocolCaptureOwner>();
    if ledger.row_aligned(
        MetadataRecordKind::Shared,
        1,
        align_of::<ProtocolCaptureOwner>(),
    )? != layout
    {
        return Err(invalid());
    }
    let mut fields = Fields::array(input)?;
    if plain_string(next(&mut fields)?)? != "source-private.original-creator-rust-thread/12" {
        return Err(invalid());
    }
    let process = u32::try_from(unsigned(next(&mut fields)?)?).map_err(|_| invalid())?;
    let thread_text = plain_string(next(&mut fields)?)?;
    fields.finish()?;
    let Some(number) = thread_text
        .strip_prefix("ThreadId(")
        .and_then(|value| value.strip_suffix(')'))
    else {
        return Err(invalid());
    };
    if process == 0
        || thread_text.len() > 64
        || number.is_empty()
        || unsigned(number.as_bytes())? == 0
    {
        return Err(invalid());
    }
    let group = ledger.shared(MetadataSharedKind::ProtocolOwner, layout, input, b"")?;
    if !build {
        return Ok((None, group));
    }
    let mut thread = [0; 64];
    thread[..thread_text.len()].copy_from_slice(thread_text.as_bytes());
    Ok((
        Some(HistoricalNativeActor17 {
            process,
            thread,
            thread_length: thread_text.len(),
            group,
        }),
        group,
    ))
}
