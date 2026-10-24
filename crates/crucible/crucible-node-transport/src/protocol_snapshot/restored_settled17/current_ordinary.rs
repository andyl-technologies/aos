//! Reads the closed ordinary body roster shared by retained native17 attempts.

use super::current_contracts::{CurrentDto17, CurrentField17};
use crate::{
    ProviderError,
    bodies::*,
    protocol_snapshot::owned11::typed::{Ledger, invalid},
};

pub(crate) enum CurrentOrdinaryBody17 {
    Input(InputRequest),
    Begin(BeginRequest),
    Poll(PollRequest),
    Retire(RetireRequest),
    Observe(ObserveRequest),
    BlobBegin(BlobBeginRequest),
    BlobChunk(BlobChunkRequest),
    BlobFinish(BlobFinishRequest),
}

pub(crate) fn read_ordinary17(
    kind: &str,
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<CurrentOrdinaryBody17>, ProviderError> {
    macro_rules! body {
        ($ty:ty, $variant:ident) => {
            <CurrentDto17<$ty> as CurrentField17>::read(input, ledger, build)
                .map(|value| value.map(CurrentOrdinaryBody17::$variant))
        };
    }
    match kind {
        "input" => body!(InputRequest, Input),
        "begin" | "capture" => body!(BeginRequest, Begin),
        "poll" | "confirmation" => body!(PollRequest, Poll),
        "retire" => body!(RetireRequest, Retire),
        "observe" => body!(ObserveRequest, Observe),
        "blob_begin" => body!(BlobBeginRequest, BlobBegin),
        "blob_chunk" => body!(BlobChunkRequest, BlobChunk),
        "blob_finish" => body!(BlobFinishRequest, BlobFinish),
        _ => Err(invalid()),
    }
}
