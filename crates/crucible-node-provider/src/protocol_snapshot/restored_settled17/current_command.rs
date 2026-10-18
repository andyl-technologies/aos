//! Reads signed17 action and unchanged edition4 Input command objects as DATA.

use super::current_contracts::{CurrentContract17, CurrentDto17, CurrentField17, Plain17};
use crate::reference_packet::input::{PacketInputContext, PacketInputCut};
use crate::reference_packet::service::restored_input_reactive17::PacketRestoredInputReactive17Command;
use crate::retained_metadata::MetadataObserver;
use crate::{
    ProviderError,
    protocol_snapshot::owned11::typed::{Fields, HistoricalType, Ledger, invalid, plain_string},
};
use crucible_node_contract::{ContentRef, Id};

pub(crate) struct CurrentInputCommand17;

impl CurrentField17 for CurrentInputCommand17 {
    type Native = PacketRestoredInputReactive17Command;

    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self::Native>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let action = plain_string(fields.named("action")?)?;
        let result = match action {
            "input" => read_context17(fields.named("context")?, ledger, build)?
                .map(|context| PacketRestoredInputReactive17Command::Input { context }),
            "run" => build.then_some(PacketRestoredInputReactive17Command::Run),
            "settle" => build.then_some(PacketRestoredInputReactive17Command::Settle),
            "poll" => build.then_some(PacketRestoredInputReactive17Command::Poll),
            "retire" => build.then_some(PacketRestoredInputReactive17Command::Retire),
            "observe" => build.then_some(PacketRestoredInputReactive17Command::Observe),
            "blob_begin" => build.then_some(PacketRestoredInputReactive17Command::BlobBegin),
            "blob_chunk" => build.then_some(PacketRestoredInputReactive17Command::BlobChunk),
            "blob_finish" => build.then_some(PacketRestoredInputReactive17Command::BlobFinish),
            _ => return Err(invalid()),
        };
        fields.finish()?;
        Ok(result)
    }

    fn observe(
        value: &Self::Native,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let PacketRestoredInputReactive17Command::Input { context } = value {
            match context {
                PacketInputContext::Stage { cut } => cut.observe_current(observer)?,
                PacketInputContext::Commit {
                    cut,
                    input_request_id,
                    staging_receipt,
                } => {
                    cut.observe_current(observer)?;
                    observer.observe(input_request_id)?;
                    observer.observe(staging_receipt)?;
                }
            }
        }
        Ok(())
    }
}

fn read_context17(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<PacketInputContext>, ProviderError> {
    let mut fields = Fields::object(input)?;
    let action = plain_string(fields.named("action")?)?;
    let cut = <CurrentDto17<PacketInputCut> as CurrentField17>::read(
        fields.named("cut")?,
        ledger,
        build,
    )?;
    let result = match action {
        "stage" => cut.map(|cut| PacketInputContext::Stage { cut }),
        "commit" => {
            let id = <Plain17<Id> as CurrentField17>::read(
                fields.named("input_request_id")?,
                ledger,
                build,
            )?;
            let receipt = <Plain17<ContentRef> as CurrentField17>::read(
                fields.named("staging_receipt")?,
                ledger,
                build,
            )?;
            if build {
                Some(PacketInputContext::Commit {
                    cut: cut.ok_or_else(invalid)?,
                    input_request_id: id.ok_or_else(invalid)?,
                    staging_receipt: receipt.ok_or_else(invalid)?,
                })
            } else {
                None
            }
        }
        _ => return Err(invalid()),
    };
    fields.finish()?;
    Ok(result)
}
