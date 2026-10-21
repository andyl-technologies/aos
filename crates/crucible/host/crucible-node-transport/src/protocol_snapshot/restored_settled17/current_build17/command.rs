//! Retains complete Input context fields before a later command-field refusal.

use super::*;
use crate::protocol_snapshot::owned11::typed::plain_string;
use crate::protocol_snapshot::restored_settled17::current_command::CurrentInputCommand17;
use crate::reference_packet::{
    input::{PacketInputContext, PacketInputCut},
    service::restored_input_reactive17::PacketRestoredInputReactive17Command,
};
use crucible_node_format::{ContentRef, Id};

#[derive(Default)]
pub(crate) struct InputCommand17ReadAttempt {
    pub(crate) cut: <CurrentDto17<PacketInputCut> as BuildCurrentField17>::Attempt,
    pub(crate) input_request_id: <Plain17<Id> as BuildCurrentField17>::Attempt,
    pub(crate) staging_receipt: <Plain17<ContentRef> as BuildCurrentField17>::Attempt,
    pub(crate) phase: usize,
    pub(crate) failed: bool,
    completed: Option<PacketRestoredInputReactive17Command>,
}

fn fields17(
    input: &[u8],
) -> Result<(&str, Option<(&str, &[u8], Option<(&[u8], &[u8])>)>), ProviderError> {
    let mut f = Fields::object(input)?;
    let action = plain_string(f.named("action")?)?;
    let context = if action == "input" {
        let mut c = Fields::object(f.named("context")?)?;
        let kind = plain_string(c.named("action")?)?;
        let cut = c.named("cut")?;
        let rest = match kind {
            "stage" => None,
            "commit" => Some((c.named("input_request_id")?, c.named("staging_receipt")?)),
            _ => return Err(invalid()),
        };
        c.finish()?;
        Some((kind, cut, rest))
    } else {
        if !matches!(
            action,
            "run"
                | "settle"
                | "poll"
                | "retire"
                | "observe"
                | "blob_begin"
                | "blob_chunk"
                | "blob_finish"
        ) {
            return Err(invalid());
        }
        None
    };
    f.finish()?;
    Ok((action, context))
}

impl BuildCurrentField17 for CurrentInputCommand17 {
    type Attempt = InputCommand17ReadAttempt;

    fn preflight_data(input: &[u8], l: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let (_, context) = fields17(input)?;
        if let Some((_, cut, rest)) = context {
            <CurrentDto17<PacketInputCut> as BuildCurrentField17>::preflight_data(cut, l)?;
            if let Some((id, receipt)) = rest {
                <Plain17<Id> as BuildCurrentField17>::preflight_data(id, l)?;
                <Plain17<ContentRef> as BuildCurrentField17>::preflight_data(receipt, l)?;
            }
        }
        Ok(())
    }

    fn read_into_data(
        input: &[u8],
        l: &mut Ledger<'_, '_, '_>,
        a: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        if a.failed || a.phase != 0 || a.completed.is_some() {
            return Err(invalid());
        }

        let result = (|| {
            let (action, context) = fields17(input)?;
            let value = if let Some((kind, cut, rest)) = context {
                <CurrentDto17<PacketInputCut> as BuildCurrentField17>::read_into_data(
                    cut, l, &mut a.cut,
                )?;
                a.phase = 1;
                if let Some((id, receipt)) = rest {
                    <Plain17<Id> as BuildCurrentField17>::read_into_data(
                        id,
                        l,
                        &mut a.input_request_id,
                    )?;
                    a.phase = 2;
                    <Plain17<ContentRef> as BuildCurrentField17>::read_into_data(
                        receipt,
                        l,
                        &mut a.staging_receipt,
                    )?;
                    a.phase = 3;
                }
                if <CurrentDto17<PacketInputCut> as BuildCurrentField17>::output_data(&a.cut)
                    .is_none()
                {
                    return Err(invalid());
                }

                let context = match kind {
                    "stage" => PacketInputContext::Stage {
                        cut:
                            <CurrentDto17<PacketInputCut> as BuildCurrentField17>::take_output_data(
                                &mut a.cut,
                            )
                            .ok_or_else(invalid)?,
                    },
                    "commit" => {
                        if <Plain17<Id> as BuildCurrentField17>::output_data(&a.input_request_id)
                            .is_none()
                            || <Plain17<ContentRef> as BuildCurrentField17>::output_data(
                                &a.staging_receipt,
                            )
                            .is_none()
                        {
                            return Err(invalid());
                        }
                        PacketInputContext::Commit {
                            cut: <CurrentDto17<PacketInputCut> as BuildCurrentField17>::take_output_data(
                                &mut a.cut
                            ).ok_or_else(invalid)?,
                            input_request_id: <Plain17<Id> as BuildCurrentField17>::take_output_data(
                                &mut a.input_request_id
                            ).ok_or_else(invalid)?,
                            staging_receipt: <Plain17<ContentRef> as BuildCurrentField17>::take_output_data(
                                &mut a.staging_receipt
                            ).ok_or_else(invalid)?
                        }
                    }
                    _ => return Err(invalid()),
                };
                PacketRestoredInputReactive17Command::Input { context }
            } else {
                match action {
                    "run" => PacketRestoredInputReactive17Command::Run,
                    "settle" => PacketRestoredInputReactive17Command::Settle,
                    "poll" => PacketRestoredInputReactive17Command::Poll,
                    "retire" => PacketRestoredInputReactive17Command::Retire,
                    "observe" => PacketRestoredInputReactive17Command::Observe,
                    "blob_begin" => PacketRestoredInputReactive17Command::BlobBegin,
                    "blob_chunk" => PacketRestoredInputReactive17Command::BlobChunk,
                    "blob_finish" => PacketRestoredInputReactive17Command::BlobFinish,
                    _ => return Err(invalid()),
                }
            };

            a.completed = Some(value);
            Ok(())
        })();
        if result.is_err() {
            a.failed = true;
        }
        result
    }

    fn output_data(a: &Self::Attempt) -> Option<&Self::Native> {
        a.completed.as_ref()
    }

    fn take_output_data(a: &mut Self::Attempt) -> Option<Self::Native> {
        a.completed.take()
    }

    fn observe_attempt_data(
        a: &Self::Attempt,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        <CurrentDto17<PacketInputCut> as BuildCurrentField17>::observe_attempt_data(&a.cut, o)?;
        <Plain17<Id> as BuildCurrentField17>::observe_attempt_data(&a.input_request_id, o)?;
        <Plain17<ContentRef> as BuildCurrentField17>::observe_attempt_data(&a.staging_receipt, o)?;
        if let Some(v) = &a.completed {
            <Self as BuildCurrentField17>::observe_output_data(v, o)?;
        }
        Ok(())
    }

    fn observe_output_data(
        v: &Self::Native,
        o: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        <Self as CurrentField17>::observe(v, o)
    }
}
