//! Owns the closed rooted native17 graph grammar and its concrete root spans.
//!
//! The archive contains one complete payload for each actual source root. Child
//! variants use closed role literals and this parser's exact borrowed root
//! spans; caller-supplied scalars cannot construct those substitutions.
//!
//! ```text
//! ["source-private.cnp-protocol/17",
//!  ["source-private.native-current-rooted-graph/17", registrar, actor,
//!   supervisor, codec, controlIdentity, hold, frames, deadline, mapping,
//!   receiver, boot, connection, endpoint, control, service], rows, aliases]
//! ```

mod actor;
mod borrowed;
mod hello;
mod limits;
mod reader;
pub(crate) use borrowed::{BorrowedNativeCurrentGraph17Plan, NativeCurrentGraph17Rows};
pub(crate) use limits::NativeCurrentGraph17ReadLimits;
pub(crate) use reader::{
    NativeCurrentGraph17Data, NativeCurrentGraph17DecodeAttempt,
    read_native_current_graph17_into_data, read_native_current_graph17_with_limits_into_data,
    read_native_current_graph17_with_admission_into_data, native_current_graph17_banks_data,
};

use super::owned11::typed::{Fields, invalid, plain_string};
use crate::ProviderError;

pub(crate) const CURRENT_GRAPH17_FORMAT: &str = "source-private.native-current-rooted-graph/17";
pub(crate) const CURRENT_PROTOCOL17_FORMAT: &str = "source-private.cnp-protocol/17";

/// Borrows only root payloads selected by the enclosing closed graph grammar.
///
/// Fields and the constructor are private to this defining parser. Consumers
/// cannot fabricate this value from independent leaf spans or scalar budgets.
pub(crate) struct NativeCurrentGraph17RootSpans<'input> {
    registrar: &'input [u8],
    actor: &'input [u8],
    supervisor: &'input [u8],
    codec: &'input [u8],
    control_identity: &'input [u8],
    hold: &'input [u8],
    frames: &'input [u8],
    deadline: &'input [u8],
    mapping: &'input [u8],
    receiver: &'input [u8],
    boot: &'input [u8],
    connection: &'input [u8],
    endpoint: &'input [u8],
    control: &'input [u8],
    service: &'input [u8],
    records: &'input [u8],
    aliases: &'input [u8],
}

impl<'input> NativeCurrentGraph17RootSpans<'input> {
    fn read(input: &'input [u8]) -> Result<Self, ProviderError> {
        let mut outer = Fields::array(input)?;
        exact(next(&mut outer)?, CURRENT_PROTOCOL17_FORMAT)?;
        let mut fields = Fields::array(next(&mut outer)?)?;
        exact(next(&mut fields)?, CURRENT_GRAPH17_FORMAT)?;
        let value = Self {
            registrar: next(&mut fields)?,
            actor: next(&mut fields)?,
            supervisor: next(&mut fields)?,
            codec: next(&mut fields)?,
            control_identity: next(&mut fields)?,
            hold: next(&mut fields)?,
            frames: next(&mut fields)?,
            deadline: next(&mut fields)?,
            mapping: next(&mut fields)?,
            receiver: next(&mut fields)?,
            boot: next(&mut fields)?,
            connection: next(&mut fields)?,
            endpoint: next(&mut fields)?,
            control: next(&mut fields)?,
            service: next(&mut fields)?,
            records: next(&mut outer)?,
            aliases: next(&mut outer)?,
        };
        fields.finish()?;
        outer.finish()?;
        Ok(value)
    }

    pub(crate) fn boot_data(&self) -> &'input [u8] {
        self.boot
    }
    pub(crate) fn mapping_data(&self) -> &'input [u8] {
        self.mapping
    }

    pub(crate) fn registrar_data(&self) -> &'input [u8] {
        self.registrar
    }
    pub(crate) fn codec_data(&self) -> &'input [u8] {
        self.codec
    }
    pub(crate) fn frames_data(&self) -> &'input [u8] {
        self.frames
    }
    pub(crate) fn receiver_data(&self) -> &'input [u8] {
        self.receiver
    }
    pub(crate) fn control_data(&self) -> &'input [u8] {
        self.control
    }
    pub(crate) fn endpoint_data(&self) -> &'input [u8] {
        self.endpoint
    }
    pub(crate) fn connection_data(&self) -> &'input [u8] {
        self.connection
    }
    pub(crate) fn service_data(&self) -> &'input [u8] {
        self.service
    }
    pub(crate) fn hold_data(&self) -> Option<&'input [u8]> {
        (self.hold != b"null").then_some(self.hold)
    }
}

fn next<'a>(fields: &mut Fields<'a>) -> Result<&'a [u8], ProviderError> {
    fields.next()?.ok_or_else(invalid)
}

fn exact(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}

/// Counts this reader's explicit fixed borrowed-parser workspaces.
///
/// The actual once-owner header is reported separately by
/// `NativeCurrentGraph17DecodeAttempt::inline_header_bytes_data`. Raw/scratch
/// banks and typed target backing remain independent dynamic terms. Defining
/// component and compiler/serializer workspaces need their separate admission.
pub(crate) const fn native_current_graph17_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<NativeCurrentGraph17RootSpans<'static>>()
        + size_of::<BorrowedNativeCurrentGraph17Plan<'static, 'static>>()
        + size_of::<NativeCurrentGraph17Rows<'static>>()
        + size_of::<NativeCurrentGraph17ReadLimits>()
        + size_of::<crate::protocol_snapshot::owned11::typed::Ledger<'static, 'static, 'static>>()
        + size_of::<[u8; 64]>()
        + crate::connection::native17_logical_projection_scratch_data()
        + NativeCurrentGraph17DecodeAttempt::inline_header_bytes_data()
        + size_of::<crate::retained_metadata::records::ValidatedMetadataRecords<'static>>()
        + size_of::<crate::retained_metadata::records::MetadataRecordRows<'static>>()
}
