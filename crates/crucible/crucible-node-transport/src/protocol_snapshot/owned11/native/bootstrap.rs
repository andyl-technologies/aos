//! Restores closed private bootstrap history without recreating an input stream.

use super::super::{
    state::{next, tag},
    typed::{Fields, invalid},
};
use super::{boot::HistoricalNativeBoot, shared::NativeLedger, token::HistoricalNativeAckToken};
use crate::{
    ProviderError,
    retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind},
    transport::{DecodedCompactOriginalFrames, original_frames::FrameDirection},
};
use serde_json::Value;
use std::rc::Rc;

/// Retains every successful closed bootstrap field as inert historical data.
pub struct HistoricalNativeBootstrap {
    /// Retains the original reader limits, phase and last literal slot as data.
    pub reader: super::super::reader::HistoricalFrameReaderFacts,
    /// Shares the complete private-channel bank with its checked archive group.
    pub literals: Rc<DecodedCompactOriginalFrames>,
    /// Retains the entire decoded original launch object and its capacities.
    pub launch_value: Value,
    /// Retains the exact original canonical launch bytes and spare capacity.
    pub launch_bytes: Vec<u8>,
    /// Retains the complete decoded original private boot object.
    pub boot_value: Value,
    /// Shares the original boot history with the historical admission token.
    pub boot: Rc<HistoricalNativeBoot>,
    /// Retains the full fixed original startup preamble and nonrenewing flags.
    pub startup: Option<super::startup::HistoricalNativeStartupBootstrap>,
}

impl HistoricalNativeBootstrap {
    /// Checks complete private literals and original-token alias correspondence.
    ///
    /// # Errors
    /// Refuses a differing boot group, unfinished reader, changed launch or
    /// private-channel history. The outer result slot retains this owner.
    pub(crate) fn authenticate_correspondence(
        &self,
        token: &HistoricalNativeAckToken,
    ) -> Result<(), ProviderError> {
        if !Rc::ptr_eq(&self.boot, &token.boot)
            || self.reader.failed
            || self.reader.last_original_slot != Some(1)
            || self.literals.frames().count() != 2
        {
            return Err(invalid());
        }
        for (index, frame) in self.literals.frames().enumerate() {
            if frame.direction != FrameDirection::Incoming
                || !frame.complete
                || frame.transferred != frame.bytes.len()
                || frame.bytes.len() < 4
            {
                return Err(invalid());
            }
            let body = &frame.bytes[4..];
            if index == 0 {
                if body != self.launch_bytes || body != self.boot.launch_body {
                    return Err(invalid());
                }
                super::super::correspondence::json_value(&self.launch_value, body)?;
            } else {
                super::super::correspondence::json_value(&self.boot_value, body)?;
            }
        }
        match (&self.startup, &self.boot.startup) {
            (None, None) => {}
            (Some(startup), Some(_)) if self.boot.invocation.is_some() => {
                super::invocation::authenticate_bootstrap(startup, self)?
            }
            (Some(startup), Some(_)) => startup.authenticate(self)?,
            _ => return Err(invalid()),
        }
        Ok(())
    }
}

pub(super) fn read(
    input: &[u8],
    ledger: &mut NativeLedger<'_, '_, '_, '_, '_>,
    build: bool,
    bootstrap_layout: usize,
    boot_layout: usize,
) -> Result<Option<HistoricalNativeBootstrap>, ProviderError> {
    let startup_class = ledger.requires_startup_class()?;
    let invocation_class = ledger.requires_invocation_class()?;
    let (input, startup_input) = if startup_class {
        let mut wrapper = Fields::array(input)?;
        tag(
            &mut wrapper,
            if invocation_class {
                "source-private.native-private-bootstrap-invocation/15"
            } else {
                "source-private.native-private-bootstrap-startup/14"
            },
        )?;
        let base = next(&mut wrapper)?;
        let startup = next(&mut wrapper)?;
        wrapper.finish()?;
        (base, Some(startup))
    } else {
        (input, None)
    };
    let mut fields = Fields::array(input)?;
    tag(
        &mut fields,
        if invocation_class {
            "source-private.native-private-bootstrap/15"
        } else if startup_class {
            "source-private.native-private-bootstrap/14"
        } else {
            "source-private.native-private-bootstrap/11"
        },
    )?;
    tag(&mut fields, "closed-original-private-stream")?;
    tag(&mut fields, "original-cut-transferred")?;
    if ledger.ledger.row(MetadataRecordKind::Boxed, 1)? != bootstrap_layout {
        return Err(invalid());
    }
    let reader = ledger
        .ledger
        .read::<super::super::reader::HistoricalFrameReaderFacts>(next(&mut fields)?, true)?
        .ok_or_else(invalid)?;
    if reader.failed || reader.last_original_slot != Some(1) {
        return Err(invalid());
    }
    let literal_view = next(&mut fields)?;
    let literals = ledger.frames(
        literal_view,
        build,
        MetadataSharedKind::PrivateBootstrapBank,
    )?;
    let reader_literals = ledger.frames(
        literal_view,
        build,
        MetadataSharedKind::PrivateBootstrapBank,
    )?;
    if build
        && !Rc::ptr_eq(
            literals.as_ref().ok_or_else(invalid)?,
            reader_literals.as_ref().ok_or_else(invalid)?,
        )
    {
        return Err(invalid());
    }
    let launch_raw = next(&mut fields)?;
    if launch_raw == b"null" {
        return Err(invalid());
    }
    let launch_value = ledger.ledger.read::<Value>(launch_raw, build)?;
    let launch_bytes = super::bytes::bank(next(&mut fields)?, ledger.ledger, build, None)?;
    // The actual typed launch moved into the endpoint; the retained slot is empty.
    if next(&mut fields)? != b"true" {
        return Err(invalid());
    }
    let boot_raw = next(&mut fields)?;
    if boot_raw == b"null" {
        return Err(invalid());
    }
    let boot_value = ledger.ledger.read::<Value>(boot_raw, build)?;
    let boot = ledger.boot(next(&mut fields)?, build, boot_layout)?;
    fields.finish()?;
    let startup = if let Some(input) = startup_input {
        if invocation_class {
            super::startup::read_invocation_bootstrap(input, ledger.ledger, build)?
        } else {
            super::startup::read_bootstrap(input, ledger.ledger, build)?
        }
    } else {
        None
    };
    if !build {
        return Ok(None);
    }
    Ok(Some(HistoricalNativeBootstrap {
        reader,
        literals: literals.ok_or_else(invalid)?,
        launch_value: launch_value.ok_or_else(invalid)?,
        launch_bytes: launch_bytes.ok_or_else(invalid)?,
        boot_value: boot_value.ok_or_else(invalid)?,
        boot: boot.ok_or_else(invalid)?,
        startup,
    }))
}

// The closed owning walk fails to compile if a historical field is added.
super::super::retained_storage::fields!(
    HistoricalNativeBootstrap,
    reader,
    literals,
    launch_value,
    launch_bytes,
    boot_value,
    boot,
    startup
);

pub(crate) mod current17;

/// Names actual fixed local and returned headers of this handwritten reader.
///
/// Empty maps and `Option` payloads remain real controls when `build` is false;
/// no tree entries, backing allocations or owning reconstruction are included.
pub(super) fn borrowed_validation_headers_data() -> usize {
    use std::mem::size_of;

    fn header<T>() -> usize {
        size_of::<Option<T>>() + size_of::<Result<Option<T>, ProviderError>>()
    }

    fn field<T: super::super::typed::HistoricalType>() -> usize {
        header::<T>() + T::borrowed_header_counter_scratch_data()
    }

    field::<super::super::reader::HistoricalFrameReaderFacts>()
        + field::<Value>()
        + field::<Value>()
        + header::<HistoricalNativeBootstrap>()
        + header::<super::startup::HistoricalNativeStartupBootstrap>()
        + header::<std::rc::Rc<super::boot::HistoricalNativeBoot>>()
        + header::<std::rc::Rc<super::policy::HistoricalNativePolicy>>()
        + header::<std::rc::Rc<crate::transport::DecodedCompactOriginalFrames>>()
        + header::<std::rc::Rc<crate::transport::DecodedCompactOriginalFrames>>()
        + header::<Vec<u8>>()
}
