//! Exact-token settlement for the correlated native reset callback.
//!
//! Native PREPARE precedes scheduling, CHECK precedes lifecycle restoration,
//! and COMMIT follows the real terminal reset boundary. This module retains
//! the actual catalog incarnation and first refusal until VM retirement.
//! Neither a correlation nor this state is original resource authority.

use std::any::Any;
use std::os::raw::{c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::NonNull;

use crucible_protocol::{SELECTABLE_MESSAGE_MAX_BYTES, SelectableProtocolError, SelectionRequest};

use super::{LiveSelectableState, LiveWhiteboxError, SelectableCatalogError};
use crate::SelectablePendingRequest;

const PREPARE: u32 = 1;
const CHECK: u32 = 2;
const COMMIT: u32 = 3;

/// Private GPL-side ABI; its pointer never appears in a process protocol.
#[repr(C)]
pub(in crate::runtime::live_whitebox) struct NativeResetRequest {
    schema_version: u32,
    vcpu_index: u32,
    correlation: u64,
    request_sequence: u64,
    raw_icount: u64,
    trap_tick_ps: u64,
    reply_address: u64,
    request: *const u8,
    request_length: usize,
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum ResetPhase {
    #[default]
    Idle,
    Prepared,
    Committed,
    Failed,
}

/// Retains custody independently of callback success, error or unwind.
#[derive(Default)]
pub(super) struct ResetSettlement {
    pending: Option<SelectablePendingRequest>,
    correlation: u64,
    canonical: Vec<u8>,
    phase: ResetPhase,
    failure: Option<ResetRefusal>,
}

enum ResetRefusal {
    InvalidCommand,
    ConflictingStage,
    StaleToken,
    PendingReply,
    Protocol(SelectableProtocolError),
    Catalog(SelectableCatalogError),
    ReplyQueue(LiveWhiteboxError),
    Panic(Box<dyn Any + Send>),
}

impl std::fmt::Debug for ResetRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

impl std::fmt::Display for ResetRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCommand => formatter.write_str("invalid correlated reset command"),
            Self::ConflictingStage => formatter.write_str("correlated reset stage is occupied"),
            Self::StaleToken => formatter.write_str("correlated reset token is stale"),
            Self::PendingReply => formatter.write_str("selectable reply is already queued"),
            Self::Protocol(source) => std::fmt::Display::fmt(source, formatter),
            Self::Catalog(source) => std::fmt::Display::fmt(source, formatter),
            Self::ReplyQueue(source) => std::fmt::Display::fmt(source, formatter),
            Self::Panic(payload) => formatter
                .debug_tuple("correlated reset panic")
                .field(&(**payload).type_id())
                .finish(),
        }
    }
}

impl std::error::Error for ResetRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(source) => Some(source),
            Self::Catalog(source) => Some(source),
            Self::ReplyQueue(source) => Some(source),
            _ => None,
        }
    }
}

impl ResetRefusal {
    fn status(&self) -> c_int {
        match self {
            Self::InvalidCommand | Self::Protocol(_) => -libc::EINVAL,
            Self::ConflictingStage | Self::PendingReply => -libc::EBUSY,
            Self::StaleToken => -libc::ESTALE,
            Self::Catalog(_) | Self::ReplyQueue(_) => -libc::EIO,
            Self::Panic(_) => -libc::EFAULT,
        }
    }
}

impl ResetSettlement {
    pub(super) fn blocks_restore(&self) -> bool {
        matches!(self.phase, ResetPhase::Prepared | ResetPhase::Failed)
    }

    fn refuse(&mut self, failure: ResetRefusal) -> c_int {
        if self.failure.is_none() {
            self.failure = Some(failure);
        }
        self.phase = ResetPhase::Failed;
        self.failure
            .as_ref()
            .map_or(-libc::EFAULT, ResetRefusal::status)
    }
}

impl LiveSelectableState {
    pub(in crate::runtime::live_whitebox) fn register_reset_owner(
        &mut self,
        plugin_id: crate::QemuPluginId,
    ) -> Result<(), LiveWhiteboxError> {
        super::super::api::register_selectable_reset_owner(
            plugin_id,
            native_reset_callback,
            std::ptr::from_mut(self).cast(),
        )
    }

    fn reset_prepare(
        &mut self,
        request: &NativeResetRequest,
        bytes: &[u8],
    ) -> Result<(), ResetRefusal> {
        if self.reset.blocks_restore() {
            return Err(ResetRefusal::ConflictingStage);
        }
        if request.schema_version != 1
            || request.correlation == 0
            || request.correlation <= self.reset.correlation
        {
            return Err(ResetRefusal::InvalidCommand);
        }
        let decoded = SelectionRequest::decode(bytes).map_err(ResetRefusal::Protocol)?;
        let encoded = decoded.encode().map_err(ResetRefusal::Protocol)?;
        if encoded != bytes || decoded.sequence() != request.request_sequence {
            return Err(ResetRefusal::InvalidCommand);
        }
        let pending = self
            .catalog
            .pending_request()
            .ok_or(ResetRefusal::StaleToken)?;
        let coordinate = pending.coordinate();
        let range = pending.reply_range();
        if pending.request() != &decoded
            || coordinate.raw_icount() != request.raw_icount
            || coordinate.tick_ps() != request.trap_tick_ps
            || coordinate.vcpu_index() != request.vcpu_index
            || range.guest_address() != request.reply_address
            || range.len() != decoded.reply_capacity()
        {
            return Err(ResetRefusal::StaleToken);
        }
        if self
            .reply_input
            .has_reply()
            .map_err(ResetRefusal::ReplyQueue)?
        {
            return Err(ResetRefusal::PendingReply);
        }

        // Clone only the real retained token after complete identity validation.
        // Its private incarnation Arc is shared, never recreated from scalars.
        let retained = pending.clone();
        self.reset.pending = Some(retained);
        self.reset.canonical = encoded;
        self.reset.correlation = request.correlation;
        self.reset.phase = ResetPhase::Prepared;
        self.reset.failure = None;
        Ok(())
    }

    fn reset_check(
        &mut self,
        request: &NativeResetRequest,
        bytes: &[u8],
    ) -> Result<(), ResetRefusal> {
        if self.reset.phase != ResetPhase::Prepared || self.reset.correlation != request.correlation
        {
            return Err(ResetRefusal::ConflictingStage);
        }
        let retained = self
            .reset
            .pending
            .as_ref()
            .ok_or(ResetRefusal::StaleToken)?;
        let coordinate = retained.coordinate();
        if self.catalog.pending_request() != Some(retained)
            || request.schema_version != 1
            || request.request_sequence != retained.request().sequence()
            || request.raw_icount != coordinate.raw_icount()
            || request.trap_tick_ps != coordinate.tick_ps()
            || request.vcpu_index != coordinate.vcpu_index()
            || request.reply_address != retained.reply_range().guest_address()
            || bytes != self.reset.canonical
        {
            return Err(ResetRefusal::StaleToken);
        }
        if self
            .reply_input
            .has_reply()
            .map_err(ResetRefusal::ReplyQueue)?
        {
            return Err(ResetRefusal::PendingReply);
        }
        Ok(())
    }

    fn reset_commit(
        &mut self,
        request: &NativeResetRequest,
        bytes: &[u8],
    ) -> Result<(), ResetRefusal> {
        self.reset_check(request, bytes)?;
        let retained = self
            .reset
            .pending
            .as_ref()
            .ok_or(ResetRefusal::StaleToken)?;
        self.catalog
            .abandon_request_after_reset(retained)
            .map_err(ResetRefusal::Catalog)?;
        self.reset.phase = ResetPhase::Committed;
        Ok(())
    }

    fn reset_action(
        &mut self,
        action: u32,
        request: &NativeResetRequest,
        bytes: &[u8],
    ) -> Result<(), ResetRefusal> {
        match action {
            PREPARE => self.reset_prepare(request, bytes),
            CHECK => self.reset_check(request, bytes),
            COMMIT => self.reset_commit(request, bytes),
            _ => Err(ResetRefusal::InvalidCommand),
        }
    }
}

/// Contains all panics within the GPL callback and retains the original payload.
///
/// Native serializes the callback with BQL and its operation mutex, retaining
/// this published live owner and the request byte loan for the entire call.
pub(in crate::runtime::live_whitebox) extern "C" fn native_reset_callback(
    action: u32,
    request: *const NativeResetRequest,
    userdata: *mut c_void,
) -> c_int {
    let (Some(request), Some(mut state)) = (
        NonNull::new(request.cast_mut()),
        NonNull::new(userdata.cast::<LiveSelectableState>()),
    ) else {
        return -libc::EINVAL;
    };
    // SAFETY: the registrar binds the published process-lifetime owner. Native
    // holds BQL and its operation mutex, so no callback or unload can alias it.
    let state = unsafe { state.as_mut() };
    // SAFETY: native lends this exact repr(C) object for the callback duration.
    let request = unsafe { request.as_ref() };
    if request.request_length == 0
        || request.request_length > SELECTABLE_MESSAGE_MAX_BYTES
        || request.request.is_null()
    {
        return state.reset.refuse(ResetRefusal::InvalidCommand);
    }
    // SAFETY: the published native owner retains all request_length bytes.
    let bytes = unsafe { std::slice::from_raw_parts(request.request, request.request_length) };
    match catch_unwind(AssertUnwindSafe(|| {
        state.reset_action(action, request, bytes)
    })) {
        Ok(Ok(())) => 0,
        Ok(Err(failure)) => state.reset.refuse(failure),
        Err(payload) => state.reset.refuse(ResetRefusal::Panic(payload)),
    }
}

#[cfg(test)]
mod tests;
