//! Original offered ACK and continuation custody beside consumed native history.
//!
//! Each datagram owns a separate pre-dequeue reply credit. Getter copies expose
//! only retained requests; replies require authentic native consumed-ACK or
//! typed-result getters. Resending an original is historical recovery only.

// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(not(test))]
use super::PrefixPolicy;
use super::{
    NativeEffectPosition, SemanticPrefixOwner, SourcePrefixEffectCut, SourcePrefixRootSeal, State,
};
use crate::native_node_control::administrative_inbox::{
    NativeAdministrativeInbox, NativeAdministrativeInboxError,
};
use crate::native_node_control::administrative_mailbox::NativeAdministrativeReplyCredit;
use crucible_node_contract::U64;
use crucible_protocol::node_control::{
    NativeCommandError, NativeFrame, NativePrefixAcknowledgement, NativePrefixProgress,
};
use std::ffi::{c_int, c_void};
use std::sync::{Arc, TryLockError};

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub(super) struct NativeAcknowledgement {
    version: u32,
    size: u32,
    scope: [u8; 32],
    preparation: [u8; 32],
    grant: [u8; 32],
    command: [u8; 32],
    result: [u8; 32],
    sequence: u64,
    cut_id: u64,
    acknowledgement_sequence: u64,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub(super) struct NativeRequest {
    version: u32,
    size: u32,
    kind: u32,
    reserved: u32,
    acknowledgement: NativeAcknowledgement,
    cursor: NativeEffectPosition,
}

pub(super) type QueryAcknowledgement = extern "C" fn(
    *const SourcePrefixRootSeal,
    *mut c_void,
    *const SourcePrefixEffectCut,
    *mut NativeAcknowledgement,
) -> c_int;

pub(super) struct OriginalRequest {
    pub(super) frame: NativeFrame,
    native: NativeRequest,
    pub(super) credit: Option<NativeAdministrativeReplyCredit>,
    pub(super) cursor: u64,
    pub(super) cut_handle: usize,
    pub(super) cut_id: Option<u64>,
    pub(super) reply: Option<NativeFrame>,
    replied: bool,
    pub(super) published: bool,
}

impl OriginalRequest {
    pub(super) fn matches_continuation_cut(&self, id: u64, handle: usize) -> bool {
        id > 1
            && handle != 0
            && self.native.kind == 2
            && self.cut_id == Some(id)
            && self.cut_handle == handle
            && matches!(self.frame, NativeFrame::ContinuePrefix(_))
    }
}

impl NativeRequest {
    pub(super) fn preparation(
        ack: &crucible_protocol::node_control::NativePrefixPreparationAcknowledgement,
    ) -> Self {
        // Request232's closed union begins with ACK160. The last 56 inactive
        // bytes remain zero; the three native u64s occupy the result field of
        // the older ACK192 view. No pointer or Rust enum crosses this ABI.
        let mut scalar_tail = [0; 32];
        for (offset, value) in [
            (0, ack.initialization_sequence),
            (8, ack.epoch_incarnation),
            (16, ack.acknowledgement_sequence),
        ] {
            scalar_tail[offset..offset + 8].copy_from_slice(&value.get().to_ne_bytes());
        }
        Self {
            version: 1,
            size: 232,
            kind: 3,
            reserved: 0,
            acknowledgement: NativeAcknowledgement {
                version: 1,
                size: 160,
                scope: ack.scope,
                preparation: ack.prefix_preparation,
                grant: ack.facts_digest,
                command: ack.initialization_cut,
                result: scalar_tail,
                ..Default::default()
            },
            cursor: NativeEffectPosition::default(),
        }
    }
}

impl NativeAcknowledgement {
    fn original(ack: &NativePrefixAcknowledgement) -> Self {
        Self {
            version: ack.result_version,
            size: 192,
            scope: ack.scope,
            preparation: ack.prefix_preparation,
            grant: ack.grant_digest,
            command: ack.command_digest,
            result: ack.result_digest,
            sequence: ack.sequence.get(),
            cut_id: ack.cut_id.get(),
            acknowledgement_sequence: ack.acknowledgement_sequence.get(),
        }
    }

    fn portable(self) -> Result<NativePrefixAcknowledgement, NativeCommandError> {
        if self.size != 192 {
            return Err(NativeCommandError::Conflict);
        }
        let ack = NativePrefixAcknowledgement {
            result_version: self.version,
            scope: self.scope,
            prefix_preparation: self.preparation,
            grant_digest: self.grant,
            command_digest: self.command,
            result_digest: self.result,
            sequence: U64::new(self.sequence),
            cut_id: U64::new(self.cut_id),
            acknowledgement_sequence: U64::new(self.acknowledgement_sequence),
        };
        ack.encode()?;
        Ok(ack)
    }
}

impl SemanticPrefixOwner {
    /// Retains a validated original request and its real reply credit before exposure.
    ///
    /// # Errors
    /// Refuses foreign original identity, missing native-consumed ACK, conflicting
    /// history or exhausted preallocated request storage. Busy stays pending.
    pub(crate) fn try_admit_request(
        &self,
        actor: &Arc<NativeAdministrativeInbox>,
        cursor: u64,
    ) -> Result<bool, NativeCommandError> {
        if self.process_id != std::process::id() {
            return Err(NativeCommandError::Conflict);
        }
        if !Arc::ptr_eq(
            self.original_actor()
                .map_err(|_| NativeCommandError::Conflict)?,
            actor,
        ) {
            return Err(NativeCommandError::Conflict);
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        if state.failed {
            return Err(NativeCommandError::Conflict);
        }
        let frame = match actor.original_frame(cursor) {
            Ok(frame) => frame,
            Err(NativeAdministrativeInboxError::Busy) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        if let Some(original) = state
            .requests
            .iter_mut()
            .find(|original| original.frame == frame)
        {
            original.published = false;
            return Ok(true);
        }
        if state
            .requests
            .iter()
            .any(|original| original.reply.is_none())
        {
            return Ok(false);
        }
        if state.requests.len() == self.policy.maximum_prefixes as usize * 2 {
            return Err(NativeCommandError::ResourceLimit);
        }
        let (ack, expected, kind) = match &frame {
            NativeFrame::AcknowledgePrefix(ack) => (ack, NativeEffectPosition::default(), 1),
            NativeFrame::ContinuePrefix(continuation) => (
                &continuation.acknowledgement,
                super::position(continuation.expected_cursor),
                2,
            ),
            _ => return Err(NativeCommandError::Conflict),
        };
        if ack.prefix_preparation != self.policy.prefix_preparation_commitment
            || ack.scope != self.policy.original_effect.digests[0]
        {
            return Err(NativeCommandError::Conflict);
        }
        let cut_handle = validate_predecessor(&state, &frame, ack)?;
        if kind == 2 && !state.requests.iter().any(|request|
            matches!(&request.reply, Some(NativeFrame::PrefixAcknowledged(consumed)) if consumed == ack))
        { return Err(NativeCommandError::Conflict); }
        let credit = match actor.reserve_construction_reply(cursor) {
            Ok(credit) => credit,
            Err(NativeAdministrativeInboxError::Busy) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        let native = NativeRequest {
            version: 1,
            size: 232,
            kind,
            reserved: 0,
            acknowledgement: NativeAcknowledgement::original(ack),
            cursor: expected,
        };
        let id = if kind == 1 {
            Some(ack.cut_id.get())
        } else {
            None
        };
        state.requests.push(OriginalRequest {
            frame,
            native,
            credit: Some(credit),
            cursor,
            cut_handle: if kind == 1 { cut_handle } else { 0 },
            cut_id: id,
            reply: None,
            replied: false,
            published: false,
        });
        Ok(true)
    }

    /// Recovers consumed ACKs and typed prefixes from exact native history only.
    ///
    /// # Errors
    /// Refuses native contradictions or changed result correlation. Busy retains
    /// the same request, source handles and reply credit without receiving again.
    pub(crate) fn recover_original_requests(&self) -> Result<(), NativeCommandError> {
        if self.process_id != std::process::id() {
            return Err(NativeCommandError::Conflict);
        }
        let actor = self
            .original_actor()
            .map_err(|_| NativeCommandError::Conflict)?;
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Ok(()),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        if state.failed {
            return Err(NativeCommandError::Conflict);
        }
        if !state.acquired {
            return Ok(());
        }
        let root = state.root as *const SourcePrefixRootSeal;
        let epoch = std::ptr::from_mut(state.epoch.as_mut()).cast::<c_void>();
        for index in 0..state.requests.len() {
            if state.requests[index].reply.is_none() {
                let request = &state.requests[index];
                if request.cut_handle == 0 {
                    continue;
                }
                let cut = request.cut_handle as *const SourcePrefixEffectCut;
                let reply = match &request.frame {
                    NativeFrame::AcknowledgePrefix(offered) => {
                        let mut native = NativeAcknowledgement::default();
                        let result =
                            (self.api.query_acknowledgement)(root, epoch, cut, &mut native);
                        if result == -libc::EAGAIN {
                            continue;
                        }
                        if result != 0 {
                            return Err(NativeCommandError::Conflict);
                        }
                        let consumed = native.portable()?;
                        if consumed != *offered {
                            return Err(NativeCommandError::Conflict);
                        }
                        NativeFrame::PrefixAcknowledged(consumed)
                    }
                    NativeFrame::ContinuePrefix(continuation) => {
                        let mut native = super::typed_result::NativeResult::default();
                        let result = (self.api.query_typed_result)(root, epoch, cut, &mut native);
                        if result == -libc::EAGAIN {
                            continue;
                        }
                        if result != 0 {
                            return Err(NativeCommandError::Conflict);
                        }
                        let result = native.portable()?;
                        if request.cut_id != Some(result.cut_id.get())
                            || result.previous_cut_id != continuation.acknowledgement.cut_id
                        {
                            return Err(NativeCommandError::Conflict);
                        }
                        validate_typed_history(&state, &result)?;
                        NativeFrame::PrefixProgress(Box::new(result))
                    }
                    _ => return Err(NativeCommandError::Conflict),
                };
                state.requests[index].reply = Some(reply);
            }
            let request = &mut state.requests[index];
            let reply = request.reply.as_ref().ok_or(NativeCommandError::Conflict)?;
            if !request.replied {
                match actor.retain_construction_reply(&mut request.credit, reply) {
                    Ok(()) => request.replied = true,
                    Err(NativeAdministrativeInboxError::Busy) => continue,
                    Err(_) => return Err(NativeCommandError::Conflict),
                }
            }
            if !request.published {
                match actor.send_reply(request.cursor) {
                    Ok(sent) => request.published = sent,
                    Err(NativeAdministrativeInboxError::Busy) => {}
                    Err(_) => return Err(NativeCommandError::Conflict),
                }
            }
        }
        Ok(())
    }
}

fn validate_predecessor(
    state: &State,
    frame: &NativeFrame,
    ack: &NativePrefixAcknowledgement,
) -> Result<usize, NativeCommandError> {
    let command = state.command.as_ref().ok_or(NativeCommandError::Conflict)?;
    if let Some(initial) = &command.result
        && initial.cut_id == ack.cut_id
    {
        match frame {
            NativeFrame::AcknowledgePrefix(_) => ack.validate_initial(initial)?,
            NativeFrame::ContinuePrefix(continuation) => continuation.validate_initial(initial)?,
            _ => return Err(NativeCommandError::Conflict),
        }
        return Ok(command.cut_handle);
    }
    for request in &state.requests {
        if let Some(NativeFrame::PrefixProgress(result)) = &request.reply
            && result.cut_id == ack.cut_id
        {
            match frame {
                NativeFrame::AcknowledgePrefix(_) => ack.validate_progress(result)?,
                NativeFrame::ContinuePrefix(continuation) => {
                    continuation.validate_progress(result)?
                }
                _ => return Err(NativeCommandError::Conflict),
            }
            return Ok(request.cut_handle);
        }
    }
    Err(NativeCommandError::Conflict)
}

fn validate_typed_history(
    state: &State,
    result: &NativePrefixProgress,
) -> Result<(), NativeCommandError> {
    let command = state.command.as_ref().ok_or(NativeCommandError::Conflict)?;
    if let Some(initial) = &command.result
        && result.previous_cut_id == initial.cut_id
    {
        return result.validate_after_initial(&command.compute, initial);
    }
    for request in &state.requests {
        if let Some(NativeFrame::PrefixProgress(previous)) = &request.reply
            && previous.cut_id == result.previous_cut_id
        {
            return result.validate_after_progress(&command.compute, previous);
        }
    }
    Err(NativeCommandError::Conflict)
}

/// Copies the retained original request without accepting or evaluating it.
///
/// # Safety
/// Source supplies known acquired epoch, exact registered process-life userdata
/// and aligned writable Request232 storage. The callback zeros every refusal.
type Getter = unsafe extern "C" fn(
    epoch: *mut c_void,
    output: *mut NativeRequest,
    userdata: *mut c_void,
) -> c_int;
/// Registers the source-only getter against the retained original policy.
///
/// # Safety
/// Native installation copies the callback and retains its original userdata
/// for process life. Source invokes it only with its known acquired epoch and
/// aligned writable output; registration provides no request or effect authority.
#[cfg(not(test))]
pub(super) type RegisterGetter = extern "C" fn(*const PrefixPolicy, Getter, *mut c_void) -> c_int;

/// Copies the same retained request only while the source owns the acquired epoch.
///
/// # Safety
/// Native code authenticates its known epoch and installed userdata before the
/// call. Output is aligned writable Request232 storage retained synchronously.
pub(super) unsafe extern "C" fn get_request(
    epoch: *mut c_void,
    output: *mut NativeRequest,
    userdata: *mut c_void,
) -> c_int {
    if output.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Native supplies complete aligned writable output for this call.
    unsafe {
        output.write(NativeRequest::default());
    }
    if userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Native retains the exact process-life registered owner allocation.
    let owner = unsafe { &*userdata.cast::<SemanticPrefixOwner>() };
    if owner.process_id != std::process::id() {
        return -libc::ESTALE;
    }
    let mut state = match super::try_callback_journal(&owner.state) {
        Ok(state) => state,
        Err(error) => return error,
    };
    if state.failed
        || !state.acquired
        || std::ptr::from_mut(state.epoch.as_mut()).cast::<c_void>() != epoch
    {
        return -libc::ESTALE;
    }
    match owner.preparation_request(&state, epoch) {
        Ok(Some(request)) => {
            // SAFETY: Native owns aligned writable Request232 storage for this call.
            unsafe {
                output.write(request);
            }
            return 0;
        }
        Ok(None) => {}
        Err(error) => return error,
    }
    let Some(original) = state
        .requests
        .iter()
        .find(|request| request.reply.is_none())
    else {
        return -libc::EAGAIN;
    };
    let credit = match original.credit.as_ref() {
        Some(credit) => credit,
        None => return -libc::ESTALE,
    };
    let actor = match owner.original_actor() {
        Ok(actor) => actor,
        Err(error) => return error,
    };
    match actor.validate_unpublished_credit(credit) {
        Ok(()) => {}
        Err(NativeAdministrativeInboxError::Busy) => return -libc::EAGAIN,
        Err(_) => return -libc::ESTALE,
    }
    // SAFETY: The original request and separately reserved reply stay retained;
    // the copied native ABI contains only scalar fields, never a wire pointer.
    unsafe {
        output.write(original.native);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn native_request_preserves_inactive_ack_bytes_and_closed_offsets() {
        assert_eq!(size_of::<NativeAcknowledgement>(), 192);
        assert_eq!(size_of::<NativeRequest>(), 232);
        assert_eq!(offset_of!(NativeRequest, acknowledgement), 16);
        assert_eq!(offset_of!(NativeRequest, cursor), 208);
        assert_eq!(offset_of!(NativeAcknowledgement, sequence), 168);
    }

    #[test]
    fn initial_preparation_request_encodes_only_ack160_and_zero_inactive_union() {
        let ack = crucible_protocol::node_control::NativePrefixPreparationAcknowledgement {
            scope: [1; 32],
            prefix_preparation: [2; 32],
            facts_digest: [3; 32],
            initialization_cut: [4; 32],
            initialization_sequence: U64::new(5),
            epoch_incarnation: U64::new(6),
            acknowledgement_sequence: U64::new(1),
        };
        let request = NativeRequest::preparation(&ack);

        assert_eq!(request.kind, 3);
        assert_eq!(request.size, 232);
        assert_eq!(request.acknowledgement.size, 160);
        assert_eq!(&request.acknowledgement.result[..8], &5u64.to_ne_bytes());
        assert_eq!(&request.acknowledgement.result[8..16], &6u64.to_ne_bytes());
        assert_eq!(&request.acknowledgement.result[16..24], &1u64.to_ne_bytes());
        assert_eq!(&request.acknowledgement.result[24..], &[0; 8]);
        assert_eq!(request.acknowledgement.sequence, 0);
        assert_eq!(request.acknowledgement.cut_id, 0);
        assert_eq!(request.acknowledgement.acknowledgement_sequence, 0);
        assert_eq!(request.cursor, NativeEffectPosition::default());
    }

    #[test]
    fn staged_continuation_requires_the_exact_retained_request_kind_and_cut() {
        // Scalar journal metadata exercises admission correlation only. These
        // sentinels issue no native root, epoch, selected cut or callback scope.
        let acknowledgement = NativePrefixAcknowledgement {
            result_version: 1,
            scope: [1; 32],
            prefix_preparation: [2; 32],
            grant_digest: [3; 32],
            command_digest: [4; 32],
            result_digest: [5; 32],
            sequence: U64::new(1),
            cut_id: U64::new(1),
            acknowledgement_sequence: U64::new(1),
        };
        let mut request = OriginalRequest {
            frame: NativeFrame::ContinuePrefix(Box::new(
                crucible_protocol::node_control::NativePrefixContinuation {
                    acknowledgement: acknowledgement.clone(),
                    expected_cursor: crucible_node_contract::Position {
                        time_ps: U64::new(50),
                        microstep: U64::new(0),
                        phase: crucible_node_contract::Phase::Reaction,
                    },
                },
            )),
            native: NativeRequest {
                kind: 2,
                ..Default::default()
            },
            credit: None,
            cursor: 3,
            cut_handle: 11,
            cut_id: Some(2),
            reply: None,
            replied: false,
            published: false,
        };

        assert!(request.matches_continuation_cut(2, 11));
        assert!(!request.matches_continuation_cut(1, 11));
        assert!(!request.matches_continuation_cut(2, 0));
        assert!(!request.matches_continuation_cut(2, 12));
        assert!(!request.matches_continuation_cut(3, 11));

        request.native.kind = 1;
        assert!(!request.matches_continuation_cut(2, 11));
        request.native.kind = 2;
        request.frame = NativeFrame::AcknowledgePrefix(acknowledgement);
        assert!(!request.matches_continuation_cut(2, 11));
    }

    #[test]
    fn refused_original_request_getter_clears_complete_output() {
        let mut output = NativeRequest {
            version: 1,
            size: 232,
            kind: 2,
            acknowledgement: NativeAcknowledgement {
                sequence: 9,
                ..Default::default()
            },
            ..Default::default()
        };
        let getter: Getter = get_request;
        // SAFETY: Output is writable complete storage. Null userdata refuses
        // before any owner/opaque epoch dereference.
        let result = unsafe { getter(std::ptr::null_mut(), &mut output, std::ptr::null_mut()) };
        assert_eq!(result, -libc::EINVAL);
        assert_eq!(output.version, 0);
        assert_eq!(output.acknowledgement.sequence, 0);
        assert_eq!(output.cursor, NativeEffectPosition::default());
    }
}
