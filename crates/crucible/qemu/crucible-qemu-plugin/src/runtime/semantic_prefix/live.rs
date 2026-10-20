//! Backed original command and live-request admission and historical recovery.
//!
//! Only RR executes the native transition. This reader retains the same
//! original request/credit and copies native results; no packet issues Ready.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::{OriginalCommand, PrefixPolicy, SemanticPrefixOwner, SourcePrefixRootSeal};
use crate::native_node_control::administrative_inbox::{
    NativeAdministrativeInbox, NativeAdministrativeInboxError,
};
use crucible_qemu_protocol::node_control::{
    ExecutionKind, NativeCommandError, NativeFrame, NativeLiveIdentity, NativeQuietCommand,
    NativeRetirementCommitted, NativeRetirementProposal, NativeRetirementReceipt,
};
use std::ffi::{c_int, c_void};
use std::sync::{Arc, TryLockError};

#[derive(Clone, PartialEq, Eq)]
#[repr(C, align(8))]
pub(super) struct Request([u8; 312]);

/// Lends an original request to the native owner through its registered callback.
///
/// # Safety
/// Callers retain the registered owner and acquired input epoch, and supply a
/// complete aligned writable Request for the duration of the callback.
pub(super) type Getter = unsafe extern "C" fn(*mut c_void, *mut Request, *mut c_void) -> c_int;
type Query = extern "C" fn(
    *const SourcePrefixRootSeal,
    *mut c_void,
    *const Request,
    *mut u32,
    *mut u32,
    *mut u8,
    u32,
) -> c_int;

pub(super) struct Api {
    pub(super) register_contract: extern "C" fn(u32, *const PrefixPolicy) -> c_int,
    pub(super) register_getter: extern "C" fn(*const PrefixPolicy, Getter, *mut c_void) -> c_int,
    query: Query,
}

impl Api {
    pub(super) fn resolve() -> Option<Self> {
        macro_rules! symbol {
            ($name:literal, $signature:ty) => {{
                // SAFETY: Static NUL-terminated export names select exact GPL-local declarations.
                let pointer = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if pointer.is_null() { return None; }
                // SAFETY: Request312/output952 are aligned native-only storage with exact signatures.
                unsafe { std::mem::transmute::<*mut c_void, $signature>(pointer) }
            }};
        }
        Some(Self {
            register_contract: symbol!(
                c"qemu_plugin_register_crucible_prefix_live_contract",
                extern "C" fn(u32, *const PrefixPolicy) -> c_int
            ),
            register_getter: symbol!(
                c"qemu_plugin_register_crucible_prefix_live_getter",
                extern "C" fn(*const PrefixPolicy, Getter, *mut c_void) -> c_int
            ),
            query: symbol!(
                c"qemu_plugin_crucible_node_query_original_prefix_live",
                Query
            ),
        })
    }
}

#[derive(Default)]
pub(super) struct Journal {
    originals: [Option<super::preparation::Original>; 4],
    quiet: Option<NativeQuietCommand>,
    proposal: Option<NativeRetirementProposal>,
    receipt: Option<NativeRetirementReceipt>,
    committed: Option<NativeRetirementCommitted>,
}

impl Journal {
    pub(super) fn pending(&self) -> bool {
        self.originals
            .iter()
            .flatten()
            .any(|original| original.pending())
    }
}

fn slot(frame: &NativeFrame) -> Result<usize, NativeCommandError> {
    match frame {
        NativeFrame::QuietAdvance(_) => Ok(0),
        NativeFrame::RetireOriginal(_) => Ok(1),
        NativeFrame::AcceptTerminal(_) => Ok(2),
        NativeFrame::AcknowledgeRetirement(_) => Ok(3),
        _ => Err(NativeCommandError::Conflict),
    }
}

impl SemanticPrefixOwner {
    /// Retains the sole reader's immutable command and reply credit before effects.
    ///
    /// # Errors
    /// Rejects foreign inbox/preparation, widened budgets or conflicting retries.
    pub(crate) fn try_admit(
        &self,
        actor: &Arc<NativeAdministrativeInbox>,
        cursor: u64,
    ) -> Result<bool, NativeCommandError> {
        if self.process_id != std::process::id() {
            return Err(NativeCommandError::Conflict);
        }
        let control =
            crate::native_node_control::registered_owner().ok_or(NativeCommandError::Conflict)?;
        if !control
            .original_administrative_actor()
            .is_some_and(|original| Arc::ptr_eq(original, actor))
        {
            return Err(NativeCommandError::Conflict);
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Ok(false),
            Err(TryLockError::Poisoned(_)) => return Err(NativeCommandError::Conflict),
        };
        if state.failed || (self.preparation_api.is_some() && !state.preparation.acknowledged()) {
            return Err(NativeCommandError::Conflict);
        }
        let frame = match actor.original_frame(cursor) {
            Ok(frame) => frame,
            Err(NativeAdministrativeInboxError::Busy) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        let crucible_qemu_protocol::node_control::NativeFrame::EffectCompute(compute) = frame
        else {
            return Err(NativeCommandError::Conflict);
        };
        compute.validate()?;
        if compute.effect_preparation != self.policy.prefix_preparation_commitment
            || compute.maximum_callbacks > self.policy.original_effect.callbacks
            || compute.maximum_service_span.get() > self.policy.original_effect.maximum_span
        {
            state.failed = true;
            return Err(NativeCommandError::Conflict);
        }
        if let Some(original) = state.command.as_mut() {
            if original.compute != *compute {
                state.failed = true;
                return Err(NativeCommandError::Conflict);
            }
            original.published = false;
            return Ok(true);
        }
        // The genuine RR preparation hold can borrow this same inbox ledger.
        // Contention keeps the original packet and pre-dequeue reply allowance;
        // it must not turn an administrative retry into permanent quarantine.
        let credit = match actor.reserve_construction_reply(cursor) {
            Ok(credit) => credit,
            Err(NativeAdministrativeInboxError::Busy) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        let digest = compute.command.identity_digest()?;
        state.journal.retain(compute.command.clone())?;
        state.command = Some(OriginalCommand {
            compute: *compute,
            digest,
            credit: Some(credit),
            cursor,
            cut_handle: 0,
            result: None,
            replied: false,
            published: false,
            cut_id: None,
        });
        Ok(true)
    }

    /// Retains the same original live request beside genuine pre-dequeue reply credit.
    ///
    /// # Errors
    /// Refuses unselected/foreign/failed ownership, changed originals or missing commit.
    pub(crate) fn try_admit_live(
        &self,
        actor: &Arc<NativeAdministrativeInbox>,
        cursor: u64,
    ) -> Result<bool, NativeCommandError> {
        if self.live_api.is_none()
            || self.process_id != std::process::id()
            || !Arc::ptr_eq(
                self.original_actor()
                    .map_err(|_| NativeCommandError::Conflict)?,
                actor,
            )
        {
            return Err(NativeCommandError::Conflict);
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        if state.failed || !state.acquired || !state.preparation.acknowledged() {
            return Err(NativeCommandError::Conflict);
        }
        let frame = match actor.original_frame(cursor) {
            Ok(frame) => frame,
            Err(NativeAdministrativeInboxError::Busy) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        let index = slot(&frame)?;
        if let Some(original) = &mut state.live.originals[index]
            && original.frame == frame
        {
            return original.admit_repeated(actor, cursor, &frame);
        }
        if let NativeFrame::QuietAdvance(quiet) = &frame {
            quiet.validate()?;
            let committed = state
                .live
                .committed
                .clone()
                .ok_or(NativeCommandError::Conflict)?;
            if quiet.predecessor_commit != committed.digest()
                || quiet.preparation != self.policy.prefix_preparation_commitment
            {
                return Err(NativeCommandError::Conflict);
            }
            if state.live.quiet.as_ref() != Some(quiet.as_ref()) {
                // The same native committed predecessor fences real bank reuse.
                // The existing bounded journal keeps operation/grant tombstones.
                state.journal.retain(quiet.command.clone())?;
                state.live = Journal {
                    quiet: Some((**quiet).clone()),
                    committed: Some(committed.clone()),
                    ..Default::default()
                };
            }
        }
        if let Some(original) = &mut state.live.originals[index] {
            return original.admit_repeated(actor, cursor, &frame);
        }
        let credit = match actor.reserve_construction_reply(cursor) {
            Ok(credit) => credit,
            Err(NativeAdministrativeInboxError::Busy) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        state.live.originals[index] = Some(super::preparation::Original::with_credit(
            frame, cursor, credit,
        ));
        Ok(true)
    }

    /// Recovers actual retained source history on the sole administrative reader.
    ///
    /// # Errors
    /// Refuses changed source/operation/archive lineage; native Busy stays pending.
    pub(crate) fn recover_live(&self) -> Result<(), NativeCommandError> {
        let Some(api) = &self.live_api else {
            return Ok(());
        };
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
        for index in 0..4 {
            let Some(original) = state.live.originals[index].as_ref() else {
                continue;
            };
            if original.reply.is_none() {
                let request = Request::from_original(&original.frame, epoch)?;
                let mut kind = 0;
                let mut length = 0;
                let mut bytes = [0; 952];
                let status = (api.query)(
                    root,
                    epoch,
                    &request,
                    &mut kind,
                    &mut length,
                    bytes.as_mut_ptr(),
                    952,
                );
                if status == -libc::EAGAIN {
                    continue;
                }
                if status != 0 || length as usize > bytes.len() {
                    return Err(NativeCommandError::Conflict);
                }
                let reply = match kind {
                    45 if index == 0 => {
                        let result =
                            crucible_qemu_protocol::node_control::NativeQuietProgress::decode(
                                &bytes[..length as usize],
                            )?;
                        result.validate_original(
                            state
                                .live
                                .quiet
                                .as_ref()
                                .ok_or(NativeCommandError::Conflict)?,
                            self.process_id,
                        )?;
                        NativeFrame::QuietProgress(Box::new(result))
                    }
                    47 if index == 1 => {
                        let proposal = NativeRetirementProposal::decode(&bytes[..length as usize])?;
                        let NativeFrame::RetireOriginal(offered) = &original.frame else {
                            return Err(NativeCommandError::Conflict);
                        };
                        if proposal.identity()? != offered.identity {
                            return Err(NativeCommandError::Conflict);
                        }
                        state.live.proposal = Some(proposal.clone());
                        NativeFrame::RetirementProposed(Box::new(proposal))
                    }
                    49 if index == 2 => {
                        let receipt = NativeRetirementReceipt::decode(&bytes[..length as usize])?;
                        let NativeFrame::AcceptTerminal(offered) = &original.frame else {
                            return Err(NativeCommandError::Conflict);
                        };
                        receipt.validate_original(
                            state
                                .live
                                .proposal
                                .as_ref()
                                .ok_or(NativeCommandError::Conflict)?,
                            offered.archive_digest,
                        )?;
                        state.live.receipt = Some(receipt.clone());
                        NativeFrame::RetirementReceipt(Box::new(receipt))
                    }
                    51 if index == 3 => {
                        let committed =
                            NativeRetirementCommitted::decode(&bytes[..length as usize])?;
                        let NativeFrame::AcknowledgeRetirement(offered) = &original.frame else {
                            return Err(NativeCommandError::Conflict);
                        };
                        committed.validate_original(
                            state
                                .live
                                .receipt
                                .as_ref()
                                .ok_or(NativeCommandError::Conflict)?,
                            offered.archive_digest,
                        )?;
                        let proposal = state
                            .live
                            .proposal
                            .as_ref()
                            .ok_or(NativeCommandError::Conflict)?;
                        let identity = proposal.identity()?;
                        let reached = proposal.current()?.position()?;
                        let authorization = state
                            .journal
                            .original(identity.sequence)
                            .ok_or(NativeCommandError::Conflict)?
                            .authorization_digest;
                        state
                            .journal
                            .record_native_stop(identity.sequence, reached)?;
                        state
                            .journal
                            .acknowledge(identity.sequence, &authorization)?;
                        state.live.committed = Some(committed.clone());
                        NativeFrame::RetirementCommitted(Box::new(committed))
                    }
                    _ => return Err(NativeCommandError::Conflict),
                };
                state.live.originals[index]
                    .as_mut()
                    .ok_or(NativeCommandError::Conflict)?
                    .reply = Some(reply);
            }
            state.live.originals[index]
                .as_mut()
                .ok_or(NativeCommandError::Conflict)?
                .publish(actor)?;
        }
        Ok(())
    }
}

impl Request {
    fn from_original(frame: &NativeFrame, epoch: *mut c_void) -> Result<Self, NativeCommandError> {
        if std::mem::size_of::<usize>() != 8 {
            return Err(NativeCommandError::Conflict);
        }
        let mut bytes = [0; 312];
        native32(&mut bytes, 0, 1);
        native32(&mut bytes, 4, 312);
        match frame {
            NativeFrame::QuietAdvance(quiet) => {
                quiet.validate()?;
                native32(&mut bytes, 8, 1);
                let identity = NativeLiveIdentity::from_command(&quiet.command, quiet.preparation)?;
                let command = &quiet.command;
                let b = &mut bytes[16..];
                native32(b, 0, 1);
                native32(b, 4, 224);
                native32(
                    b,
                    8,
                    if matches!(command.kind, ExecutionKind::BoundarySettle { .. }) {
                        2
                    } else {
                        1
                    },
                );
                native64(b, 16, command.sequence.get());
                b[24..56].copy_from_slice(&identity.scope);
                b[56..88].copy_from_slice(&identity.preparation);
                b[88..120].copy_from_slice(&command.authorization_digest);
                b[120..152].copy_from_slice(&identity.command);
                // Native-only original epoch pointer; never a process wire field.
                b[152..160].copy_from_slice(&(epoch as usize).to_ne_bytes());
                native_position(b, 160, command.kind.start());
                native_position(b, 184, command.kind.limit());
                b[224..256].copy_from_slice(&quiet.predecessor_commit);
            }
            NativeFrame::RetireOriginal(offered) => {
                native32(&mut bytes, 8, 2);
                native_identity(&mut bytes[16..120], &offered.identity)?;
                bytes[120..312].copy_from_slice(&offered.final_acknowledgement);
                if offered.final_acknowledgement != [0; 192] {
                    for at in [0, 4] {
                        let value = u32::from_be_bytes(
                            offered.final_acknowledgement[at..at + 4]
                                .try_into()
                                .map_err(|_| NativeCommandError::Conflict)?,
                        );
                        native32(&mut bytes, 120 + at, value);
                    }
                    for at in [168, 176, 184] {
                        let value = u64::from_be_bytes(
                            offered.final_acknowledgement[at..at + 8]
                                .try_into()
                                .map_err(|_| NativeCommandError::Conflict)?,
                        );
                        native64(&mut bytes, 120 + at, value);
                    }
                }
            }
            NativeFrame::AcceptTerminal(offered) | NativeFrame::AcknowledgeRetirement(offered) => {
                native32(
                    &mut bytes,
                    8,
                    if matches!(frame, NativeFrame::AcceptTerminal(_)) {
                        3
                    } else {
                        4
                    },
                );
                native_identity(&mut bytes[16..120], &offered.identity)?;
                bytes[120..152].copy_from_slice(&offered.native_digest);
                bytes[152..184].copy_from_slice(&offered.archive_digest);
            }
            _ => return Err(NativeCommandError::Conflict),
        }
        Ok(Self(bytes))
    }
}

fn native32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_ne_bytes());
}
fn native64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_ne_bytes());
}
fn native_identity(
    bytes: &mut [u8],
    identity: &NativeLiveIdentity,
) -> Result<(), NativeCommandError> {
    bytes.copy_from_slice(&identity.encode()?);
    native64(bytes, 96, identity.sequence.get());
    Ok(())
}
fn native_position(bytes: &mut [u8], at: usize, position: crucible_node_format::Position) {
    native64(bytes, at, position.time_ps.get());
    native64(bytes, at + 8, position.microstep.get());
    native32(
        bytes,
        at + 16,
        match position.phase {
            crucible_node_format::Phase::BoundaryControl => 0,
            crucible_node_format::Phase::Publication => 1,
            crucible_node_format::Phase::Delivery => 2,
            crucible_node_format::Phase::Reaction => 3,
        },
    );
}

/// Lends only a retained original request beside already reserved reply storage.
///
/// # Safety
/// Source supplies its exact acquired epoch, process-life owner and aligned
/// complete Request312 storage. Every refusal clears that output.
pub(super) unsafe extern "C" fn get_request(
    epoch: *mut c_void,
    output: *mut Request,
    userdata: *mut c_void,
) -> c_int {
    if output.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Source supplies complete aligned writable storage for this call.
    unsafe {
        output.write(Request([0; 312]));
    }
    if userdata.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: Irreversible registration retains this exact original owner.
    let owner = unsafe { &*userdata.cast::<SemanticPrefixOwner>() };
    if owner.process_id != std::process::id() || owner.runtime().is_err() {
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
    let Some(original) = state
        .live
        .originals
        .iter()
        .flatten()
        .find(|original| original.reply.is_none())
    else {
        return -libc::EAGAIN;
    };
    let actor = match owner.original_actor() {
        Ok(actor) => actor,
        Err(error) => return error,
    };
    let Some(credit) = &original.credit else {
        return -libc::ESTALE;
    };
    match actor.validate_unpublished_credit(credit) {
        Ok(()) => {}
        Err(NativeAdministrativeInboxError::Busy) => return -libc::EAGAIN,
        Err(_) => return -libc::ESTALE,
    }
    let request = match Request::from_original(&original.frame, epoch) {
        Ok(request) => request,
        Err(_) => return -libc::ESTALE,
    };
    // SAFETY: Native storage is complete and the original credit remains owned.
    unsafe {
        output.write(request);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::U64;
    use crucible_qemu_protocol::node_control::NativeLiveAccept;

    #[test]
    fn live_native_request_extent_offsets_and_inactive_bytes_are_closed() {
        let identity = NativeLiveIdentity {
            scope: [1; 32],
            preparation: [2; 32],
            command: [3; 32],
            sequence: U64::new(4),
        };
        let frame = NativeFrame::AcceptTerminal(NativeLiveAccept {
            identity,
            native_digest: [5; 32],
            archive_digest: [6; 32],
        });
        let request = Request::from_original(&frame, std::ptr::null_mut());
        assert!(request.is_ok());
        let Ok(request) = request else {
            return;
        };
        assert_eq!(std::mem::size_of::<Request>(), 312);
        assert_eq!(&request.0[..4], &1u32.to_ne_bytes());
        assert_eq!(&request.0[4..8], &312u32.to_ne_bytes());
        assert_eq!(&request.0[8..12], &3u32.to_ne_bytes());
        assert_eq!(&request.0[112..120], &4u64.to_ne_bytes());
        assert_eq!(&request.0[120..152], &[5; 32]);
        assert_eq!(&request.0[152..184], &[6; 32]);
        assert_eq!(&request.0[184..], &[0; 128]);
    }

    #[test]
    fn refused_live_getter_clears_complete_output_before_owner_dereference() {
        let mut request = Request([9; 312]);
        let status = unsafe {
            // SAFETY: Request is complete writable storage. Null userdata refuses
            // before dereferencing any owner, source epoch or native callback.
            get_request(std::ptr::null_mut(), &mut request, std::ptr::null_mut())
        };
        assert_eq!(status, -libc::EINVAL);
        assert_eq!(request.0, [0; 312]);
    }
}
