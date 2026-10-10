//! Original pre-command observation and native-consumed initial ACK custody.
//!
//! The explicit constructor contract retains two fixed original datagrams and
//! their pre-dequeue credits. Native historical getters authenticate the known
//! root and acquired epoch; the portable observation additionally matches the
//! complete preparation and actually retained Applied receipt. No callback or
//! native writer is admitted by these records.

// SPDX-License-Identifier: GPL-2.0-or-later

use super::{PrefixPolicy, SemanticPrefixOwner, SourcePrefixRootSeal, State};
use crate::native_node_control::administrative_inbox::{
    NativeAdministrativeInbox, NativeAdministrativeInboxError,
};
use crate::native_node_control::administrative_mailbox::NativeAdministrativeReplyCredit;
use crucible_protocol::node_control::{
    NativeCommandError, NativeFrame, NativePrefixPreparationAcknowledgement,
    NativePrefixPreparationFacts,
};
use std::ffi::{c_int, c_void};
use std::sync::{Arc, TryLockError};

// All native fields have fixed scalar extents and no invalid Rust bit patterns.
// Alignment matches the source structs. Endian conversion below is explicit;
// these native storage objects remain inside the GPL process.
#[repr(C, align(8))]
struct NativeStorage<const N: usize>([u8; N]);

impl<const N: usize> Default for NativeStorage<N> {
    fn default() -> Self {
        Self([0; N])
    }
}

type QueryFacts =
    extern "C" fn(*const SourcePrefixRootSeal, *mut c_void, *mut NativeStorage<640>) -> c_int;
type QueryAcknowledgement =
    extern "C" fn(*const SourcePrefixRootSeal, *mut c_void, *mut NativeStorage<160>) -> c_int;

pub(super) struct SourceApi {
    pub(super) register_contract: extern "C" fn(u32, *const PrefixPolicy) -> c_int,
    query_facts: QueryFacts,
    query_acknowledgement: QueryAcknowledgement,
}

impl SourceApi {
    pub(super) fn resolve() -> Option<Self> {
        macro_rules! symbol {
            ($name:literal, $signature:ty) => {{
                // SAFETY: The static export name selects the exact native ACK6
                // declaration; absent symbols refuse only this opt-in contract.
                let pointer = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if pointer.is_null() {
                    return None;
                }
                // SAFETY: The source signature and aligned scalar storage extent
                // match the reviewed ACK6 header. Pointers stay GPL-local.
                unsafe { std::mem::transmute::<*mut c_void, $signature>(pointer) }
            }};
        }
        Some(Self {
            register_contract: symbol!(
                c"qemu_plugin_register_crucible_prefix_preparation_contract",
                extern "C" fn(u32, *const PrefixPolicy) -> c_int
            ),
            query_facts: symbol!(
                c"qemu_plugin_crucible_node_query_original_prefix_preparation",
                QueryFacts
            ),
            query_acknowledgement: symbol!(
                c"qemu_plugin_crucible_node_query_original_prefix_preparation_acknowledgement",
                QueryAcknowledgement
            ),
        })
    }
}

struct PhysicalReply {
    cursor: u64,
    credit: Option<NativeAdministrativeReplyCredit>,
    retained: bool,
    published: bool,
}

struct Original {
    frame: NativeFrame,
    cursor: u64,
    credit: Option<NativeAdministrativeReplyCredit>,
    reply: Option<NativeFrame>,
    retained: bool,
    published: bool,
    repeated: Option<PhysicalReply>,
}

impl Original {
    fn admit_repeated(
        &mut self,
        actor: &NativeAdministrativeInbox,
        cursor: u64,
        frame: &NativeFrame,
    ) -> Result<bool, NativeCommandError> {
        if self.frame != *frame {
            return Err(NativeCommandError::Conflict);
        }
        if self.cursor == cursor {
            self.published = false;
            return Ok(true);
        }
        // Every physical datagram has its own pre-dequeue reply storage. An
        // equal request recovers the immutable native history; its new cursor
        // cannot replace the original request or acquire native ACK authority.
        if self.reply.is_none() || !self.retained || !self.published {
            return Ok(false);
        }
        if let Some(repeated) = &mut self.repeated {
            if repeated.cursor == cursor {
                repeated.published = false;
                return Ok(true);
            }
            if !repeated.published {
                return Ok(false);
            }
        }
        let credit = match actor.reserve_construction_reply(cursor) {
            Ok(credit) => credit,
            Err(NativeAdministrativeInboxError::Busy) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        self.repeated = Some(PhysicalReply {
            cursor,
            credit: Some(credit),
            retained: false,
            published: false,
        });
        Ok(true)
    }

    fn publish(&mut self, actor: &NativeAdministrativeInbox) -> Result<(), NativeCommandError> {
        let Some(reply) = &self.reply else {
            return Ok(());
        };
        if !self.retained {
            match actor.retain_construction_reply(&mut self.credit, reply) {
                Ok(()) => self.retained = true,
                Err(NativeAdministrativeInboxError::Busy) => return Ok(()),
                Err(_) => return Err(NativeCommandError::Conflict),
            }
        }
        if !self.published {
            match actor.send_reply(self.cursor) {
                Ok(published) => self.published = published,
                Err(NativeAdministrativeInboxError::Busy) => {}
                Err(_) => return Err(NativeCommandError::Conflict),
            }
        }
        if let Some(repeated) = &mut self.repeated {
            if !repeated.retained {
                match actor.retain_construction_reply(&mut repeated.credit, reply) {
                    Ok(()) => repeated.retained = true,
                    Err(NativeAdministrativeInboxError::Busy) => return Ok(()),
                    Err(_) => return Err(NativeCommandError::Conflict),
                }
            }
            if !repeated.published {
                match actor.send_reply(repeated.cursor) {
                    Ok(published) => repeated.published = published,
                    Err(NativeAdministrativeInboxError::Busy) => {}
                    Err(_) => return Err(NativeCommandError::Conflict),
                }
            }
        }
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct Journal {
    query: Option<Original>,
    acknowledgement: Option<Original>,
}

impl Journal {
    pub(super) fn acknowledged(&self) -> bool {
        self.acknowledgement.as_ref().is_some_and(|original| {
            original.retained
                && matches!(
                    original.reply,
                    Some(NativeFrame::PrefixPreparationAcknowledged(_))
                )
        })
    }

    pub(super) fn pending(&self) -> bool {
        [self.query.as_ref(), self.acknowledgement.as_ref()]
            .into_iter()
            .flatten()
            .any(|original| {
                !original.published
                    || original
                        .repeated
                        .as_ref()
                        .is_some_and(|repeated| !repeated.published)
            })
    }
}

impl SemanticPrefixOwner {
    /// Retains the same initial-contract packet and credit before native exposure.
    ///
    /// # Errors
    /// Refuses an unselected contract, foreign owner or changed historical body.
    /// Temporary ownership leaves the original packet pending without consumption.
    pub(crate) fn try_admit_initial_preparation(
        &self,
        actor: &Arc<NativeAdministrativeInbox>,
        cursor: u64,
    ) -> Result<bool, NativeCommandError> {
        if self.process_id != std::process::id()
            || self.preparation_api.is_none()
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
        if state.failed {
            return Err(NativeCommandError::Conflict);
        }
        let frame = match actor.original_frame(cursor) {
            Ok(frame) => frame,
            Err(NativeAdministrativeInboxError::Busy) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        let existing = match &frame {
            NativeFrame::QueryPrefixPreparation {
                scope,
                prefix_preparation,
            } if *scope == self.policy.original_effect.digests[0]
                && *prefix_preparation == self.policy.prefix_preparation_commitment =>
            {
                &mut state.preparation.query
            }
            NativeFrame::AcknowledgePrefixPreparation(offered) => {
                let facts = match state
                    .preparation
                    .query
                    .as_ref()
                    .and_then(|query| query.reply.as_ref())
                {
                    Some(NativeFrame::PrefixPreparationFacts(facts)) => facts,
                    _ => return Err(NativeCommandError::Conflict),
                };
                let Some(initialization) = crate::native_node_control::registered_owner()
                    .ok_or(NativeCommandError::Conflict)?
                    .try_semantic_initialization_receipt()?
                else {
                    return Ok(false);
                };
                let observation = facts.observe_original(&self.preparation, &initialization)?;
                if *offered != NativePrefixPreparationAcknowledgement::from_original(&observation)?
                {
                    return Err(NativeCommandError::Conflict);
                }
                &mut state.preparation.acknowledgement
            }
            _ => return Err(NativeCommandError::Conflict),
        };
        if let Some(original) = existing {
            return original.admit_repeated(actor, cursor, &frame);
        }
        let credit = match actor.reserve_construction_reply(cursor) {
            Ok(credit) => credit,
            Err(NativeAdministrativeInboxError::Busy) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        *existing = Some(Original {
            frame,
            cursor,
            credit: Some(credit),
            reply: None,
            retained: false,
            published: false,
            repeated: None,
        });
        Ok(true)
    }

    /// Recovers native original initial facts and consumed ACK on the sole reader.
    ///
    /// # Errors
    /// Refuses changed native records or owner correlation. Every temporary Busy
    /// retains the original packet, epoch and pre-dequeue reply credit.
    pub(crate) fn recover_initial_preparation(&self) -> Result<(), NativeCommandError> {
        if self.process_id != std::process::id() {
            return Err(NativeCommandError::Conflict);
        }
        let Some(api) = &self.preparation_api else {
            return Ok(());
        };
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
        if let Some(query) = &mut state.preparation.query {
            if query.reply.is_none() {
                let mut native = NativeStorage::<640>::default();
                let status = (api.query_facts)(root, epoch, &mut native);
                if status == -libc::EAGAIN {
                    return Ok(());
                }
                if status != 0 {
                    return Err(NativeCommandError::Conflict);
                }
                let facts = NativePrefixPreparationFacts::decode(&canonical_facts(native.0))?;
                let Some(initialization) = crate::native_node_control::registered_owner()
                    .ok_or(NativeCommandError::Conflict)?
                    .try_semantic_initialization_receipt()?
                else {
                    return Ok(());
                };
                facts.observe_original(&self.preparation, &initialization)?;
                query.reply = Some(NativeFrame::PrefixPreparationFacts(Box::new(facts)));
            }
            query.publish(actor)?;
        }
        if let Some(original) = &mut state.preparation.acknowledgement {
            if original.reply.is_none() {
                let mut native = NativeStorage::<160>::default();
                let status = (api.query_acknowledgement)(root, epoch, &mut native);
                if status == -libc::EAGAIN {
                    return Ok(());
                }
                if status != 0 {
                    return Err(NativeCommandError::Conflict);
                }
                let mut canonical = native.0;
                canonicalize32(&mut canonical, &[0, 4]);
                canonicalize64(&mut canonical, &[136, 144, 152]);
                let consumed = NativePrefixPreparationAcknowledgement::decode_record(&canonical)?;
                if original.frame != NativeFrame::AcknowledgePrefixPreparation(consumed.clone()) {
                    return Err(NativeCommandError::Conflict);
                }
                original.reply = Some(NativeFrame::PrefixPreparationAcknowledged(consumed));
            }
            original.publish(actor)?;
        }
        Ok(())
    }

    pub(super) fn preparation_request(
        &self,
        state: &State,
        _epoch: *mut c_void,
    ) -> Result<Option<super::request::NativeRequest>, c_int> {
        let Some(original) = &state.preparation.acknowledgement else {
            return Ok(None);
        };
        if original.reply.is_some() {
            return Ok(None);
        }
        let credit = original.credit.as_ref().ok_or(-libc::ESTALE)?;
        match self.original_actor()?.validate_unpublished_credit(credit) {
            Ok(()) => {}
            Err(NativeAdministrativeInboxError::Busy) => return Err(-libc::EAGAIN),
            Err(_) => return Err(-libc::ESTALE),
        }
        let NativeFrame::AcknowledgePrefixPreparation(ack) = &original.frame else {
            return Err(-libc::ESTALE);
        };
        Ok(Some(super::request::NativeRequest::preparation(ack)))
    }
}

fn canonical_facts(mut bytes: [u8; 640]) -> [u8; 640] {
    canonicalize32(
        &mut bytes,
        &[
            0, 4, 8, 12, 312, 316, 320, 324, 328, 332, 336, 340, 344, 348, 512, 516, 624, 628, 632,
            636,
        ],
    );
    canonicalize64(
        &mut bytes,
        &[
            272, 280, 288, 296, 304, 352, 360, 496, 504, 552, 560, 568, 576, 584, 592, 600, 608,
            616,
        ],
    );
    bytes
}

fn canonicalize32(bytes: &mut [u8], offsets: &[usize]) {
    for &offset in offsets {
        let mut scalar = [0; 4];
        scalar.copy_from_slice(&bytes[offset..offset + 4]);
        bytes[offset..offset + 4].copy_from_slice(&u32::from_ne_bytes(scalar).to_be_bytes());
    }
}

fn canonicalize64(bytes: &mut [u8], offsets: &[usize]) {
    for &offset in offsets {
        let mut scalar = [0; 8];
        scalar.copy_from_slice(&bytes[offset..offset + 8]);
        bytes[offset..offset + 8].copy_from_slice(&u64::from_ne_bytes(scalar).to_be_bytes());
    }
}

#[cfg(test)]
#[path = "preparation_tests.rs"]
mod tests;
