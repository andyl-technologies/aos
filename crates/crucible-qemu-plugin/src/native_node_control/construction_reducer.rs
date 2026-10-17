//! Original construction effects beneath actual mailbox and initializer custody.
//!
//! The installed construction profile supplies this reducer with its sole inbox
//! and actual registered initializer. Admission reserves the original reply and
//! retains the request before exposing a command to HOME. Source callbacks only
//! recover the original receipt; retries cannot execute callbacks again. This
//! component grants no guest execution, input epoch, output closure or Ready.

use std::sync::{Arc, Mutex};

use crucible_protocol::node_control::{NativeCommandError, NativeFrame};

use super::administrative_inbox::{NativeAdministrativeInbox, NativeAdministrativeInboxError};
use super::administrative_mailbox::NativeAdministrativeReplyCredit;
use super::initialization_custody::InitializationCustody;
use super::preparation_successor_custody::PreparationSuccessorCustody;

const MAXIMUM_CONSTRUCTION_REQUESTS: usize = 1024;

struct OriginalRequest {
    cursor: u64,
    frame: NativeFrame,
    credit: Option<NativeAdministrativeReplyCredit>,
    replied: bool,
    published: bool,
}

struct State {
    requests: Vec<OriginalRequest>,
    maximum_requests: usize,
    failed: bool,
}

/// Retains the actual inbox identity and bounded original initialization requests.
///
/// This reducer must be installed by a separately selected construction profile.
/// A matching scope or reconstructed portable preparation cannot install it.
pub(crate) struct NativeConstructionReducer {
    actor: Arc<NativeAdministrativeInbox>,
    initializer: Arc<InitializationCustody>,
    successor: Option<Arc<PreparationSuccessorCustody>>,
    state: Mutex<State>,
}

impl NativeConstructionReducer {
    /// Reserves every request ledger slot before any original construction effect.
    ///
    /// # Errors
    /// Refuses invalid limits or allocation before changing native admission.
    pub(crate) fn new(
        actor: Arc<NativeAdministrativeInbox>,
        initializer: Arc<InitializationCustody>,
        successor: Option<Arc<PreparationSuccessorCustody>>,
        maximum_requests: usize,
    ) -> Result<Self, NativeCommandError> {
        if actor.scope() != &initializer.scope {
            return Err(NativeCommandError::Conflict);
        }
        if maximum_requests == 0 || maximum_requests > MAXIMUM_CONSTRUCTION_REQUESTS {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut requests = Vec::new();
        requests
            .try_reserve_exact(maximum_requests)
            .map_err(|_| NativeCommandError::ResourceLimit)?;
        Ok(Self {
            actor,
            initializer,
            successor,
            state: Mutex::new(State {
                requests,
                maximum_requests,
                failed: false,
            }),
        })
    }

    /// Admits one already retained original request with backed reply storage.
    ///
    /// The native initializer validates its actual retained source-selected cut.
    /// The inbox cursor and reply credit identify storage, never effect authority.
    /// All requests remain retained after refusal, completion or lost replies.
    /// Returns false when a native callback owns the journal; the sole reader
    /// retains that original cursor and retries it before receiving another frame.
    ///
    /// # Errors
    /// Refuses a foreign inbox, unknown cursor, unsupported request, exhausted
    /// ledger, conflicting original or invalid native initializer transition.
    pub(crate) fn try_admit(
        &self,
        actor: &Arc<NativeAdministrativeInbox>,
        cursor: u64,
    ) -> Result<bool, NativeCommandError> {
        let initializer = &self.initializer;
        if !Arc::ptr_eq(actor, &self.actor) {
            return Err(NativeCommandError::Conflict);
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(false),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(NativeCommandError::Conflict),
        };
        if state.failed {
            return Err(NativeCommandError::Conflict);
        }
        if let Some(index) = state
            .requests
            .iter()
            .position(|entry| entry.cursor == cursor)
        {
            state.requests[index].published = false;
            let waiting_for_successor = matches!(
                state.requests[index].frame,
                NativeFrame::QueryPreparationSuccessor(_)
            );
            return self
                .recover_one(&mut state, initializer, index)
                .map(|recovered| !waiting_for_successor || recovered);
        }
        if state.requests.len() == state.maximum_requests {
            return Err(NativeCommandError::ResourceLimit);
        }

        let frame = match actor.original_frame(cursor) {
            Ok(frame) => frame,
            Err(NativeAdministrativeInboxError::Busy) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        if !matches!(
            frame,
            NativeFrame::QueryInitialization(_)
                | NativeFrame::Initialize(_)
                | NativeFrame::AcknowledgeInitialization(_)
                | NativeFrame::QueryPreparationSuccessor(_)
        ) {
            state.failed = true;
            return Err(NativeCommandError::Conflict);
        }
        let credit = match actor.reserve_construction_reply(cursor) {
            Ok(credit) => credit,
            Err(NativeAdministrativeInboxError::Busy) => return Ok(false),
            Err(_) => return Err(NativeCommandError::Conflict),
        };
        if credit.cursor() != cursor {
            state.failed = true;
            return Err(NativeCommandError::Conflict);
        }

        // No native command can become visible before this original entry and
        // its actual pre-dequeue reply buffer belong to retained custody.
        state.requests.push(OriginalRequest {
            cursor,
            frame,
            credit: Some(credit),
            replied: false,
            published: false,
        });
        let index = state.requests.len() - 1;
        let transition = match &state.requests[index].frame {
            NativeFrame::QueryInitialization(query) => {
                if query.prepared_scope_hash != initializer.scope
                    || query.initialization_commitment != initializer.commitment
                {
                    Err(NativeCommandError::Conflict)
                } else {
                    Ok(true)
                }
            }
            NativeFrame::Initialize(command) => {
                initializer.retain((**command).clone()).map(|_| true)
            }
            NativeFrame::AcknowledgeInitialization(acknowledgement) => {
                initializer.acknowledge(acknowledgement).map(|_| true)
            }
            NativeFrame::QueryPreparationSuccessor(query) => {
                // This cache authenticates the same actual original ACK; it
                // never queries QEMU or substitutes source Applied for ACK.
                match &self.successor {
                    Some(successor) => successor
                        .try_acknowledged_original_chunk(initializer, query)
                        .map(|chunk| chunk.is_some()),
                    None => Err(NativeCommandError::Conflict),
                }
            }
            _ => Err(NativeCommandError::Conflict),
        };
        match transition {
            Ok(true) => {}
            Ok(false) => return Ok(false),
            Err(error) => {
                state.failed = true;
                return Err(error);
            }
        }
        self.recover_one(&mut state, initializer, index)
            .map(|_| true)
    }

    #[cfg(test)]
    fn admit(
        &self,
        actor: &Arc<NativeAdministrativeInbox>,
        cursor: u64,
    ) -> Result<(), NativeCommandError> {
        if self.try_admit(actor, cursor)? {
            Ok(())
        } else {
            Err(NativeCommandError::Conflict)
        }
    }

    /// Publishes only cached original receipts after a real native source stop.
    ///
    /// Returns `false` while original receipts or an inbox lock remain pending.
    /// A busy reader never waits under BQL. No request is received, source cut
    /// sampled or HOME command admitted here. This status grants no authority.
    ///
    /// # Errors
    /// Refuses poisoned custody, previous divergence, missing credit or physical
    /// transport failure. Original native and mailbox custody is retained.
    pub(crate) fn recover(&self) -> Result<bool, NativeCommandError> {
        let initializer = &self.initializer;
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(false),
            Err(std::sync::TryLockError::Poisoned(_)) => return Err(NativeCommandError::Conflict),
        };
        if state.failed || self.actor.scope() != &initializer.scope {
            return Err(NativeCommandError::Conflict);
        }
        let mut complete = true;
        for index in 0..state.requests.len() {
            if !state.requests[index].published {
                complete &= self.recover_one(&mut state, initializer, index)?;
            }
        }
        Ok(complete)
    }

    fn recover_one(
        &self,
        state: &mut State,
        initializer: &InitializationCustody,
        index: usize,
    ) -> Result<bool, NativeCommandError> {
        let original = &mut state.requests[index];
        if original.replied {
            return self.publish_one(original);
        }
        let response = match &original.frame {
            NativeFrame::QueryInitialization(_) => initializer
                .original_cut()
                .map(|cut| NativeFrame::InitializationCut(Box::new(cut))),
            NativeFrame::Initialize(_) => initializer
                .original_receipt()
                .map(|receipt| NativeFrame::InitializationStopped(Box::new(receipt))),
            NativeFrame::AcknowledgeInitialization(acknowledgement) => Some(
                NativeFrame::InitializationAcknowledged(acknowledgement.clone()),
            ),
            NativeFrame::QueryPreparationSuccessor(query) => self
                .successor
                .as_ref()
                .ok_or(NativeCommandError::Conflict)?
                .try_acknowledged_original_chunk(initializer, query)?
                .map(|chunk| NativeFrame::PreparationSuccessorChunk(Box::new(chunk))),
            _ => return Err(NativeCommandError::Conflict),
        };
        let Some(response) = response else {
            return Ok(false);
        };
        match self
            .actor
            .retain_construction_reply(&mut original.credit, &response)
        {
            Ok(()) => {}
            // The original credit remains in the ledger when the native seam
            // cannot acquire the inbox. No source callback waits under BQL.
            Err(NativeAdministrativeInboxError::Busy) => return Ok(false),
            Err(_) => {
                state.failed = true;
                return Err(NativeCommandError::Conflict);
            }
        }
        original.replied = true;
        self.publish_one(original)
    }

    fn publish_one(&self, original: &mut OriginalRequest) -> Result<bool, NativeCommandError> {
        match self.actor.send_reply(original.cursor) {
            Ok(published) => {
                original.published = published;
                Ok(published)
            }
            // Cached receipt custody survives both a busy reader and socket
            // backpressure. Publication retry never repeats the native effect.
            Err(NativeAdministrativeInboxError::Busy) => Ok(false),
            Err(_) => Err(NativeCommandError::Conflict),
        }
    }
}

#[cfg(test)]
#[path = "construction_reducer_tests.rs"]
// crucible-lint: allow panic-shortcut -- Test-only assertions panic on an unmet original preparation invariant.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
