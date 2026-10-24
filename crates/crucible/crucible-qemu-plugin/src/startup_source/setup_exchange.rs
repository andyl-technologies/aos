//! Retains the actual framed Hello/HelloAck and its nominal physical slot.
//!
//! Source owns the endpoint, complete frames and canonical creation fields.
//! Movable projections precede Runtime birth; stable destination fields remain
//! inline in its paid Layout. A copied reply records protocol progress only.
// SPDX-License-Identifier: GPL-2.0-only

use super::{InstallerStartupSource, StartupSourceError};
use std::cell::UnsafeCell;

mod abi;
use abi::{Api, Handshake, Slot, Status};

/// Retains movable creation projections and stable Native-written destinations.
#[derive(Default)]
pub(super) struct SetupExchange {
    api: Option<Api>,
    creation: *mut Handshake,
    handshake: *mut Handshake,
    holder: UnsafeCell<*mut Handshake>,
    slot_creation: *mut Slot,
    slot: *mut Slot,
    slot_holder: UnsafeCell<*mut Slot>,
    attempted: bool,
    transfer_attempted: bool,
    slot_attempted: bool,
    slot_transfer_attempted: bool,
    journal: Status,
}

/// Retains physical progress independently of the signed exchange result.
pub(crate) struct ExchangeOutcome {
    /// Records authentic complete write progress even after a signed post refusal.
    pub(crate) write_completed: bool,
    /// Retains validated complete reply facts independently of the signed result.
    pub(crate) reply: Option<crucible_qemu_protocol::NegotiatedHandshake>,
    /// Preserves the initiating exchange cause before the independent caller post.
    pub(crate) result: Result<(), StartupSourceError>,
}

impl SetupExchange {
    fn observe(&mut self, id: u64, api: Api) -> Result<(), StartupSourceError> {
        let mut output = Status::default();
        let status = (api.observe)(id, self.handshake, &mut output);
        native_status(status)?;
        if output.schema_version != 1
            || usize::try_from(output.struct_size).ok() != Some(std::mem::size_of::<Status>())
            || output.write_completed > 1
            || output.read_completed > 1
            || output.reply_validated > 1
        {
            return Err(StartupSourceError::Ownership {
                reason: "setup exchange progress layout differs",
            });
        }
        self.journal = output;
        Ok(())
    }

    fn exchange(&mut self, id: u64, api: Api) -> Result<(), StartupSourceError> {
        if self.attempted {
            return Err(StartupSourceError::Ownership {
                reason: "initial exchange cannot replay",
            });
        }
        self.attempted = true;
        self.api = Some(api);
        let first = (api.write)(id, &mut self.creation);
        self.handshake = self.creation;
        let observed = if self.handshake.is_null() {
            Err(StartupSourceError::Ownership {
                reason: "initial exchange has no born owner",
            })
        } else {
            self.observe(id, api)
        };
        native_status(first)?;
        observed?;
        let first = (api.read)(id, self.handshake);
        let observed = self.observe(id, api);
        // Save consumed read progress even if its independent post refused.
        native_status(first)?;
        observed
    }
}

impl InstallerStartupSource {
    /// Performs the one authentic initial exchange without repeating Setup I/O.
    pub(crate) fn exchange_setup(&self) -> ExchangeOutcome {
        let refused = |source| ExchangeOutcome {
            write_completed: false,
            reply: None,
            result: Err(source),
        };
        if let Err(source) = self.check() {
            return refused(source);
        }
        let api = match Api::resolve() {
            Ok(api) => api,
            Err(source) => return refused(source),
        };
        let Ok(mut exchange) = self.setup_exchange.try_lock() else {
            return refused(StartupSourceError::Ownership {
                reason: "setup exchange is busy or poisoned",
            });
        };
        let result = exchange.exchange(self.plugin_id, api);
        let journal = exchange.journal;
        drop(exchange);
        let post = self.check();
        ExchangeOutcome {
            write_completed: journal.write_completed == 1,
            reply: (journal.reply_validated == 1 && journal.read_completed == 1).then_some(
                crucible_qemu_protocol::NegotiatedHandshake {
                    proto_version: crucible_qemu_protocol::CONTROL_PROTOCOL_VERSION,
                    abi_version: crucible_qemu_shmem::ABI_VERSION,
                    slot_index: journal.selected_slot,
                    node_count: journal.node_count,
                },
            ),
            result: result.and(post),
        }
    }

    /// Creates actual slot custody from Source's retained exchange and VMA.
    ///
    /// # Errors
    /// Retains born output and parents on any constructor or independent post refusal.
    pub(super) fn create_setup_slot(
        &self,
        mapping: *mut super::setup_mapping::NativeMapping,
    ) -> Result<(), StartupSourceError> {
        self.check()?;
        let mut exchange =
            self.setup_exchange
                .try_lock()
                .map_err(|_| StartupSourceError::Ownership {
                    reason: "setup exchange is busy or poisoned",
                })?;
        if exchange.slot_attempted {
            return Err(StartupSourceError::Ownership {
                reason: "setup slot creation cannot repeat",
            });
        }
        let api = exchange.api.ok_or(StartupSourceError::Ownership {
            reason: "setup exchange API absent",
        })?;
        exchange.slot_attempted = true;
        let handshake = exchange.handshake;
        let first = (api.create_slot)(
            self.plugin_id,
            handshake,
            mapping,
            &mut exchange.slot_creation,
        );
        exchange.slot = exchange.slot_creation;
        let slot = exchange.slot;
        drop(exchange);
        let post = self.check();
        native_status(first)?;
        post?;
        if slot.is_null() {
            return Err(StartupSourceError::Ownership {
                reason: "setup slot output absent",
            });
        }
        native_status((api.current_slot)(self.plugin_id, slot))
    }

    /// Moves both nominal parent loans into this same paid pinned Runtime.
    ///
    /// # Safety
    /// This Source is already inside the paid pinned Runtime after completion enrollment.
    ///
    /// # Errors
    /// Preserves moved fields even when an independent transfer post refuses.
    pub(super) unsafe fn transfer_setup_exchange(&self) -> Result<(), StartupSourceError> {
        let runtime = self.setup_mapping_runtime_purpose()?;
        let mut exchange =
            self.setup_exchange
                .try_lock()
                .map_err(|_| StartupSourceError::Ownership {
                    reason: "setup exchange is busy or poisoned",
                })?;
        let Some(api) = exchange.api else {
            #[cfg(test)]
            if self.model_setup.is_some() {
                return Ok(());
            }
            return Err(StartupSourceError::Ownership {
                reason: "setup exchange API absent",
            });
        };
        if exchange.transfer_attempted || exchange.creation.is_null() {
            return Err(StartupSourceError::Ownership {
                reason: "setup exchange transfer has no unused creation",
            });
        }
        exchange.transfer_attempted = true;
        let field = exchange.holder.get();
        let first = (api.transfer)(self.plugin_id, runtime, &mut exchange.creation, field);
        native_status(first)?;
        if !exchange.creation.is_null() {
            return Err(StartupSourceError::Ownership {
                reason: "setup exchange transfer did not consume projection",
            });
        }
        exchange.slot_transfer_attempted = true;
        let field = exchange.slot_holder.get();
        let first =
            (api.transfer_slot)(self.plugin_id, runtime, &mut exchange.slot_creation, field);
        native_status(first)?;
        if !exchange.slot_creation.is_null() {
            return Err(StartupSourceError::Ownership {
                reason: "setup slot transfer did not consume projection",
            });
        }
        native_status((api.current_slot)(self.plugin_id, exchange.slot))
    }

    /// Returns physical slot before exchange, only after every mapped user ends.
    ///
    /// # Safety
    /// The caller ends all view and child uses first; refusal preserves Runtime.
    pub(super) unsafe fn return_setup_exchange(&self) -> bool {
        let Ok(mut exchange) = self.setup_exchange.try_lock() else {
            return false;
        };
        let Some(api) = exchange.api else {
            return !exchange.attempted;
        };
        if exchange.slot_attempted {
            let canonical = exchange.slot_transfer_attempted && exchange.slot_creation.is_null();
            let field = if canonical {
                exchange.slot_holder.get()
            } else {
                &mut exchange.slot_creation
            };
            if exchange.slot.is_null() || (api.return_slot)(self.plugin_id, field) != 0 {
                return false;
            }
            exchange.slot = std::ptr::null_mut();
            exchange.slot_attempted = false;
        }
        if exchange.attempted {
            let canonical = exchange.transfer_attempted && exchange.creation.is_null();
            let field = if canonical {
                exchange.holder.get()
            } else {
                &mut exchange.creation
            };
            if exchange.handshake.is_null() || (api.return_handshake)(self.plugin_id, field) != 0 {
                return false;
            }
            exchange.handshake = std::ptr::null_mut();
            exchange.attempted = false;
        }
        true
    }
}

fn native_status(status: i32) -> Result<(), StartupSourceError> {
    if status == 0 {
        Ok(())
    } else {
        Err(StartupSourceError::NativeStatus { status })
    }
}
