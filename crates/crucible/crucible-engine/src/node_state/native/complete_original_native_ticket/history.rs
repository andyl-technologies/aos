//! Borrows a ticket's historical edge to its actual shared archive Source.
//!
//! The shared Source body is defined once by the enclosing archive graph. This
//! view repeats no archive/content owner and has no decoder or live constructor.
//! The retained Prepare request owns the signed parent-index full reference;
//! the ticket cannot invent one from the archive's different manifest reference.

use super::*;
use crate::node_contract::restored_owner_history::{
    OriginalRestoredOwnerCapacityAliases, OriginalRestoredOwnerCapacityRow,
};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use std::cell::RefCell;

/// Borrows historical ticket facts while preserving their actual Source relation.
///
/// This nonconstructible DATA loan supplies neither a ticket nor a restoration
/// context. The whole historical writer must encode its shared Source definition
/// once and use the same precharged alias bank for every ticket edge.
pub struct CompleteOriginalNativeTicketHistory<'a> {
    ticket: &'a CompleteOriginalNativeTicket,
    source: &'a CompleteOriginalRestorationSource,
    owner: &'a NativeOwnerState,
    journal: &'a ContentRef,
}

impl CompleteOriginalNativeTicket {
    /// Borrows the exact ticket index and authenticated historical owner roles.
    ///
    /// This performs no parsing, hashing, allocation or target-context check.
    /// Old source identity stays historical DATA; it is never a fresh permit.
    ///
    /// # Errors
    /// Refuses another process/thread or Source allocation, a missing owner, or
    /// an ambiguous, unsettled or inconsistent administrative journal role.
    pub fn borrowed_settled_history_data<'a>(
        &'a self,
        source: &'a CompleteOriginalRestorationSource,
    ) -> Result<CompleteOriginalNativeTicketHistory<'a>, RuntimeError> {
        self.authenticate_source(source)?;
        let owner = self.owner()?;
        let journal = self.original_restoration_journal_reference_data()?;
        self.authenticate_source(source)?;
        Ok(CompleteOriginalNativeTicketHistory {
            ticket: self,
            source,
            owner,
            journal,
        })
    }

    /// Names the complete direct historical ticket loan and shared-row headers.
    pub fn settled_history_counter_scratch_data() -> usize {
        use std::cell::{BorrowMutError, RefMut};
        use std::mem::size_of;

        Self::original_restoration_journal_counter_scratch_data()
            + size_of::<CompleteOriginalNativeTicketHistory<'static>>()
            + size_of::<Result<CompleteOriginalNativeTicketHistory<'static>, RuntimeError>>()
            + size_of::<TicketHistory<'static, 'static>>()
            + size_of::<OriginalRestoredOwnerCapacityRow>()
            + size_of::<Result<OriginalRestoredOwnerCapacityRow, RuntimeError>>()
            + size_of::<RefMut<'static, OriginalRestoredOwnerCapacityAliases>>()
            + size_of::<Result<RefMut<'static, OriginalRestoredOwnerCapacityAliases>, BorrowMutError>>(
            )
            + size_of::<Result<RefMut<'static, OriginalRestoredOwnerCapacityAliases>, RuntimeError>>(
            )
            + size_of::<&CompleteOriginalNativeTicket>()
            + size_of::<&CompleteOriginalRestorationSource>()
            + size_of::<&NativeOwnerState>()
            + size_of::<&ContentRef>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<(
                &CompleteOriginalNativeTicket,
                &CompleteOriginalRestorationSource,
                &NativeOwnerState,
                &ContentRef,
            )>()
    }
}

impl<'a> CompleteOriginalNativeTicketHistory<'a> {
    /// Links this actual ticket edge through the whole graph's same alias bank.
    pub(crate) fn with_aliases<'view>(
        &'view self,
        aliases: &'view RefCell<OriginalRestoredOwnerCapacityAliases>,
    ) -> impl Serialize + 'view {
        TicketHistory {
            data: self,
            aliases,
        }
    }
}

struct TicketHistory<'view, 'source> {
    data: &'view CompleteOriginalNativeTicketHistory<'source>,
    aliases: &'view RefCell<OriginalRestoredOwnerCapacityAliases>,
}

impl Serialize for TicketHistory<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;

        let CompleteOriginalNativeTicketHistory {
            ticket,
            source,
            owner,
            journal,
        } = self.data;
        ticket
            .authenticate_source(source)
            .map_err(S::Error::custom)?;
        if !std::ptr::eq(ticket.owner().map_err(S::Error::custom)?, *owner)
            || ticket
                .original_restoration_journal_reference_data()
                .map_err(S::Error::custom)?
                != *journal
        {
            return Err(S::Error::custom(RuntimeError::ForeignAuthority));
        }
        let edge = self
            .aliases
            .try_borrow_mut()
            .map_err(|_| S::Error::custom(RuntimeError::OwnerBusy))?
            .shared_owner_data(&source.inner)
            .map_err(S::Error::custom)?;

        let mut value = serializer.serialize_struct("CompleteOriginalNativeTicketHistory", 9)?;
        value.serialize_field(
            "schema",
            "source-private.complete-original-native-ticket-history/1",
        )?;
        value.serialize_field("source_role", "complete_original_source")?;
        value.serialize_field("source_edge", &edge)?;
        value.serialize_field("owner_index", &ticket.owner_index)?;
        value.serialize_field("owner", &owner.owner)?;
        value.serialize_field("key", &owner.key)?;
        value.serialize_field("runtime_object", source.inner.runtime_object())?;
        value.serialize_field("journal", journal)?;
        value.serialize_field("manifest", source.inner.archive().artifact())?;
        let completed = value.end()?;
        ticket
            .authenticate_source(source)
            .map_err(S::Error::custom)?;
        Ok(completed)
    }
}
