//! Retains the genuine original group and its host-authored historical scope.
//!
//! The three independently decoded parent occurrences must name exactly one
//! original archive. Shared immutable ancestry earns no allocation refund.

use super::super::initial15_history::{HistoricalInitial15Scope17, Initial15ScopeMember17};
use super::*;
use crate::node_adapters::cnp::OriginalInitial15ArchivedGroup;

impl RetainedCold17Collection {
    /// Completes one original group and scope beneath three exact parent occurrences.
    ///
    /// # Errors
    /// Refuses changed parents, spent output, incomplete original custody,
    /// malformed history or any independently admitted constructor failure.
    pub(super) fn read_initial15_group_data(
        &mut self,
        scope: &CompleteRestoredSettledArchiveValidation<'_>,
    ) -> Result<(), StateError> {
        if self.parents.len() != 3
            || self.initial15_group.is_some()
            || self.historical_scope.is_some()
        {
            return Err(refused(
                "cold17 original group roster is incomplete or spent",
            ));
        }
        let first = self.parents[0]
            .as_ref()
            .ok_or_else(|| refused("cold17 first parent occurrence absent"))?
            .parts_data()?;
        for parent in &self.parents[1..] {
            let parent = parent
                .as_ref()
                .ok_or_else(|| refused("cold17 parent occurrence absent"))?
                .parts_data()?;
            if parent.0 != first.0 || parent.1.artifact != first.1.artifact {
                return Err(refused("cold17 members name different original archives"));
            }
        }
        let source_index = RestoredArchive17SourceIndex::from_data(2)?;
        let prefix = scope.terminal_prefix_retained_storage_data()?;
        let group_additional = self
            .terminal_cache
            .checked_sub(prefix)
            .ok_or_else(|| refused("cold17 original group enclosing cache overflow"))?;
        let Self {
            parents,
            initial15_group,
            terminal_cache,
            ..
        } = self;
        let parent = parents[2]
            .as_ref()
            .ok_or_else(|| refused("cold17 final parent occurrence absent"))?
            .borrow_data(scope)?;
        *terminal_cache = OriginalInitial15ArchivedGroup::read_into_with_terminal_data(
            &parent,
            scope,
            source_index,
            0,
            *terminal_cache,
            group_additional,
            initial15_group,
        )
        .map_err(|_| refused("cold17 original Initial15 group refused"))?;

        let Self {
            members,
            parents,
            initial15_group,
            historical_scope,
            terminal_cache,
            ..
        } = self;
        let parent = parents[2]
            .as_ref()
            .ok_or_else(|| refused("cold17 final parent occurrence absent"))?
            .borrow_data(scope)?;
        let group = initial15_group
            .as_ref()
            .ok_or_else(|| refused("cold17 original Initial15 group absent"))?;
        let members = [
            historical_member_data(&members[0])?,
            historical_member_data(&members[1])?,
            historical_member_data(&members[2])?,
        ];
        let scope_additional = terminal_cache
            .checked_sub(prefix)
            .ok_or_else(|| refused("cold17 historical scope enclosing cache overflow"))?;
        *terminal_cache = HistoricalInitial15Scope17::read_historical_scope_into(
            &parent,
            group,
            scope,
            source_index,
            0,
            *terminal_cache,
            &members,
            scope_additional,
            historical_scope,
        )?;
        self.authenticate_archive_data(scope.archive)
            .map_err(crate::node_state::schema)?;
        scope.validation_origin.authenticate(scope.archive)?;
        // All new partials already reside in this collection. The next Source
        // prewalk admits its own census; no unadmitted recursive walk runs here.
        Ok(())
    }
}

fn historical_member_data(
    member: &[RetainedCold17Member],
) -> Result<Initial15ScopeMember17<'_>, StateError> {
    let [member] = member else {
        return Err(refused("cold17 historical member absent"));
    };
    Ok(Initial15ScopeMember17 {
        node: member
            .node
            .as_ref()
            .ok_or_else(|| refused("cold17 historical Node absent"))?,
        prelude: member
            .prelude
            .as_ref()
            .ok_or_else(|| refused("cold17 historical first component absent"))?,
        native: member
            .native
            .as_ref()
            .ok_or_else(|| refused("cold17 historical native owner absent"))?,
        ancestry: member
            .ancestry
            .as_ref()
            .ok_or_else(|| refused("cold17 historical ancestry absent"))?,
    })
}
