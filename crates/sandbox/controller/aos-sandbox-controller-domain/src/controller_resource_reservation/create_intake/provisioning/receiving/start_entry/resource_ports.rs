//! Names the finite Storage and Mount entrances on the same accepted Start.
//!
//! Each front delegates the sole Root/native stage engine. The immutable
//! prepared purpose and stored genuine immediate predecessor select its own
//! four once-slots; these methods cannot select another payer or Session.

use super::*;
use super::host_root::{OriginalStartHostRootLoanV1, StartRootEntryErrorV1};
use crate::source_domain::ProtectedSourceDomainJournalOwnerV1;
use crate::CreateContinuationIntakeAttemptV1;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

const CLOSED: ResourceReservationErrorV1 = ResourceReservationErrorV1::Conflict;

impl AcceptedStartEntryOriginalV1 {
    /// Opens only the prepared storage child after its stored genuine predecessor.
    ///
    /// # Errors
    /// Retains a changed purpose, unfinished predecessor, native or Root refusal.
    #[doc(hidden)]
    pub fn begin_storage_root_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1, ready: &[u8],
        preparation: &AuthenticatedBrokerMethodOutcomeV1,
        prepared: &PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_once_v2(resource_state::StartResourceKindV2::Storage,
            client, intake, controller, source, ready, preparation, prepared)
    }

    /// Starts this storage child's distinct construction turn.
    ///
    /// # Errors
    /// Refuses changed purpose, reentry, or an incomplete native predecessor.
    #[doc(hidden)]
    pub fn begin_storage_construction_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_turn_v2(resource_state::StartResourceKindV2::Storage,
            client, intake, controller, source, 0)
    }

    /// Starts this storage child's distinct session opening turn.
    ///
    /// # Errors
    /// Refuses changed purpose, reentry, or an incomplete native predecessor.
    #[doc(hidden)]
    pub fn begin_storage_session_opening_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_turn_v2(resource_state::StartResourceKindV2::Storage,
            client, intake, controller, source, 1)
    }

    /// Starts this storage child's distinct io turn.
    ///
    /// # Errors
    /// Refuses changed purpose, reentry, or an incomplete native predecessor.
    #[doc(hidden)]
    pub fn begin_storage_io_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_turn_v2(resource_state::StartResourceKindV2::Storage,
            client, intake, controller, source, 2)
    }

    /// Starts this storage child's distinct final proof turn.
    ///
    /// # Errors
    /// Refuses changed purpose, reentry, or an incomplete native predecessor.
    #[doc(hidden)]
    pub fn begin_storage_final_proof_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_turn_v2(resource_state::StartResourceKindV2::Storage,
            client, intake, controller, source, 3)
    }

    /// Runs the same storage child's C post and independent prepaid Root post.
    ///
    /// # Errors
    /// Retains the original body or first reached post failure without reentry.
    #[doc(hidden)]
    pub fn finish_storage_root_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        controller: &mut Journal,
        body: Result<(), crate::normal_root::RootHostLaunchClientClosedV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.finish_resource_root_turn_once_v2(resource_state::StartResourceKindV2::Storage,
            client, controller, body)
    }

    /// Opens only the prepared mount child after its stored genuine predecessor.
    ///
    /// # Errors
    /// Retains a changed purpose, unfinished predecessor, native or Root refusal.
    #[doc(hidden)]
    pub fn begin_mount_root_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1, ready: &[u8],
        preparation: &AuthenticatedBrokerMethodOutcomeV1,
        prepared: &PreparedStartResourceRequestOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_once_v2(resource_state::StartResourceKindV2::Mount,
            client, intake, controller, source, ready, preparation, prepared)
    }

    /// Starts this mount child's distinct construction turn.
    ///
    /// # Errors
    /// Refuses changed purpose, reentry, or an incomplete native predecessor.
    #[doc(hidden)]
    pub fn begin_mount_construction_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_turn_v2(resource_state::StartResourceKindV2::Mount,
            client, intake, controller, source, 0)
    }

    /// Starts this mount child's distinct session opening turn.
    ///
    /// # Errors
    /// Refuses changed purpose, reentry, or an incomplete native predecessor.
    #[doc(hidden)]
    pub fn begin_mount_session_opening_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_turn_v2(resource_state::StartResourceKindV2::Mount,
            client, intake, controller, source, 1)
    }

    /// Starts this mount child's distinct io turn.
    ///
    /// # Errors
    /// Refuses changed purpose, reentry, or an incomplete native predecessor.
    #[doc(hidden)]
    pub fn begin_mount_io_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_turn_v2(resource_state::StartResourceKindV2::Mount,
            client, intake, controller, source, 2)
    }

    /// Starts this mount child's distinct final proof turn.
    ///
    /// # Errors
    /// Refuses changed purpose, reentry, or an incomplete native predecessor.
    #[doc(hidden)]
    pub fn begin_mount_final_proof_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.begin_resource_root_turn_v2(resource_state::StartResourceKindV2::Mount,
            client, intake, controller, source, 3)
    }

    /// Runs the same mount child's C post and independent prepaid Root post.
    ///
    /// # Errors
    /// Retains the original body or first reached post failure without reentry.
    #[doc(hidden)]
    pub fn finish_mount_root_turn_once_v2(&mut self,
        client: &mut crate::normal_root::RootHostLaunchClientOriginalV1,
        controller: &mut Journal,
        body: Result<(), crate::normal_root::RootHostLaunchClientClosedV1>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.finish_resource_root_turn_once_v2(resource_state::StartResourceKindV2::Mount,
            client, controller, body)
    }

}

impl AcceptedStartEntryOriginalV1 {
    /// Freezes the same Mount final proof's actual original refusal before posts.
    #[doc(hidden)]
    #[must_use]
    pub fn snapshot_mount_final_proof_failure_v2(&mut self,
        client: &crate::normal_root::RootHostLaunchClientOriginalV1,
    ) -> bool {
        let selected = client.selected_original_failure_v1()
            && self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1).is_some();
        if selected { self.resource_entries.mount.turn_native_selected[3] = true; }
        selected
    }

    /// Selects the Mount opening's original Root body cause without native IO.
    #[doc(hidden)]
    #[must_use]
    pub fn mount_root_failure_is_selected_v2(&self) -> bool {
        self.resource_entries.mount.root_selected && !self.resource_entries.mount.root_native_selected
    }

    /// Selects only the actual Mount turn's recorded Root-before or Root-after cause.
    #[doc(hidden)]
    #[must_use]
    pub fn mount_current_turn_root_failure_is_selected_v2(&self) -> bool {
        let Some(index) = self.resource_entries.mount.turn_next.iter().rposition(Option::is_some) else {
            return false;
        };
        if self.resource_entries.mount.turn_next[index].as_ref().is_some_and(Result::is_err)
            || self.resource_entries.mount.turn_native_selected[index]
        {
            return false;
        }
        if let Some(Err(cause)) = &self.resource_entries.mount.turn_before[index] {
            return matches!(cause, StartRootEntryErrorV1::Client(_));
        }
        if self.resource_entries.mount.turn_after[index].as_ref().is_some_and(Result::is_err) {
            return false;
        }
        self.resource_entries.mount.turn_root_after[index].as_ref().is_some_and(Result::is_err)
    }
}

impl OriginalStartHostRootLoanV1<'_, '_> {
    /// Borrows the immutable creation selectors from this Start's actual predecessor.
    ///
    /// # Errors
    /// Refuses changed current C/Source/Start or an unfinished original custody.
    pub(crate) fn creation_workspace_selectors_v2(&self, controller: &Journal)
        -> Result<([u8; 32], [u8; 16]), ResourceReservationErrorV1> {
        self.require_current_v1(controller)?;
        Ok(self.native.predecessor_association_v1()?.creation_workspace_selectors_v2())
    }
}
impl AcceptedStartEntryOriginalV1 {
    /// Freezes the same Storage final proof's actual original refusal before posts.
    #[doc(hidden)]
    #[must_use]
    pub fn snapshot_storage_final_proof_failure_v2(&mut self,
        client: &crate::normal_root::RootHostLaunchClientOriginalV1,
    ) -> bool {
        let selected = client.selected_original_failure_v1()
            && self.native_state.as_ref().and_then(StartNativeStateV1::native_failure_v1).is_some();
        if selected { self.resource_entries.storage.turn_native_selected[3] = true; }
        selected
    }

    /// Selects the Storage opening's original Root body cause without native IO.
    #[doc(hidden)]
    #[must_use]
    pub fn storage_root_failure_is_selected_v2(&self) -> bool {
        self.resource_entries.storage.root_selected && !self.resource_entries.storage.root_native_selected
    }

    /// Selects only the actual Storage turn's recorded Root-before or Root-after cause.
    #[doc(hidden)]
    #[must_use]
    pub fn storage_current_turn_root_failure_is_selected_v2(&self) -> bool {
        let Some(index) = self.resource_entries.storage.turn_next.iter().rposition(Option::is_some) else {
            return false;
        };
        if self.resource_entries.storage.turn_next[index].as_ref().is_some_and(Result::is_err)
            || self.resource_entries.storage.turn_native_selected[index]
        {
            return false;
        }
        if let Some(Err(cause)) = &self.resource_entries.storage.turn_before[index] {
            return matches!(cause, StartRootEntryErrorV1::Client(_));
        }
        if self.resource_entries.storage.turn_after[index].as_ref().is_some_and(Result::is_err) {
            return false;
        }
        self.resource_entries.storage.turn_root_after[index].as_ref().is_some_and(Result::is_err)
    }
}

impl OriginalStartHostRootLoanV1<'_, '_> {
    /// Selects only the stored Storage rejoin failure before independent posts.
    #[doc(hidden)]
    #[must_use]
    pub fn retained_storage_session_failure_is_selected_v2(&self) -> bool {
        matches!(self.native.first, Some(FirstV1::ResourceSessionJoin(_)))
    }
}
