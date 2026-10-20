//! Shares the closed Delete26, DeleteApply7, Network9 and Mount62 Session flight.

use super::*;

pub(super) struct DeleteStorageSessionFlightOriginalV3 {
    pub(super) flight: ProvisioningFlightV1,
    pub(super) entry: Option<Result<(), ResourceReservationErrorV1>>,
    entry_original_selected: bool,
    pub(super) association: Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) native: Option<Result<[u8; 64], ResourceReservationErrorV1>>,
    entered: bool,
    association_original_selected: bool,
    association_sdk_owner_selected: bool,
    retirement_original_selected: bool,
    pub(super) retirement: Option<Result<(), ResourceReservationErrorV1>>,
}

impl DeleteStorageSessionFlightOriginalV3 {
    /// Constructs inert inline destinations without IO, allocation or permission.
    #[must_use]
    pub(super) fn new(kind: ProvisioningKindV4) -> Self {
        Self {
            flight: ProvisioningFlightV1::new(kind),
            entry: None,
            entry_original_selected: false,
            association: None,
            native: None,
            entered: false,
            retirement: None,
            association_original_selected: false,
            association_sdk_owner_selected: false,
            retirement_original_selected: false,
        }
    }

    pub(super) fn run_once_v3(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        mut original: DeleteStorageLoanV3<'_, '_>,
        predecessor: DeleteStoragePredecessorV3<'_>,
    ) -> Result<(), OutputPreparationClosedV1> {
        if self.entered {
            self.flight.mark(First::Reentry);
            return Err(OutputPreparationClosedV1);
        }
        self.entered = true;
        // Price this actual negotiated Session recipe before either native
        // capture or its owed post can enter. A caller's earlier shape DATA
        // cannot replace this closed SDK recipe or suppress its real debit.
        let shape = original.request_bound_v3().and_then(|bound| {
            let maximum = session.transcript.negotiated_maximum_response_bytes() as usize;
            match self.flight.kind {
                ProvisioningKindV4::DeleteMount => super::delete_mount::delete_mount_reap_security_shape_v4(maximum, bound),
                _ => delete_security_shape_v3(maximum, bound),
            }
        });
        self.entry = Some(match shape {
            Some(shape) => {
                self.entry_original_selected = true;
                original.prepay_once_v3(shape)
            }
            None => Err(ResourceReservationErrorV1::Conflict),
        });
        if !matches!(self.entry, Some(Ok(()))) {
            // No SDK native before was entered. The upper original still owes
            // its independently entered C/Root posts after this return.
            return Err(OutputPreparationClosedV1);
        }
        self.association = Some(
            match original.journal_mut_v4(&mut session.owner) {
                Ok(journal) => original.capture_once_v3(
                    journal,
                    &session.socket,
                    &session.transcript,
                    predecessor,
                    &mut self.association_original_selected,
                ),
                Err(cause) => {
                    self.association_sdk_owner_selected = true;
                    self.flight
                        .shared
                        .inner
                        .protected_failure
                        .get_or_insert(cause);
                    Err(ResourceReservationErrorV1::Conflict)
                }
            },
        );
        if !matches!(self.association, Some(Ok(()))) {
            // Only the upper constructor can enter this native lane. Its owed
            // Session posts run even when association capture itself refused.
            original.final_posts_v3(&mut self.flight, session);
            original.close_window_v3();
            return Err(OutputPreparationClosedV1);
        }
        let primary = original.run_flight_v3(&mut self.flight, session);
        // This fence is mechanical and infallible. A rejected/uncertain flight
        // keeps the same window and every native error for actual recovery.
        original.close_window_v3();
        primary?;
        self.native = Some(original.completed_native_v3().copied());
        if !matches!(self.native, Some(Ok(_))) {
            return Err(OutputPreparationClosedV1);
        }
        Ok(())
    }

    pub(super) fn retire_once_v3(
        &mut self,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        mut original: DeleteStorageLoanV3<'_, '_>,
    ) -> Result<(), OutputPreparationClosedV1> {
        self.retirement = Some(
            match original.journal_mut_v4(&mut session.owner) {
                Ok(journal) => {
                    self.retirement_original_selected = true;
                    original.retire_window_v3(journal)
                }
                Err(cause) => {
                    self.association_sdk_owner_selected = true;
                    self.flight
                        .shared
                        .inner
                        .protected_failure
                        .get_or_insert(cause);
                    Err(ResourceReservationErrorV1::Conflict)
                }
            },
        );
        if matches!(self.retirement, Some(Ok(()))) {
            Ok(())
        } else {
            Err(OutputPreparationClosedV1)
        }
    }

    /// Borrows only the all-posts completed actual outcome and its native boundary.
    ///
    /// This view is historical DATA. The upper Root/C afters and independent
    /// subsequent catalog verification remain mandatory before destruction.
    ///
    /// # Errors
    /// Refuses incomplete entry, association, receipt or any independently owed post.
    pub(super) fn require_completed_v3(
        &self,
    ) -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &[u8; 64]), OutputPreparationClosedV1> {
        if !matches!(self.entry, Some(Ok(())))
            || !matches!(self.association, Some(Ok(())))
            || self.retirement.as_ref().is_some_and(Result::is_err)
        {
            return Err(OutputPreparationClosedV1);
        }
        let outcome = self
            .flight
            .authenticated(false)
            .ok_or(OutputPreparationClosedV1)?;
        let native = self
            .native
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(OutputPreparationClosedV1)?;
        Ok((outcome, native))
    }

    /// Borrows the selected actual error while all owning prefixes remain resident.
    #[must_use]
    pub(super) fn failure_v3(&self) -> Option<&(dyn Error + 'static)> {
        self.entry
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn Error + 'static))
            .or_else(|| {
                self.association
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| {
                    if self.association_sdk_owner_selected {
                        self.flight.shared.inner.failure().unwrap_or(cause)
                    } else {
                        cause as &(dyn Error + 'static)
                        }
                    })
            })
            .or_else(|| self.flight.failure())
            .or_else(|| {
                self.native
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.retirement
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| {
                        if self.retirement_original_selected {
                            cause as &(dyn Error + 'static)
                        } else {
                            self.flight.shared.inner.failure().unwrap_or(cause)
                        }
                    })
            })
    }

    /// Identifies a selected lower original marker without overriding earlier SDK errors.
    #[must_use]
    pub(super) fn original_failure_selected_v3(&self) -> bool {
        (self.entry_original_selected && self.entry.as_ref().is_some_and(Result::is_err))
            || (self.association_original_selected
                && self.association.as_ref().is_some_and(Result::is_err))
            || (matches!(self.association, Some(Ok(()))) && self.flight.selected_original_failure())
            || (self.flight.first.is_none()
                && (self.native.as_ref().is_some_and(Result::is_err)
                    || (self.retirement_original_selected
                        && self.retirement.as_ref().is_some_and(Result::is_err))))
    }
}

pub(super) enum DeleteStorageLoanV3<'io, 'held> {
    Preparation(&'io mut aos_sandbox::OriginalDeleteStoragePreparationLoanV3<'held>),
    Apply(&'io mut aos_sandbox::OriginalDeleteStorageApplyLoanV3<'held>),
    Network(&'io mut aos_sandbox::OriginalDeleteNetworkApplyLoanV4<'held>),
    Mount(&'io mut aos_sandbox::OriginalDeleteMountReapLoanV4<'held>),
}

pub(super) enum DeleteStoragePredecessorV3<'held> {
    Inventory(&'held super::super::delete_inventory::DeleteInventoryAnswerOriginalsV1),
    Preparation(&'held super::delete_preparation::DeleteStoragePreparationSessionIoOriginalV3),
}

pub(super) fn inline_bytes_v3() -> Option<usize> {
    size_of::<DeleteStorageSessionFlightOriginalV3>()
        .checked_mul(2)?
        .checked_add(ProvisioningFlightV1::body_slots_receiving_bytes_v5(1)?)?
        .checked_add(size_of::<DeleteStorageLoanV3<'static, 'static>>().checked_mul(2)?)?
        .checked_add(size_of::<DeleteStoragePredecessorV3<'static>>().checked_mul(2)?)
}

pub(super) fn delete_security_shape_v3(
    negotiated_maximum: usize,
    request_bytes: usize,
) -> Option<aos_sandbox::StorageProvisioningSessionIoShapeDataV1> {
    StorageProvisioningSessionIoOriginalV1::shape_data_v4(
        negotiated_maximum,
        request_bytes,
        inline_bytes_v3()?,
        0,
    )
}

impl DeleteStorageLoanV3<'_, '_> {
    fn journal_mut_v4<'owner>(&self, owner: &'owner mut crate::recovery::ProtectedBrokerSessionOwnerV1)
        -> Result<&'owner mut aos_sandbox::Journal, BrokerSessionSecurityError> {
        match self {
            Self::Preparation(_) | Self::Apply(_) => owner.retained_storage_client_journal_mut_v3(),
            Self::Network(_) | Self::Mount(_) => owner.delete_inventory_client_journal_mut_v1(),
        }
    }

    fn capture_once_v3(
        &mut self,
        journal: &mut aos_sandbox::Journal,
        socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        transcript: &aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1,
        predecessor: DeleteStoragePredecessorV3<'_>,
        original_selected: &mut bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        match (self, predecessor) {
            (Self::Network(original), DeleteStoragePredecessorV3::Inventory(inventory)) => {
                *original_selected = true;
                original.capture_network_session_once_v4(journal, socket, transcript,
                    inventory.outcome_v1(), inventory.native_boundary_data_v2(),
                    inventory.protected_cut_data_v2())
            }
            (Self::Mount(original), DeleteStoragePredecessorV3::Inventory(inventory)) => {
                *original_selected = true;
                original.capture_mount_session_once_v4(journal, socket, transcript,
                    inventory.outcome_v1(), inventory.native_boundary_data_v2(),
                    inventory.protected_cut_data_v2())
            }
            (Self::Preparation(original), DeleteStoragePredecessorV3::Inventory(inventory)) => {
                *original_selected = true;
                original.capture_preparation_session_once_v3(
                    journal,
                    socket,
                    transcript,
                    inventory.outcome_v1(),
                    inventory.native_boundary_data_v2(),
                    inventory.protected_cut_data_v2(),
                )
            }
            (Self::Apply(original), DeleteStoragePredecessorV3::Preparation(preparation)) => {
                let (outcome, native) = preparation
                    .require_completed_v3()
                    .map_err(|_| ResourceReservationErrorV1::Conflict)?;
                *original_selected = true;
                // The upper context also holds the actual native26 original;
                // this borrowed SDK result is only an affinity comparison.
                original
                    .capture_apply_session_once_v3(journal, socket, transcript, outcome, *native)
            }
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    fn request_bound_v3(&self) -> Option<usize> {
        match self {
            Self::Preparation(original) => original.preparation_request_bound_v3(),
            Self::Apply(original) => original.apply_request_bound_v3(),
            Self::Network(original) => original.network_request_bound_v4(),
            Self::Mount(original) => original.mount_request_bound_v4(),
        }
    }

    fn prepay_once_v3(
        &mut self,
        shape: aos_sandbox::StorageProvisioningSessionIoShapeDataV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Preparation(original) => original.prepay_preparation_entry_once_v3(shape),
            Self::Apply(original) => original.prepay_apply_entry_once_v3(shape),
            Self::Network(original) => original.prepay_network_entry_once_v4(shape),
            Self::Mount(original) => original.prepay_mount_entry_once_v4(shape),
        }
    }

    fn close_window_v3(&mut self) {
        match self {
            Self::Preparation(original) => original.close_preparation_append_window_v3(),
            Self::Apply(original) => original.close_apply_append_window_v3(),
            Self::Network(original) => original.close_network_append_window_v4(),
            Self::Mount(original) => original.close_mount_append_window_v4(),
        }
    }

    fn completed_native_v3(&self) -> Result<&[u8; 64], ResourceReservationErrorV1> {
        match self {
            Self::Preparation(original) => original.completed_preparation_native_v3(),
            Self::Apply(original) => original.completed_apply_native_v3(),
            Self::Network(original) => original.completed_network_native_v4(),
            Self::Mount(original) => original.completed_mount_native_v4(),
        }
    }

    fn retire_window_v3(
        &mut self,
        journal: &mut aos_sandbox::Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        match self {
            Self::Preparation(original) => {
                original.retire_completed_preparation_append_once_v3(journal)
            }
            Self::Apply(original) => original.retire_completed_apply_append_once_v3(journal),
            Self::Network(original) => original.retire_completed_network_append_once_v4(journal),
            Self::Mount(original) => original.retire_completed_mount_append_once_v4(journal),
        }
    }

    fn run_flight_v3(
        &mut self,
        flight: &mut ProvisioningFlightV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) -> Result<(), OutputPreparationClosedV1> {
        match self {
            Self::Preparation(original) => {
                StorageProvisioningSessionIoOriginalV1::run_flight_once_v4(
                    flight,
                    session,
                    *original,
                    &(),
                    false,
                )
            }
            Self::Network(original) => StorageProvisioningSessionIoOriginalV1::run_flight_once_v4(
                flight, session, *original, &(), false),
            Self::Mount(original) => StorageProvisioningSessionIoOriginalV1::run_flight_once_v4(
                flight, session, *original, &(), false),
            Self::Apply(original) => StorageProvisioningSessionIoOriginalV1::run_flight_once_v4(
                flight,
                session,
                *original,
                &(),
                false,
            ),
        }
    }

    fn final_posts_v3(
        &mut self,
        flight: &mut ProvisioningFlightV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
    ) {
        match self {
            Self::Preparation(original) => {
                StorageProvisioningSessionIoOriginalV1::final_posts(flight, session, *original)
            }
            Self::Apply(original) => {
                StorageProvisioningSessionIoOriginalV1::final_posts(flight, session, *original)
            }
            Self::Network(original) => {
                StorageProvisioningSessionIoOriginalV1::final_posts(flight, session, *original)
            }
            Self::Mount(original) => {
                StorageProvisioningSessionIoOriginalV1::final_posts(flight, session, *original)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_sdk_predecessor_stays_first_over_a_later_owed_post() {
        let mut original = DeleteStorageSessionFlightOriginalV3::new(ProvisioningKindV4::DeleteApply);
        original.association = Some(Err(ResourceReservationErrorV1::Conflict));
        original.flight.shared.inner.protected_failure = Some(BrokerSessionSecurityError::Currentness);

        assert!(original.failure_v3().unwrap().is::<ResourceReservationErrorV1>());
        assert!(!original.original_failure_selected_v3());

        original.association_sdk_owner_selected = true;

        assert!(original.failure_v3().unwrap().is::<BrokerSessionSecurityError>());
        assert!(!original.original_failure_selected_v3());
    }

    #[test]
    fn fixed_owner_refusal_selects_its_actual_sdk_cause() {
        for kind in [ProvisioningKindV4::DeletePreparation, ProvisioningKindV4::DeleteApply] {
            let mut flight = ProvisioningFlightV1::new(kind);
            flight.fixed = Some(Err(ResourceReservationErrorV1::Conflict));
            flight.shared.inner.protected_failure = Some(BrokerSessionSecurityError::Currentness);
            flight.mark(First::Fixed);

            assert!(flight.failure().unwrap().is::<BrokerSessionSecurityError>());
            assert!(!flight.selected_original_failure());

            flight.fixed_original_selected = true;

            assert!(flight.failure().unwrap().is::<ResourceReservationErrorV1>());
            assert!(flight.selected_original_failure());
        }
    }

    #[test]
    fn retirement_resolves_its_actual_owner_error_without_masking_an_earlier_entry() {
        let mut original =
            DeleteStorageSessionFlightOriginalV3::new(ProvisioningKindV4::DeleteApply);
        original.flight.shared.inner.protected_failure =
            Some(BrokerSessionSecurityError::Currentness);
        original.retirement = Some(Err(ResourceReservationErrorV1::Conflict));

        assert!(
            original
                .failure_v3()
                .unwrap()
                .is::<BrokerSessionSecurityError>()
        );
        assert!(!original.original_failure_selected_v3());

        original.entry = Some(Err(ResourceReservationErrorV1::Conflict));
        original.entry_original_selected = true;

        assert!(
            original
                .failure_v3()
                .unwrap()
                .is::<ResourceReservationErrorV1>()
        );
        assert!(original.original_failure_selected_v3());
    }

    #[test]
    fn the_delete_apply_constructor_selects_only_its_closed_client_purpose() {
        let original = DeleteStorageSessionFlightOriginalV3::new(ProvisioningKindV4::DeleteApply);

        assert!(matches!(
            original.flight.shared.inner.purpose,
            OriginalClientFlightPurposeV1::DeleteStorageApply
        ));
        assert!(original.require_completed_v3().is_err());
    }
}
