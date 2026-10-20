//! Retains disjoint native IO and Session-post destinations for each Start resource.
//!
//! Every stage belongs to the same genuine Start payer. The three resources
//! keep separate once-state and failure custody, while each complete debit
//! includes all surviving resource representations. Advancing a native turn
//! does not retire a Session, reset traffic or reuse another purpose's slots.

use super::*;

#[derive(Default)]
pub(super) struct StartResourceStateV2 {
    pub(super) io: Box<super::super::storage_io::StorageIoStagesV1>,
    pub(super) post: Box<network_io::StartResourcePostPreparationV2>,
    pub(super) io_loan_entered: bool,
    pub(super) retained_create_demand: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
    pub(super) retained_create_funding: Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) retained_create_join: Option<Result<(), network_opening::StartResourceSessionCurrentnessErrorV4>>,
    pub(super) completed_resident: Option<ResourceVector>,
    pub(super) completed_model_turn: Option<u64>,
    pub(super) content_resident: Option<ResourceVector>,
    pub(super) preparation_resident: Option<ResourceVector>,
    pub(super) session_resident: Option<Result<ResourceVector, ResourceReservationErrorV1>>,
}

impl StartResourceStateV2 {
    fn retained_demand_v2(&self, turn: u64) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if let Some(completed) = self.completed_resident {
            return Ok(completed);
        }
        let session = match self.session_resident.as_ref() {
            Some(Ok(resident)) => *resident,
            Some(Err(_)) => return Err(ResourceReservationErrorV1::Conflict),
            None => ResourceVector::ZERO,
        };
        self.content_resident.unwrap_or(ResourceVector::ZERO)
            .checked_add(self.preparation_resident.unwrap_or(ResourceVector::ZERO))?
            .checked_add(session)?
            .checked_add(self.post.resident_demand_v2()?)?
            .checked_add(self.io.retained_demand_v1(turn)?)?
            .checked_add(match self.retained_create_demand.as_ref() {
                Some(Ok(demand)) => *demand,
                Some(Err(_)) => return Err(ResourceReservationErrorV1::Conflict),
                None => ResourceVector::ZERO,
            })
            .map_err(Into::into)
    }

    fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.post.failure().or_else(|| self.io.failure())
            .or_else(|| self.session_resident.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

#[derive(Default)]
pub(super) struct StartResourceStatesV2 {
    pub(super) network: Box<StartResourceStateV2>,
    pub(super) storage: Box<StartResourceStateV2>,
    pub(super) mount: Box<StartResourceStateV2>,
    pub(super) host: Box<StartResourceStateV2>,
    pub(super) host_catalog_resident: ResourceVector,
    pub(super) host_catalog_entered: bool,
    pub(super) host_catalog_loan_entered: bool,
    pub(super) host_catalog_source_entered: bool,
    pub(super) host_catalog_io: Box<super::super::storage_io::StorageIoStagesV1>,
    pub(super) host_catalog_io_entered: bool,
    pub(super) host_catalog_post: Box<host_publication::StartHostCatalogPostOriginalV2>,
    pub(super) host_catalog_opening_resident: ResourceVector,
    pub(super) host_catalog_completion: Option<host_publication::StartHostCatalogNativeCompletionV2>,
    pub(super) host_publication_resident: ResourceVector,
    pub(super) host_catalog_publication_resident: ResourceVector,
}

impl StartResourceStateV2 {
    pub(super) fn retained_create_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.retained_create_demand.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.retained_create_funding.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.retained_create_join.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _))
    }
}

impl StartResourceStatesV2 {
    pub(super) fn inactive_receiving_bytes_v2() -> Option<usize> {
        let one = super::fixed_box_bytes_v2::<StartResourceStateV2>()?
            .checked_add(super::fixed_box_bytes_v2::<super::super::storage_io::StorageIoStagesV1>()?)?
            .checked_add(super::fixed_box_bytes_v2::<network_io::StartResourcePostPreparationV2>()?)?;
        one.checked_mul(4)?
            .checked_add(super::fixed_box_bytes_v2::<super::super::storage_io::StorageIoStagesV1>()?)?
            .checked_add(super::fixed_box_bytes_v2::<host_publication::StartHostCatalogPostOriginalV2>()?)
    }

    pub(super) fn retained_demand_v2(&self, turn: u64)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        // Permanent Start history is separate. Every resource contributes its
        // actual surviving content, preparation, Session, post and native IO
        // representations exactly once until genuine physical disposition.
        self.host_catalog_resident.checked_add(self.host_publication_resident)?
            .checked_add(self.host_catalog_publication_resident)?
            .checked_add(self.host_catalog_opening_resident)?
            .checked_add(self.host_catalog_post.retained_demand_v2()?)?
            .checked_add(self.host_catalog_io.retained_demand_v1(turn)?)?
            .checked_add(match self.host_catalog_completion.as_ref() {
                Some(completion) => completion.retained_demand_v2(turn)?,
                None => ResourceVector::ZERO,
            })?
            .checked_add(self.network.retained_demand_v2(turn)?)?
            .checked_add(self.storage.retained_demand_v2(turn)?)?
            .checked_add(self.mount.retained_demand_v2(turn)?)?
            .checked_add(self.host.retained_demand_v2(turn)?)
            .map_err(Into::into)
    }

    pub(super) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.network.failure_v2().or_else(|| self.storage.failure_v2())
            .or_else(|| self.mount.failure_v2())
            .or_else(|| self.host_catalog_post.failure_v2())
            .or_else(|| self.host_catalog_io.failure())
            .or_else(|| self.host_catalog_completion.as_ref().and_then(|completion| completion.failure_v2()))
            .or_else(|| self.host.failure_v2())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum StartResourceKindV2 { Network, Storage, Mount, Host }

impl StartResourceKindV2 {
    pub(super) fn from_purpose_v2(
        purpose: aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1,
    ) -> Result<Self, ResourceReservationErrorV1> {
        use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1 as Purpose;
        match purpose {
            Purpose::NetworkPrepare => Ok(Self::Network),
            Purpose::StorageGuestRoot => Ok(Self::Storage),
            Purpose::MountNamespace => Ok(Self::Mount),
            Purpose::HostLaunch => Ok(Self::Host),
        }
    }

    pub(super) fn role_v2(self) -> crate::ControllerInitialBrokerSessionRoleV1 {
        use crate::ControllerInitialBrokerSessionRoleV1 as Role;
        match self { Self::Network => Role::Network, Self::Mount => Role::Mount, Self::Storage => Role::Storage, Self::Host => Role::Host }
    }

    pub(super) fn purpose_v2(self) -> aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1 {
        use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::HostResourcePurposeDataV1 as Purpose;
        match self { Self::Network => Purpose::NetworkPrepare, Self::Storage => Purpose::StorageGuestRoot,
            Self::Mount => Purpose::MountNamespace, Self::Host => Purpose::HostLaunch }
    }
}

impl StartResourceStatesV2 {
    pub(super) fn member_v2(&self, kind: StartResourceKindV2) -> &StartResourceStateV2 {
        match kind { StartResourceKindV2::Network => &self.network,
            StartResourceKindV2::Storage => &self.storage, StartResourceKindV2::Mount => &self.mount, StartResourceKindV2::Host => &self.host }
    }

    pub(super) fn member_mut_v2(&mut self, kind: StartResourceKindV2) -> &mut StartResourceStateV2 {
        match kind { StartResourceKindV2::Network => &mut self.network,
            StartResourceKindV2::Storage => &mut self.storage, StartResourceKindV2::Mount => &mut self.mount, StartResourceKindV2::Host => &mut self.host }
    }
}

#[derive(Default)]
pub(super) struct StartResourceEntryOriginalV2 {
    pub(super) predecessor: Option<Result<(), crate::normal_root::RootHostLaunchClientClosedV1>>,
    pub(super) content: Box<network_preparation::ResourceContentTurnOriginalV2>,
    pub(super) root_next: Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) root_body: Option<Result<(), host_root::StartRootEntryErrorV1>>,
    pub(super) root_after: Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) root_native_selected: bool,
    pub(super) root_selected: bool,
    // The Host follows 0→4→6→5→1→2→3; numeric maximum cannot name the active turn.
    pub(super) active_turn: Option<usize>,
    pub(super) turn_ordinal: [Option<u64>; 7],
    pub(super) turn_native_selected: [bool; 7],
    pub(super) turn_next: [Option<Result<(), ResourceReservationErrorV1>>; 7],
    pub(super) turn_before: [Option<Result<(), host_root::StartRootEntryErrorV1>>; 7],
    pub(super) turn_after: [Option<Result<(), ResourceReservationErrorV1>>; 7],
    pub(super) turn_root_after: [Option<Result<(), crate::normal_root::RootHostLaunchClientClosedV1>>; 7],
}

#[derive(Default)]
pub(super) struct StartResourceEntriesV2 {
    pub(super) network: Box<StartResourceEntryOriginalV2>,
    pub(super) storage: Box<StartResourceEntryOriginalV2>,
    pub(super) mount: Box<StartResourceEntryOriginalV2>,
    pub(super) host: Box<StartResourceEntryOriginalV2>,
}

impl StartResourceEntriesV2 {
    pub(super) fn inactive_receiving_bytes_v2() -> Option<usize> {
        super::fixed_box_bytes_v2::<StartResourceEntryOriginalV2>()?
            .checked_add(super::fixed_box_bytes_v2::<network_preparation::ResourceContentTurnOriginalV2>()?)?
            .checked_mul(4)
    }

    pub(super) fn member_v2(&self, kind: StartResourceKindV2) -> &StartResourceEntryOriginalV2 {
        match kind { StartResourceKindV2::Network => &self.network,
            StartResourceKindV2::Storage => &self.storage, StartResourceKindV2::Mount => &self.mount, StartResourceKindV2::Host => &self.host }
    }

    pub(super) fn member_mut_v2(&mut self, kind: StartResourceKindV2) -> &mut StartResourceEntryOriginalV2 {
        match kind { StartResourceKindV2::Network => &mut self.network,
            StartResourceKindV2::Storage => &mut self.storage, StartResourceKindV2::Mount => &mut self.mount, StartResourceKindV2::Host => &mut self.host }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_surviving_resource_plane_contributes_to_the_same_complete_sum() {
        let mut resources = StartResourceStatesV2::default();
        resources.network.content_resident = Some(ResourceVector::ZERO.with(D::MemoryBytes, 11));
        resources.network.preparation_resident = Some(ResourceVector::ZERO.with(D::OpenFiles, 2));
        resources.storage.session_resident = Some(Ok(ResourceVector::ZERO.with(D::MemoryBytes, 17)));
        resources.mount.content_resident = Some(ResourceVector::ZERO.with(D::MetadataEntries, 5));
        resources.mount.preparation_resident = Some(ResourceVector::ZERO.with(D::MemoryBytes, 23));
        resources.host.session_resident = Some(Ok(ResourceVector::ZERO.with(D::MemoryBytes, 29)));

        let complete = resources.retained_demand_v2(9).unwrap();

        assert_eq!(complete.get(D::MemoryBytes), 80);
        assert_eq!(complete.get(D::OpenFiles), 2);
        assert_eq!(complete.get(D::MetadataEntries), 5);
        assert_eq!(complete.get(D::Pids), 0);
    }

    #[test]
    fn cross_resource_overflow_refuses_the_complete_invoice() {
        let mut resources = StartResourceStatesV2::default();
        resources.network.content_resident = Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::MAX));
        resources.mount.session_resident = Some(Ok(ResourceVector::ZERO.with(D::MemoryBytes, 1)));

        assert!(resources.retained_demand_v2(9).is_err());
    }
}

impl StartResourceEntryOriginalV2 {
    fn selected_failure_v2<'held>(
        &'held self,
        native: Option<&'held (dyn Error + 'static)>,
        host: bool,
        action: Option<&'held host_publication::StartHostPublicationActionOriginalV2>,
    ) -> Option<(&'held (dyn Error + 'static), bool)> {
        if let Some(cause) = self.predecessor.as_ref().and_then(|returned| returned.as_ref().err()) {
            return Some((cause, false));
        }
        if let Some(cause) = self.content.failure() {
            let selected = self.content.native_failure_is_selected_v2();
            return Some((if selected { native.unwrap_or(cause) } else { cause }, selected));
        }
        let root = resource_error_v2(&self.root_next)
            .or_else(|| self.root_body.as_ref().and_then(|returned| returned.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static)))
            .or_else(|| resource_error_v2(&self.root_after));
        if let Some(cause) = root {
            return Some((if self.root_native_selected { native.unwrap_or(cause) } else { cause },
                self.root_native_selected));
        }

        // These are semantic predecessors, not numeric stage ordering. Each
        // body refusal precedes that interval's independently owed posts.
        let order: &[usize] = if host { &[0, 4, 6, 5, 1, 2, 3] } else { &[0, 1, 2, 3] };
        for &index in order {
            let before = resource_error_v2(&self.turn_next[index])
                .or_else(|| self.turn_before[index].as_ref()
                    .and_then(|returned| returned.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static)));
            if let Some(cause) = before {
                let selected = self.turn_native_selected[index];
                return Some((if selected { native.unwrap_or(cause) } else { cause }, selected));
            }
            if host && index == 4 {
                if let Some((cause, selected)) = action.and_then(|action| action.admission_body_failure_v2()) {
                    return Some((if selected { native.unwrap_or(cause) } else { cause }, selected));
                }
            }
            if host && index == 5 {
                if let Some((cause, selected)) = action.and_then(|action| action.activation_body_failure_v2()) {
                    return Some((if selected { native.unwrap_or(cause) } else { cause }, selected));
                }
            }
            if host && index == 2 {
                if let Some((cause, selected)) = action.and_then(|action| action.effect_body_failure_v2()) {
                    return Some((if selected { native.unwrap_or(cause) } else { cause }, selected));
                }
            }
            let after = resource_error_v2(&self.turn_after[index])
                .or_else(|| self.turn_root_after[index].as_ref()
                    .and_then(|returned| returned.as_ref().err())
                    .map(|cause| cause as &(dyn Error + 'static)));
            if let Some(cause) = after {
                let selected = self.turn_native_selected[index];
                return Some((if selected { native.unwrap_or(cause) } else { cause }, selected));
            }
            if host && index == 4 {
                if let Some(cause) = action.and_then(|action| action.admission_after.as_ref())
                    .and_then(|returned| returned.as_ref().err()) {
                    return Some((cause, false));
                }
            }
            if host && index == 5 {
                if let Some(cause) = action.and_then(|action| action.activation_after.as_ref())
                    .and_then(|returned| returned.as_ref().err()) {
                    return Some((cause, false));
                }
            }
        }
        None
    }
}

fn resource_error_v2(returned: &Option<Result<(), ResourceReservationErrorV1>>)
    -> Option<&(dyn Error + 'static)> {
    returned.as_ref().and_then(|returned| returned.as_ref().err())
        .map(|cause| cause as &(dyn Error + 'static))
}

impl StartResourceEntriesV2 {
    fn selected_failure_v2<'held>(
        &'held self,
        native: Option<&'held (dyn Error + 'static)>,
        action: Option<&'held host_publication::StartHostPublicationActionOriginalV2>,
    ) -> Option<(&'held (dyn Error + 'static), bool)> {
        self.network.selected_failure_v2(native, false, None)
            .or_else(|| self.storage.selected_failure_v2(native, false, None))
            .or_else(|| self.mount.selected_failure_v2(native, false, None))
            .or_else(|| self.host.selected_failure_v2(native, true, action))
    }

    pub(super) fn failure_v2<'held>(
        &'held self,
        native: Option<&'held (dyn Error + 'static)>,
        action: Option<&'held host_publication::StartHostPublicationActionOriginalV2>,
    ) -> Option<&'held (dyn Error + 'static)> {
        self.selected_failure_v2(native, action).map(|(cause, _)| cause)
    }

    pub(super) fn native_failure_is_selected_v2(
        &self,
        action: Option<&host_publication::StartHostPublicationActionOriginalV2>,
    ) -> bool {
        self.selected_failure_v2(None, action).is_some_and(|(_, selected)| selected)
    }
}
