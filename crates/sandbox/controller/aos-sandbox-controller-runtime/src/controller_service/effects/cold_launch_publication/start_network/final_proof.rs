//! Joins each actual SDK history to its same Root child and final C turn.
//!
//! Every reached C-after and Root-after runs after the retained body result.
//! Completion remains private to the genuine Root issuer; the exported SDK
//! packets are comparison DATA and cannot dispose a resource by themselves.

use super::*;
use aos_sandbox_broker_session_security::controller_composition::OutputPreparationClosedV1;

#[derive(Debug, thiserror::Error)]
enum BodyError {
    #[error(transparent)]
    Loan(#[from] ResourceReservationErrorV1),
    #[error(transparent)]
    Root(#[from] RootHostLaunchClientClosedV1),
    #[error(transparent)]
    Session(#[from] OutputPreparationClosedV1),
}

#[derive(Clone, Copy)]
enum Failure {
    Entry,
    Body,
    Posts,
    Completion,
}

pub(super) struct ResourceCompletionV2 {
    kind: ResourceKindV2,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    body: Option<Result<(), BodyError>>,
    posts: Option<Result<(), ResourceReservationErrorV1>>,
    completion: Option<Result<(), RootHostLaunchClientClosedV1>>,
    original_failure_selected: bool,
    first: Option<Failure>,
}

impl ResourceCompletionV2 {
    pub(super) const fn new(kind: ResourceKindV2) -> Self {
        Self {
            kind,
            entry: None,
            body: None,
            posts: None,
            completion: None,
            original_failure_selected: false,
            first: None,
        }
    }

    pub(super) fn progress_once_v2(
        &mut self,
        kind: ResourceKindV2,
        entry: &mut AcceptedStartEntryOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        root: &mut RootHostLaunchClientOriginalV1,
        io: &resource_io::ResourceIoV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.kind != kind { return Err(ResourceReservationErrorV1::Conflict); }
        if self.entry.is_some() {
            return if self.first.is_none() && matches!(self.completion, Some(Ok(()))) {
                Ok(())
            } else {
                Err(ResourceReservationErrorV1::Conflict)
            };
        }
        self.entry =
            Some(match kind {
            ResourceKindV2::Network => entry.begin_network_final_proof_turn_once_v2(root, intake, controller, source),
            ResourceKindV2::Storage => entry.begin_storage_final_proof_turn_once_v2(root, intake, controller, source),
            ResourceKindV2::Mount => entry.begin_mount_final_proof_turn_once_v2(root, intake, controller, source),
            ResourceKindV2::Host => entry.begin_host_final_proof_turn_once_v2(root, intake, controller, source),
        });
        if matches!(self.entry, Some(Ok(()))) {
            self.body = Some((|| -> Result<(), BodyError> {
                let exchange = io.completed_exchange_data_v2()?;
                let mut loan = entry.borrow_host_root_v1(intake, controller, source)?;
                match kind {
            ResourceKindV2::Network => root.send_network_final_proof_once_v2(
                    &mut loan,
                    controller,
                    aos_sandbox_controller_domain::normal_root::RootStartResourceExchangeDataV2 {
                        session_native: exchange.session_native,
                        resource_request: exchange.resource_request,
                        resource_outcome: exchange.resource_outcome,
                        inventory_request: exchange.inventory_request,
                        inventory_outcome: exchange.inventory_outcome,
                    },
                ),
            ResourceKindV2::Storage => root.send_storage_final_proof_once_v2(
                    &mut loan,
                    controller,
                    aos_sandbox_controller_domain::normal_root::RootStartResourceExchangeDataV2 {
                        session_native: exchange.session_native,
                        resource_request: exchange.resource_request,
                        resource_outcome: exchange.resource_outcome,
                        inventory_request: exchange.inventory_request,
                        inventory_outcome: exchange.inventory_outcome,
                    },
                ),
            ResourceKindV2::Mount => root.send_mount_final_proof_once_v2(
                    &mut loan,
                    controller,
                    aos_sandbox_controller_domain::normal_root::RootStartResourceExchangeDataV2 {
                        session_native: exchange.session_native,
                        resource_request: exchange.resource_request,
                        resource_outcome: exchange.resource_outcome,
                        inventory_request: exchange.inventory_request,
                        inventory_outcome: exchange.inventory_outcome,
                    },
                ),
            ResourceKindV2::Host => root.send_host_final_proof_once_v2(
                    &mut loan,
                    controller,
                    aos_sandbox_controller_domain::normal_root::RootStartResourceExchangeDataV2 {
                        session_native: exchange.session_native,
                        resource_request: exchange.resource_request,
                        resource_outcome: exchange.resource_outcome,
                        inventory_request: exchange.inventory_request,
                        inventory_outcome: exchange.inventory_outcome,
                    },
                ),
        }?;
                Ok(())
            })());
            if !matches!(self.body, Some(Ok(()))) {
                self.original_failure_selected =
                    match kind {
            ResourceKindV2::Network => entry.snapshot_network_final_proof_failure_v2(root),
            ResourceKindV2::Storage => entry.snapshot_storage_final_proof_failure_v2(root),
            ResourceKindV2::Mount => entry.snapshot_mount_final_proof_failure_v2(root),
            ResourceKindV2::Host => entry.snapshot_host_final_proof_failure_v2(root),
        };
                self.first = Some(Failure::Body);
            }
        } else {
            self.first = Some(Failure::Entry);
        }

        let body = if matches!(self.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootHostLaunchClientClosedV1)
        };
        self.posts = Some(match kind {
            ResourceKindV2::Network => entry.finish_network_root_turn_once_v2(root, controller, body),
            ResourceKindV2::Storage => entry.finish_storage_root_turn_once_v2(root, controller, body),
            ResourceKindV2::Mount => entry.finish_mount_root_turn_once_v2(root, controller, body),
            ResourceKindV2::Host => entry.finish_host_root_turn_once_v2(root, controller, body),
        });
        if !matches!(self.posts, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Posts);
        }
        if self.first.is_none() {
            self.completion = Some(match kind {
            ResourceKindV2::Network => root.finish_network_resource_once_v2(entry, controller),
            ResourceKindV2::Storage => root.finish_storage_resource_once_v2(entry, controller),
            ResourceKindV2::Mount => root.finish_mount_resource_once_v2(entry, controller),
            ResourceKindV2::Host => root.finish_host_resource_once_v2(entry, controller),
        });
            if !matches!(self.completion, Some(Ok(()))) {
                self.first = Some(Failure::Completion);
            }
        }
        if self.first.is_some() {
            Err(ResourceReservationErrorV1::Conflict)
        } else {
            Ok(())
        }
    }

    pub(super) fn failure_v2<'held>(
        &'held self,
        entry: &'held AcceptedStartEntryOriginalV1,
        root: &'held RootHostLaunchClientOriginalV1,
    ) -> Option<&'held (dyn Error + 'static)> {
        if self.original_failure_selected {
            return entry.failure().or_else(|| root.failure());
        }
        match self.first? {
            Failure::Entry | Failure::Posts => {
                if match self.kind {
            ResourceKindV2::Network => entry.network_current_turn_root_failure_is_selected_v2(),
            ResourceKindV2::Storage => entry.storage_current_turn_root_failure_is_selected_v2(),
            ResourceKindV2::Mount => entry.mount_current_turn_root_failure_is_selected_v2(),
            ResourceKindV2::Host => entry.host_current_turn_root_failure_is_selected_v2(),
        } {
                    root.failure()
                } else {
                    entry.failure().or_else(|| root.failure())
                }
            }
            Failure::Body => match self.body.as_ref()?.as_ref().err()? {
                BodyError::Root(_) => root.failure(),
                cause => Some(cause),
            },
            Failure::Completion => root.failure().or_else(|| {
                self.completion
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
        }
    }
}
