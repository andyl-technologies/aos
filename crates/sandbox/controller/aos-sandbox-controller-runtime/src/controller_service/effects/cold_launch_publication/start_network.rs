//! Connects Start's four resource children through one retained executor.
//!
//! The startup invoice retains these fixed subslots and construction planes;
//! the actual accepted Start prices its small Runtime header. Content, sealing and
//! signing growth is paid through that same fresh Start owner before entry.
//! The historical completed Create lends inputs; it never lends its old clock
//! or account. Every entered construction turn runs C and independent Root
//! posts before its completed request may enter a later Session turn. The
//! same retained SDK opens new Network and Mount Clients and rejoins the held
//! Storage Client and retains catalog6's Host Client for its stage1 rejoin.
//! Each child hands its actual resident cost to the next Start
//! turn after both independent outer posts and physical operation disposal.

use super::*;
use aos_sandbox_controller_domain::StartResourceSessionOpeningOriginalV2;
use aos_sandbox_controller_domain::normal_root::{RootHostLaunchClientClosedV1, RootHostLaunchClientOriginalV1};
use aos_sandbox_controller_domain::{AcceptedStartEntryOriginalV1, PreparedStartResourceRequestOriginalV2};
use aos_sandbox_broker_session_security::{
    StartResourceSessionClosedV4, StartResourceSessionOpenOriginalV4,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum ResourceKindV2 { Network, Storage, Mount, Host }

struct StorageContextV2<'held> {
    previous: &'held aos_sandbox_controller_domain::CreateProvisioningOriginalsV1,
    session: &'held mut super::super::super::inventory::DormantStorageLifecycleInventoryOwnerV1,
}

type Driver = super::super::super::inventory::OriginalCreateStorageDriverV1;

mod resource_io;
mod final_proof;
mod host_publication;

type CompletedModelsV2<'held> = [(
    &'held aos_sandbox_controller_domain::normal_root::RootStartResourceCompletedOriginalV2,
    &'held aos_sandbox_broker_session_security::controller_composition::StartResourceCompletedModelsOriginalV2,
); 3];

#[derive(Debug, thiserror::Error)]
enum OpeningError {
    #[error(transparent)]
    Loan(#[from] ResourceReservationErrorV1),
    #[error(transparent)]
    Root(#[from] RootHostLaunchClientClosedV1),
    #[error(transparent)]
    Session(#[from] StartResourceSessionClosedV4),
}

#[derive(Clone, Copy)]
enum First {
    Content,
    Root,
    Construction,
    Models,
    HostContent,
    HostPublication,
    GuardianSigner,
    GuardianCompletion,
    GuardianCheck,
    Signer,
    SigningClock,
    Completion,
    Body,
    Posts,
    Join,
    Binding,
    OpeningEntry,
    OpeningBody,
    OpeningSdk,
    OpeningStorage,
    OpeningPosts,
    OpeningAssociation,
    OpeningSurvivors,
    OpeningResidentShape,
    OpeningHandoff,
    ResourceIo,
    FinalProof,
    Disposition,
}

/// Retains the actual prepared file, Root socket and complete signing prefix.
pub(in crate::controller_service::effects) struct OriginalStartResourceV2 {
    kind: ResourceKindV2,
    prepared: Box<PreparedStartResourceRequestOriginalV2>,
    root: Box<RootHostLaunchClientOriginalV1>,
    content: Option<Result<(), ResourceReservationErrorV1>>,
    root_entry: Option<Result<(), Cause>>,
    construction: Option<Result<(), ResourceReservationErrorV1>>,
    models: Option<Result<(), aos_sandbox_controller_domain::PreparedStartResourceRequestClosedV2>>,
    signing: Option<Result<PreparedBrokerPlanSigningV1, Cause>>,
    guardian_signing: Option<Result<PreparedBrokerPlanSigningV1, Cause>>,
    guardian_signature: Option<SignatureBytes>,
    guardian_signed: Option<Result<SignedBrokerPlan, PreparedBrokerPlanCompletionErrorV1>>,
    guardian_check: Option<Result<(), aos_sandbox_controller_domain::PreparedStartResourceRequestClosedV2>>,
    publication_body: Option<Result<(), aos_sandbox_controller_domain::PreparedStartResourceRequestClosedV2>>,
    host_content_body: Option<Result<(), Cause>>,
    signing_clock: Option<Result<RawPairedClockSample, RootHostLaunchClientClosedV1>>,
    signature: Option<SignatureBytes>,
    signed: Option<Result<SignedBrokerPlan, PreparedBrokerPlanCompletionErrorV1>>,
    signed_check: Option<Result<(), aos_sandbox_controller_domain::PreparedStartResourceRequestClosedV2>>,
    body: Option<Result<(), Cause>>,
    posts: Option<Result<(), ResourceReservationErrorV1>>,
    join: Option<Result<(), aos_sandbox_controller_domain::PreparedStartResourceRequestClosedV2>>,
    binding: Option<Result<(), RootHostLaunchClientClosedV1>>,
    opening: Box<StartResourceSessionOpeningOriginalV2>,
    session: Box<StartResourceSessionOpenOriginalV4>,
    opening_entry: Option<Result<(), ResourceReservationErrorV1>>,
    opening_body: Option<Result<(), OpeningError>>,
    opening_sdk: Option<Result<(), StartResourceSessionClosedV4>>,
    opening_storage: Option<Result<(), ResourceReservationErrorV1>>,
    opening_storage_original_selected: bool,
    opening_original_failure_selected: bool,
    opening_posts: Option<Result<(), ResourceReservationErrorV1>>,
    opening_survivors: Option<Result<ResourceVector, StartResourceSessionClosedV4>>,
    opening_shape: Option<
        Result<aos_sandbox_controller_domain::StartResourceSessionResidentShapeDataV4, ResourceReservationErrorV1>,
    >,
    opening_handoff: Option<Result<(), ResourceReservationErrorV1>>,
    io: Box<resource_io::ResourceIoV2>,
    final_proof: final_proof::ResourceCompletionV2,
    disposition: Option<Result<(), StartResourceSessionClosedV4>>,
    host_publication: Box<host_publication::HostPublicationV2>,
    rejoin: Box<aos_sandbox_controller_domain::StartHostSessionRejoinOriginalV2>,
    first: Option<First>,
}

impl OriginalStartResourceV2 {
    // Fixed destinations are prepaid by RuntimeFixed before the first constructor.
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            boxed_bytes::<PreparedStartResourceRequestOriginalV2>(),
            boxed_bytes::<RootHostLaunchClientOriginalV1>(),
            boxed_bytes::<StartResourceSessionOpeningOriginalV2>(),
            boxed_bytes::<StartResourceSessionOpenOriginalV4>(),
            boxed_bytes::<resource_io::ResourceIoV2>(),
            boxed_bytes::<host_publication::HostPublicationV2>(),
            boxed_bytes::<aos_sandbox_controller_domain::StartHostSessionRejoinOriginalV2>(),
            resource_io::ResourceIoV2::inactive_receiving_bytes_v1(),
            host_publication::HostPublicationV2::inactive_receiving_bytes_v1(),
        ])
    }

    pub(in crate::controller_service::effects) fn completed_resource_v2(&self)
        -> Result<&aos_sandbox_controller_domain::normal_root::RootStartResourceCompletedOriginalV2, RootHostLaunchClientClosedV1>
    {
        if self.first.is_some() || !matches!(self.disposition, Some(Ok(()))) {
            return Err(RootHostLaunchClientClosedV1);
        }
        self.root.borrow_completed_resource_v2()
    }

    pub(super) fn completed_models_v2(
        &self,
    ) -> Result<
        (
            &aos_sandbox_controller_domain::normal_root::RootStartResourceCompletedOriginalV2,
            &aos_sandbox_broker_session_security::controller_composition::StartResourceCompletedModelsOriginalV2,
        ),
        RootHostLaunchClientClosedV1,
    > {
        let completed = self.completed_resource_v2()?;
        let models = self.io.completed_models_v2().ok_or(RootHostLaunchClientClosedV1)?;
        Ok((completed, models))
    }

    pub(in crate::controller_service::effects) fn new() -> Self {
        Self::new_kind_v2(ResourceKindV2::Network)
    }

    pub(in crate::controller_service::effects) fn mount_namespace_v2() -> Self {
        Self::new_kind_v2(ResourceKindV2::Mount)
    }

    pub(in crate::controller_service::effects) fn storage_guest_root_v2() -> Self {
        Self::new_kind_v2(ResourceKindV2::Storage)
    }

    pub(in crate::controller_service::effects) fn host_launch_v2() -> Self {
        Self::new_kind_v2(ResourceKindV2::Host)
    }

    fn new_kind_v2(kind: ResourceKindV2) -> Self {
        Self {
            kind,
            prepared: Box::new(match kind {
            ResourceKindV2::Network => PreparedStartResourceRequestOriginalV2::new(),
            ResourceKindV2::Storage => PreparedStartResourceRequestOriginalV2::storage_guest_root_v2(),
            ResourceKindV2::Mount => PreparedStartResourceRequestOriginalV2::mount_namespace_v2(),
            ResourceKindV2::Host => PreparedStartResourceRequestOriginalV2::host_launch_v2(),
        }),
            root: Box::new(RootHostLaunchClientOriginalV1::new()),
            content: None,
            root_entry: None,
            construction: None,
            models: None,
            signing: None,
            guardian_signing: None,
            guardian_signature: None,
            guardian_signed: None,
            guardian_check: None,
            publication_body: None,
            host_content_body: None,
            signing_clock: None,
            signature: None,
            signed: None,
            signed_check: None,
            body: None,
            posts: None,
            join: None,
            binding: None,
            opening: Box::new(match kind {
            ResourceKindV2::Network => StartResourceSessionOpeningOriginalV2::new(),
            ResourceKindV2::Storage => StartResourceSessionOpeningOriginalV2::new(),
            ResourceKindV2::Mount => StartResourceSessionOpeningOriginalV2::mount_namespace_v2(),
            ResourceKindV2::Host => StartResourceSessionOpeningOriginalV2::host_catalog_v2(),
        }),
            session: Box::new(StartResourceSessionOpenOriginalV4::new()),
            opening_entry: None,
            opening_body: None,
            opening_sdk: None,
            opening_storage: None,
            opening_storage_original_selected: false,
            opening_original_failure_selected: false,
            opening_posts: None,
            opening_survivors: None,
            opening_shape: None,
            opening_handoff: None,
            io: Box::new(resource_io::ResourceIoV2::new(kind)),
            final_proof: final_proof::ResourceCompletionV2::new(kind),
            disposition: None,
            host_publication: Box::new(host_publication::HostPublicationV2::new()),
            rejoin: Box::new(aos_sandbox_controller_domain::StartHostSessionRejoinOriginalV2::new()),
            first: None,
        }
    }

    pub(in crate::controller_service::effects) fn progress_preparation_once_v2(
        &mut self,
        entry: &mut AcceptedStartEntryOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1,
        driver: &Driver,
        create: &OriginalCreateProvisioningIssuerV1,
        signer: &ControllerBrokerPlanSignerV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.kind != ResourceKindV2::Network { return Err(ResourceReservationErrorV1::Conflict); }
        self.progress_resource_preparation_once_v2(entry, intake, driver, create, signer,
            controller, source, None, None, None)
    }

    pub(in crate::controller_service::effects) fn progress_mount_preparation_once_v2(
        &mut self,
        entry: &mut AcceptedStartEntryOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1,
        driver: &Driver,
        create: &OriginalCreateProvisioningIssuerV1,
        signer: &ControllerBrokerPlanSignerV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        predecessor: &aos_sandbox_controller_domain::normal_root::RootStartResourceCompletedOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.kind != ResourceKindV2::Mount { return Err(ResourceReservationErrorV1::Conflict); }
        self.progress_resource_preparation_once_v2(entry, intake, driver, create, signer,
            controller, source, Some(predecessor), None, None)
    }

    pub(in crate::controller_service::effects) fn progress_storage_preparation_once_v2(
        &mut self,
        entry: &mut AcceptedStartEntryOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1,
        driver: &Driver,
        create: &OriginalCreateProvisioningIssuerV1,
        signer: &ControllerBrokerPlanSignerV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        session: &mut super::super::super::inventory::DormantStorageLifecycleInventoryOwnerV1,
        predecessor: &aos_sandbox_controller_domain::normal_root::RootStartResourceCompletedOriginalV2,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.kind != ResourceKindV2::Storage { return Err(ResourceReservationErrorV1::Conflict); }
        let previous = create.native.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let mut storage = StorageContextV2 { previous, session };
        self.progress_resource_preparation_once_v2(entry, intake, driver, create, signer,
            controller, source, Some(predecessor), Some(&mut storage), None)
    }

    pub(in crate::controller_service::effects) fn progress_host_preparation_once_v2(
        &mut self, entry: &mut AcceptedStartEntryOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, driver: &Driver,
        create: &OriginalCreateProvisioningIssuerV1, signer: &ControllerBrokerPlanSignerV1,
        controller: &mut Journal, source: &ProtectedSourceDomainJournalOwnerV1,
        models: CompletedModelsV2<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.kind != ResourceKindV2::Host { return Err(ResourceReservationErrorV1::Conflict); }
        self.progress_resource_preparation_once_v2(entry, intake, driver, create, signer,
            controller, source, Some(models[2].0), None, Some(&models))
    }

    fn progress_resource_preparation_once_v2(
        &mut self,
        entry: &mut AcceptedStartEntryOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1,
        driver: &Driver,
        create: &OriginalCreateProvisioningIssuerV1,
        signer: &ControllerBrokerPlanSignerV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        predecessor: Option<&aos_sandbox_controller_domain::normal_root::RootStartResourceCompletedOriginalV2>,
        mut storage: Option<&mut StorageContextV2<'_>>,
        host_models: Option<&CompletedModelsV2<'_>>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.first.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if let Some(disposition) = &self.disposition {
            // This is quiescent historical completion, not a new native grant.
            return disposition.as_ref().map(|_| ()).map_err(|_| ResourceReservationErrorV1::Conflict);
        }
        if self.binding.is_some() {
            self.require_prepared_v2()?;
            if self.opening_posts.is_some() {
                self.require_opened_session_v2()?;
                if self.io.completed_v2() {
                    return self.finish_current_resource_once_v2(entry, intake, controller, source);
                }
                let result = self.io.progress_once_v2(
                    entry,
                    intake,
                    controller,
                    source,
                    &mut self.root,
                    &mut self.session,
                    &self.opening,
                    &self.prepared,
                    storage.as_deref_mut(),
                );
                if result.is_err() {
                    self.first = Some(First::ResourceIo);
                    return result;
                }
                if self.kind == ResourceKindV2::Storage && self.io.completed_v2() {
                    // The outer concrete Session MutexGuard is still held.
                    // Root observes the actual final EOF and sends ACK before
                    // any ordinary writer can acquire this same Storage Session.
                    return self.finish_current_resource_once_v2(entry, intake, controller, source);
                }
                return result;
            }
            if self.kind == ResourceKindV2::Host {
                let publication = self.host_publication.progress_once_v2(entry, intake,
                    controller, source, &mut self.root, &self.prepared,
                    &mut self.session, &mut self.opening);
                if publication.is_err() {
                    self.first = Some(First::HostPublication);
                    return publication;
                }
            }
            return self.progress_session_opening_once_v2(entry, intake, controller, source, storage.as_deref_mut());
        }

        self.content = Some(match self.kind {
            ResourceKindV2::Network => entry.prepare_network_content_once_v2(
                &mut self.prepared, intake, controller, source),
            ResourceKindV2::Storage => match predecessor {
                Some(predecessor) => entry.prepare_storage_content_once_v2(
                    &mut self.prepared, predecessor, intake, controller, source),
                None => Err(ResourceReservationErrorV1::Conflict),
            },
            ResourceKindV2::Mount => match predecessor {
                Some(predecessor) => entry.prepare_mount_content_once_v2(
                    &mut self.prepared, predecessor, intake, controller, source),
                None => Err(ResourceReservationErrorV1::Conflict),
            },
            ResourceKindV2::Host => match host_models {
                Some(models) => self.prepare_host_content_once_v2(entry, intake, controller, source, models),
                None => Err(ResourceReservationErrorV1::Conflict),
            },
        });
        if !matches!(self.content, Some(Ok(()))) {
            self.first.get_or_insert(First::Content);
            return Err(ResourceReservationErrorV1::Conflict);
        }

        self.root_entry = Some((|| -> Result<(), Cause> {
            create.require_healthy()?;
            if !create.final_exchange.completed_v1() {
                return Err(Box::new(OriginalCreateProvisioningClosedV1));
            }
            let parent = create.parent.ok_or(OriginalCreateProvisioningClosedV1)?;
            let preparation = driver.completed_preparation_data_v1(intake, parent)?;
            let ready = driver.completed_ready_bytes_v1(intake, parent)?;
            match self.kind {
            ResourceKindV2::Network => entry.begin_network_root_once_v1(
                &mut self.root,
                intake,
                controller,
                source,
                ready,
                preparation.outcome(),
                &self.prepared,
            ),
            ResourceKindV2::Storage => entry.begin_storage_root_once_v2(
                &mut self.root,
                intake,
                controller,
                source,
                ready,
                preparation.outcome(),
                &self.prepared,
            ),
            ResourceKindV2::Mount => entry.begin_mount_root_once_v2(
                &mut self.root,
                intake,
                controller,
                source,
                ready,
                preparation.outcome(),
                &self.prepared,
            ),
            ResourceKindV2::Host => entry.begin_host_root_once_v2(
                &mut self.root,
                intake,
                controller,
                source,
                ready,
                preparation.outcome(),
                &self.prepared,
            ),
        }?;
            Ok(())
        })());
        if !matches!(self.root_entry, Some(Ok(()))) {
            self.first = Some(First::Root);
            return Err(ResourceReservationErrorV1::Conflict);
        }

        self.construction = Some(match self.kind {
            ResourceKindV2::Network => entry.begin_network_construction_turn_once_v2(
            &mut self.root,
            intake,
            controller,
            source,
        ),
            ResourceKindV2::Storage => entry.begin_storage_construction_turn_once_v2(
            &mut self.root,
            intake,
            controller,
            source,
        ),
            ResourceKindV2::Mount => entry.begin_mount_construction_turn_once_v2(
            &mut self.root,
            intake,
            controller,
            source,
        ),
            ResourceKindV2::Host => entry.begin_host_construction_turn_once_v2(
            &mut self.root,
            intake,
            controller,
            source,
        ),
        });
        if matches!(self.construction, Some(Ok(()))) {
            self.construct_paid_body_v2(entry, intake, signer, controller, source);
        } else {
            self.first = Some(First::Construction);
        }

        // The body is retained before either post. These calls remain owed on
        // every entered outcome, including failed entry, sealing or signing.
        let body = if matches!(self.body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootHostLaunchClientClosedV1)
        };
        self.posts = Some(match self.kind {
            ResourceKindV2::Network => entry.finish_network_root_turn_once_v2(&mut self.root, controller, body),
            ResourceKindV2::Storage => entry.finish_storage_root_turn_once_v2(&mut self.root, controller, body),
            ResourceKindV2::Mount => entry.finish_mount_root_turn_once_v2(&mut self.root, controller, body),
            ResourceKindV2::Host => entry.finish_host_root_turn_once_v2(&mut self.root, controller, body),
        });
        if !matches!(self.posts, Some(Ok(()))) {
            self.first.get_or_insert(First::Posts);
        }
        if self.first.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }

        self.join = Some(
            self.prepared
                .finish_construction_after_posts_once_v2(&self.root, entry, controller),
        );
        if !matches!(self.join, Some(Ok(()))) {
            self.first = Some(First::Join);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.binding = Some(match self.kind {
            ResourceKindV2::Network => self.root.bind_network_preparation_once_v2(
            &self.prepared,
            entry,
            controller,
        ),
            ResourceKindV2::Storage => self.root.bind_storage_preparation_once_v2(
            &self.prepared,
            entry,
            controller,
        ),
            ResourceKindV2::Mount => self.root.bind_mount_preparation_once_v2(
            &self.prepared,
            entry,
            controller,
        ),
            ResourceKindV2::Host => self.root.bind_host_preparation_once_v2(
            &self.prepared,
            entry,
            controller,
        ),
        });
        if !matches!(self.binding, Some(Ok(()))) {
            self.first = Some(First::Binding);
        }
        self.require_prepared_v2()
    }

    fn finish_current_resource_once_v2(
        &mut self,
        entry: &mut AcceptedStartEntryOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let result = self.final_proof.progress_once_v2(
            self.kind,
            entry,
            intake,
            controller,
            source,
            &mut self.root,
            &self.io,
        );
        if result.is_err() {
            self.first = Some(First::FinalProof);
            return result;
        }

        // Root owns the exact signed packet comparison DATA. These positive
        // signing representations have no future native obligation and retire
        // before the completed resource's resident handoff.
        self.signing = None;
        self.signed = None;
        self.signature = None;
        if self.kind == ResourceKindV2::Host {
            self.guardian_signing = None;
            self.guardian_signed = None;
            self.guardian_signature = None;
        }
        self.disposition = Some(match self.root.borrow_completed_resource_v2() {
            Ok(completed) => self.io.dispose_completed_once_v2(
                &mut self.session,
                &mut self.opening,
                &mut self.prepared,
                completed,
                entry,
                controller,
            ),
            Err(_) => Err(StartResourceSessionClosedV4),
        });
        if !matches!(self.disposition, Some(Ok(()))) {
            self.first = Some(First::Disposition);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    fn construct_paid_body_v2(
        &mut self,
        entry: &mut AcceptedStartEntryOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1,
        signer: &ControllerBrokerPlanSignerV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
    ) {
        self.body = Some((|| -> Result<(), Cause> {
            let mut loan = entry.borrow_host_root_v1(intake, controller, source)?;
            let (authority, scope) = signer.start_resource_plan_inputs_v2(&self.prepared)?;
            {
                let admission = match self.kind {
            ResourceKindV2::Network => self.root.borrow_network_prepare_admission_v1(&loan, controller),
            ResourceKindV2::Storage => self.root.borrow_storage_prepare_admission_v2(&loan, controller),
            ResourceKindV2::Mount => self.root.borrow_mount_prepare_admission_v2(&loan, controller),
            ResourceKindV2::Host => self.root.borrow_host_prepare_admission_v2(&loan, controller),
        }?;
                let construction = match self.kind {
            ResourceKindV2::Network => self.root.borrow_network_construction_v2(&loan, controller),
            ResourceKindV2::Storage => self.root.borrow_storage_construction_v2(&loan, controller),
            ResourceKindV2::Mount => self.root.borrow_mount_construction_v2(&loan, controller),
            ResourceKindV2::Host => self.root.borrow_host_construction_v2(&loan, controller),
        }?;
                self.models = Some(self.prepared.prepare_admitted_once_v2(
                    &mut loan,
                    controller,
                    &admission,
                    &construction,
                    authority,
                    scope,
                ));
                if !matches!(self.models, Some(Ok(()))) {
                    self.first = Some(First::Models);
                    return Err(Box::new(OriginalCreateProvisioningClosedV1));
                }
                if self.kind == ResourceKindV2::Host {
                    self.guardian_signing = Some(signer.prepare_original_start_guardian_plan_v2(
                        &self.prepared, &admission, &construction, &loan, controller));
                    if !matches!(self.guardian_signing, Some(Ok(_))) {
                        self.first = Some(First::GuardianSigner);
                        return Err(Box::new(OriginalCreateProvisioningClosedV1));
                    }
                }
                self.signing = Some(signer.prepare_original_start_resource_plan_v2(
                    &self.prepared,
                    &admission,
                    &construction,
                    &loan,
                    controller,
                ));
            }
            let signing = self
                .signing
                .as_mut()
                .and_then(|value| value.as_mut().ok())
                .ok_or_else(|| {
                    self.first = Some(First::Signer);
                    OriginalCreateProvisioningClosedV1
                })?;
            let key_message = signing.key_message_loan()?;
            let guardian_message = if self.kind == ResourceKindV2::Host {
                Some(self.guardian_signing.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or(OriginalCreateProvisioningClosedV1)?.key_message_loan()?)
            } else { None };
            self.signing_clock = Some(
                match self.kind {
            ResourceKindV2::Network => self.root.final_network_signing_clock_once_v2(&loan, controller),
            ResourceKindV2::Storage => self.root.final_storage_signing_clock_once_v2(&loan, controller),
            ResourceKindV2::Mount => self.root.final_mount_signing_clock_once_v2(&loan, controller),
            ResourceKindV2::Host => self.root.final_host_signing_clock_once_v2(&loan, controller),
        },
            );
            let now = *self
                .signing_clock
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or_else(|| {
                    self.first = Some(First::SigningClock);
                    OriginalCreateProvisioningClosedV1
                })?;

            let admission = match self.kind {
            ResourceKindV2::Network => self.root.borrow_network_prepare_admission_v1(&loan, controller),
            ResourceKindV2::Storage => self.root.borrow_storage_prepare_admission_v2(&loan, controller),
            ResourceKindV2::Mount => self.root.borrow_mount_prepare_admission_v2(&loan, controller),
            ResourceKindV2::Host => self.root.borrow_host_prepare_admission_v2(&loan, controller),
        }?;
            let construction = match self.kind {
            ResourceKindV2::Network => self.root.borrow_network_construction_v2(&loan, controller),
            ResourceKindV2::Storage => self.root.borrow_storage_construction_v2(&loan, controller),
            ResourceKindV2::Mount => self.root.borrow_mount_construction_v2(&loan, controller),
            ResourceKindV2::Host => self.root.borrow_host_construction_v2(&loan, controller),
        }?;
            self.prepared
                .signing_preparation_v2(&admission, &construction, &loan, controller)?;
            if let Some(message) = guardian_message {
                self.guardian_signature = Some(message.sign());
                let signature = self.guardian_signature.as_ref().ok_or(OriginalCreateProvisioningClosedV1)?;
                let guardian = self.guardian_signing.as_mut().and_then(|value| value.as_mut().ok())
                    .ok_or(OriginalCreateProvisioningClosedV1)?;
                self.guardian_signed = Some(guardian.complete_once(signature, now.wall_seconds()));
                let signed = self.guardian_signed.as_ref().and_then(|value| value.as_ref().ok())
                    .ok_or_else(|| { self.first = Some(First::GuardianCompletion); OriginalCreateProvisioningClosedV1 })?;
                self.guardian_check = Some(self.prepared.retain_guardian_signed_once_v2(
                    signed, &admission, &construction, &loan, controller));
                if !matches!(self.guardian_check, Some(Ok(()))) {
                    self.first = Some(First::GuardianCheck);
                    return Err(Box::new(OriginalCreateProvisioningClosedV1));
                }
            }
            self.signature = Some(key_message.sign());
            let signature = self
                .signature
                .as_ref()
                .ok_or(OriginalCreateProvisioningClosedV1)?;
            self.signed = Some(signing.complete_once(signature, now.wall_seconds()));
            let signed = self
                .signed
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or_else(|| {
                    self.first = Some(First::Completion);
                    OriginalCreateProvisioningClosedV1
                })?;
            self.signed_check = Some(self.prepared.retain_signed_once_v2(
                signed,
                &admission,
                &construction,
                &loan,
                controller,
            ));
            if !matches!(self.signed_check, Some(Ok(()))) {
                self.first = Some(First::Models);
                return Err(Box::new(OriginalCreateProvisioningClosedV1));
            }
            if self.kind == ResourceKindV2::Host {
                self.publication_body = Some(self.prepared.construct_host_publication_once_v2(
                    &mut loan, controller, &admission, &construction));
                if !matches!(self.publication_body, Some(Ok(()))) {
                    self.first = Some(First::HostPublication);
                    return Err(Box::new(OriginalCreateProvisioningClosedV1));
                }
            }
            Ok(())
        })());
        if matches!(self.body, Some(Err(_))) {
            self.first.get_or_insert(First::Body);
        }
    }

    fn prepare_host_content_once_v2(
        &mut self, entry: &mut AcceptedStartEntryOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1, controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1, models: &CompletedModelsV2<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        let entered = entry.begin_host_content_once_v2(
            &self.prepared, intake, controller, source, models[2].0);
        if entered.is_ok() {
            self.host_content_body = Some((|| -> Result<(), Cause> {
                let mut loan = entry.borrow_host_root_v1(intake, controller, source)?;
                let network = models[0].1.network_v2(models[0].0, &loan, controller)?;
                let storage = models[1].1.storage_v2(models[1].0, &loan, controller)?;
                let (namespace, destinations) = models[2].1.mount_v2(models[2].0, &loan, controller)?;
                self.prepared.prepare_host_content_once_v2(&mut loan, controller,
                    models[0].0, models[1].0, models[2].0,
                    network, storage, namespace, destinations)?;
                Ok(())
            })());
            if !matches!(self.host_content_body, Some(Ok(()))) {
                self.first = Some(First::HostContent);
            }
        }
        // The Entry owns the original next/body/native after Results. Even a
        // failed model borrow runs the independently owed content C-after.
        let after = entry.finish_host_content_once_v2(
            &mut self.prepared, intake, controller, source);
        entered?;
        after?;
        if self.first.is_some() { Err(ResourceReservationErrorV1::Conflict) } else { Ok(()) }
    }

    fn require_prepared_v2(&self) -> Result<(), ResourceReservationErrorV1> {
        if self.first.is_some() || !matches!(self.binding, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.prepared
            .request_body_v2()
            .map(|_| ())
            .map_err(|_| ResourceReservationErrorV1::Conflict)
    }

    fn progress_session_opening_once_v2(
        &mut self,
        entry: &mut AcceptedStartEntryOriginalV1,
        intake: &CreateContinuationIntakeAttemptV1,
        controller: &mut Journal,
        source: &ProtectedSourceDomainJournalOwnerV1,
        mut storage: Option<&mut StorageContextV2<'_>>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.opening_posts.is_some() {
            return self.require_opened_session_v2();
        }

        self.opening_entry = Some(match self.kind {
            ResourceKindV2::Network => entry.begin_network_session_opening_turn_once_v2(
            &mut self.root,
            intake,
            controller,
            source,
        ),
            ResourceKindV2::Storage => entry.begin_storage_session_opening_turn_once_v2(
            &mut self.root,
            intake,
            controller,
            source,
        ),
            ResourceKindV2::Mount => entry.begin_mount_session_opening_turn_once_v2(
            &mut self.root,
            intake,
            controller,
            source,
        ),
            ResourceKindV2::Host => entry.begin_host_session_opening_turn_once_v2(
            &mut self.root,
            intake,
            controller,
            source,
        ),
        });
        if matches!(self.opening_entry, Some(Ok(()))) {
            self.opening_body = Some((|| -> Result<(), OpeningError> {
                let mut start = entry.borrow_host_root_v1(intake, controller, source)?;
                let root = match self.kind {
            ResourceKindV2::Network => self.root.borrow_network_current_turn_v2(&start, controller),
            ResourceKindV2::Storage => self.root.borrow_storage_current_turn_v2(&start, controller),
            ResourceKindV2::Mount => self.root.borrow_mount_current_turn_v2(&start, controller),
            ResourceKindV2::Host => self.root.borrow_host_current_turn_v2(&start, controller),
        }?;
                if self.kind == ResourceKindV2::Storage {
                    let context = storage.as_deref_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
                    self.opening_storage = Some(context.session.rejoin_original_start_storage_once_v2(
                        self.io.flights_mut_v2(), &mut start, &root, context.previous, controller));
                    if !matches!(self.opening_storage, Some(Ok(()))) {
                        self.opening_storage_original_selected =
                            start.retained_storage_session_failure_is_selected_v2();
                        self.first = Some(First::OpeningStorage);
                        return Err(OpeningError::Loan(ResourceReservationErrorV1::Conflict));
                    }
                    return Ok(());
                }
                if self.kind == ResourceKindV2::Host {
                    self.opening_sdk = Some(self.session.rejoin_host_once_v2(
                        &self.opening, &mut start, &root, controller, &mut self.rejoin));
                    if !matches!(self.opening_sdk, Some(Ok(()))) {
                        self.first = Some(First::OpeningSdk);
                        return Err(OpeningError::Session(StartResourceSessionClosedV4));
                    }
                    return Ok(());
                }
                let mut opening =
                    match self.kind {
            ResourceKindV2::Network => start.borrow_network_opening_once_v2(&root, &mut self.opening, controller),
            ResourceKindV2::Storage => return Err(OpeningError::Loan(ResourceReservationErrorV1::Conflict)),
            ResourceKindV2::Mount => start.borrow_mount_opening_once_v2(&root, &mut self.opening, controller),
            ResourceKindV2::Host => return Err(OpeningError::Loan(ResourceReservationErrorV1::Conflict)),
        }?;

                self.opening_sdk = Some(self.session.open_once_v4(&mut opening));
                if !matches!(self.opening_sdk, Some(Ok(()))) {
                    // Capture the SDK's body-boundary selection before either
                    // independent outer post can poison a later native lane.
                    self.opening_original_failure_selected =
                        self.session.native_original_failure_selected_v4();
                    self.first = Some(First::OpeningSdk);
                    return Err(OpeningError::Session(StartResourceSessionClosedV4));
                }
                Ok(())
            })());
            if matches!(self.opening_body, Some(Err(_))) {
                self.first.get_or_insert(First::OpeningBody);
            }
        } else {
            self.first = Some(First::OpeningEntry);
        }

        // C and Root each retain their own owed observations after the SDK
        // result is resident, including refused opening and partial HELLO.
        let body = if matches!(self.opening_body, Some(Ok(()))) {
            Ok(())
        } else {
            Err(RootHostLaunchClientClosedV1)
        };
        self.opening_posts =
            Some(match self.kind {
            ResourceKindV2::Network => entry.finish_network_root_turn_once_v2(&mut self.root, controller, body),
            ResourceKindV2::Storage => entry.finish_storage_root_turn_once_v2(&mut self.root, controller, body),
            ResourceKindV2::Mount => entry.finish_mount_root_turn_once_v2(&mut self.root, controller, body),
            ResourceKindV2::Host => entry.finish_host_root_turn_once_v2(&mut self.root, controller, body),
        });
        if !matches!(self.opening_posts, Some(Ok(()))) {
            self.first.get_or_insert(First::OpeningPosts);
        }
        if self.first.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }

        if self.kind == ResourceKindV2::Host {
            self.opening_handoff = Some(self.rejoin.retire_positive_once_v2(entry, &self.root, controller));
            if !matches!(self.opening_handoff, Some(Ok(()))) { self.first = Some(First::OpeningHandoff); }
            return self.require_opened_session_v2();
        }

        if self.kind == ResourceKindV2::Storage {
            self.opening_handoff = Some(entry.retain_completed_storage_session_once_v2(&self.root, controller));
            if !matches!(self.opening_handoff, Some(Ok(()))) { self.first = Some(First::OpeningHandoff); }
            return self.require_opened_session_v2();
        }

        if self.opening.completed_session_association_v4().is_none() {
            self.first = Some(First::OpeningAssociation);
            return Err(ResourceReservationErrorV1::Conflict);
        }

        self.opening_survivors = Some(self.session.completed_receiving_demand_v4(&self.opening));
        let Some(Ok(demand)) = self.opening_survivors.as_ref() else {
            self.first = Some(First::OpeningSurvivors);
            return Err(ResourceReservationErrorV1::Conflict);
        };
        self.opening_shape = Some((|| {
            use aos_sandbox_model::ResourceDimension as D;

            let shape = aos_sandbox_controller_domain::StartResourceSessionResidentShapeDataV4 {
                memory_bytes: demand.get(D::MemoryBytes),
                open_files: demand.get(D::OpenFiles),
                namespace_entries: demand.get(D::MetadataEntries),
            };
            let allowed = ResourceVector::ZERO
                .with(D::MemoryBytes, shape.memory_bytes)
                .with(D::OpenFiles, shape.open_files)
                .with(D::MetadataEntries, shape.namespace_entries);
            if *demand != allowed {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok(shape)
        })());
        let Some(Ok(shape)) = self.opening_shape.as_ref() else {
            self.first = Some(First::OpeningResidentShape);
            return Err(ResourceReservationErrorV1::Conflict);
        };

        // This passive handoff checks the actual completed opening's invoice.
        // The next C turn must pay these survivors before any resource IO.
        self.opening_handoff = Some(match self.kind {
            ResourceKindV2::Network => entry.retain_completed_network_session_once_v4(
            &self.opening,
            &self.root,
            controller,
            *shape,
        ),
            ResourceKindV2::Storage => return Err(ResourceReservationErrorV1::Conflict),
            ResourceKindV2::Mount => entry.retain_completed_mount_session_once_v4(
            &self.opening,
            &self.root,
            controller,
            *shape,
        ),
            ResourceKindV2::Host => return Err(ResourceReservationErrorV1::Conflict),
        });
        if !matches!(self.opening_handoff, Some(Ok(()))) {
            self.first = Some(First::OpeningHandoff);
        }
        self.require_opened_session_v2()
    }

    fn require_opened_session_v2(&self) -> Result<(), ResourceReservationErrorV1> {
        if self.first.is_some()
            || !matches!(self.opening_posts, Some(Ok(())))
            || !matches!(self.opening_handoff, Some(Ok(())))
            || (self.kind != ResourceKindV2::Storage
                && self.opening.completed_session_association_v4().is_none())
            || (self.kind == ResourceKindV2::Storage && !matches!(self.opening_storage, Some(Ok(()))))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(in crate::controller_service::effects) fn failure_with_entry_v2<'held>(
        &'held self,
        entry: &'held AcceptedStartEntryOriginalV1,
    ) -> Option<&'held (dyn Error + 'static)> {
        let first = self.first?;
        let cause = match first {
            First::Content => {
                if match self.kind {
            ResourceKindV2::Network => entry.network_content_failure_is_selected_v2(),
            ResourceKindV2::Storage => entry.storage_content_failure_is_selected_v2(),
            ResourceKindV2::Mount => entry.mount_content_failure_is_selected_v2(),
            ResourceKindV2::Host => entry.host_content_failure_is_selected_v2(),
        } {
                    self.prepared.failure().or_else(|| entry.failure())
                } else {
                    entry.failure().or_else(|| self.prepared.failure())
                }
            }
            First::Root
            | First::Construction
            | First::Posts
            | First::OpeningEntry
            | First::OpeningPosts => {
                if self.root_failure_is_selected_v2(entry) {
                    self.root.failure()
                } else {
                    entry.failure().or_else(|| self.root.failure())
                }
            }
            First::SigningClock => self.root.failure().or_else(|| {
                self.signing_clock
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            First::Models | First::Join | First::GuardianCheck => self.prepared.failure(),
            First::GuardianSigner => self.guardian_signing.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::GuardianCompletion => self.guardian_signed.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::HostContent => self.prepared.failure().or_else(|| {
                self.host_content_body.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _)
            }),
            First::HostPublication => self.host_publication.failure_v2(entry, &self.root, &self.session, &self.opening)
                .or_else(|| self.prepared.failure()),
            First::Signer => self
                .signing
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref() as _),
            First::Completion => self.signed.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Body => self
                .body
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause.as_ref() as _),
            First::Binding => self.root.failure(),
            First::OpeningBody => self
                .opening_body
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::OpeningSdk => {
                if self.opening_original_failure_selected {
                    entry.resource_opening_failure_with_original_v4(&self.opening)
                } else {
                    self.rejoin.failure().or_else(|| self.session.failure()).or_else(|| self.opening.failure())
                }
            }
            First::OpeningStorage => {
                if self.opening_storage_original_selected { entry.failure() }
                else { self.opening_storage.as_ref()?.as_ref().err().map(|cause| cause as _) }
            },
            First::OpeningAssociation => self.opening.failure(),
            First::OpeningSurvivors => self
                .opening_survivors
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::OpeningResidentShape => self
                .opening_shape
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::OpeningHandoff => entry.failure().or_else(|| {
                self.opening_handoff
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            First::ResourceIo => {
                self.io
                    .failure_with_entry_v2(entry, &self.opening, &self.prepared, &self.root)
            }
            First::FinalProof => self.final_proof.failure_v2(entry, &self.root),
            First::Disposition => entry.failure()
                .or_else(|| self.opening.failure())
                .or_else(|| self.session.failure())
                .or_else(|| self.io.disposition_failure_v2())
                .or_else(|| self.disposition.as_ref()?.as_ref().err().map(|cause| cause as _)),
        };
        cause
            .or_else(|| {
                self.root_entry
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref() as _)
            })
            .or(Some(&ResourceReservationErrorV1::Conflict))
    }

    fn root_failure_is_selected_v2(&self, entry: &AcceptedStartEntryOriginalV1) -> bool {
        match self.first {
            Some(First::Root) => match self.kind {
            ResourceKindV2::Network => entry.network_root_failure_is_selected_v1(),
            ResourceKindV2::Storage => entry.storage_root_failure_is_selected_v2(),
            ResourceKindV2::Mount => entry.mount_root_failure_is_selected_v2(),
            ResourceKindV2::Host => entry.host_root_failure_is_selected_v2(),
        },
            Some(
                First::Construction | First::Posts | First::OpeningEntry | First::OpeningPosts,
            ) => match self.kind {
            ResourceKindV2::Network => entry.network_current_turn_root_failure_is_selected_v2(),
            ResourceKindV2::Storage => entry.storage_current_turn_root_failure_is_selected_v2(),
            ResourceKindV2::Mount => entry.mount_current_turn_root_failure_is_selected_v2(),
            ResourceKindV2::Host => entry.host_current_turn_root_failure_is_selected_v2(),
        },
            Some(First::SigningClock | First::Binding) => true,
            _ => false,
        }
    }

    pub(in crate::controller_service::effects) fn fmt_failure_with_entry_v2(
        &self,
        entry: &AcceptedStartEntryOriginalV1,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        // Runtime's earlier body selection has priority over both independent
        // posts. Only the actual selected native owner lends its rich archive.
        if matches!(self.first, Some(First::ResourceIo)) {
            return self.io.fmt_failure_with_entry_v2(
                entry,
                &self.opening,
                &self.prepared,
                &self.root,
                formatter,
            );
        } else if matches!(self.first, Some(First::OpeningSdk))
            && self.opening_original_failure_selected
        {
            return entry.fmt_resource_opening_failure_v4(&self.opening, formatter);
        } else if self.root_failure_is_selected_v2(entry) {
            if let Some(view) = self.root.failure_view_v2() {
                return std::fmt::Display::fmt(&view, formatter);
            }
        } else if matches!(self.first, Some(First::Content))
            && match self.kind {
            ResourceKindV2::Network => entry.network_content_failure_is_selected_v2(),
            ResourceKindV2::Storage => entry.storage_content_failure_is_selected_v2(),
            ResourceKindV2::Mount => entry.mount_content_failure_is_selected_v2(),
            ResourceKindV2::Host => entry.host_content_failure_is_selected_v2(),
        }
        {
            if let Some(cause) = self.prepared.failure() {
                return std::fmt::Display::fmt(cause, formatter);
            }
        } else if matches!(
            self.first,
            Some(
                First::Content
                    | First::Root
                    | First::Construction
                    | First::Posts
                    | First::OpeningEntry
                    | First::OpeningPosts
                    | First::OpeningHandoff
            )
        ) && entry.failure().is_some()
        {
            return entry.fmt_failure_v1(formatter);
        }
        match self.failure_with_entry_v2(entry) {
            Some(cause) => std::fmt::Display::fmt(cause, formatter),
            None => formatter.write_str("the original Start resource failure is unavailable"),
        }
    }
}
