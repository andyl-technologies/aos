//! Independently reconstructs Host catalog DATA from paid current resource readers.
//!
//! The protected Controller model and all three signed resource inventories
//! stay under their original native owners. This owner issues no catalog effect,
//! installed binding or Host permission; its result only feeds the paired plan.

use super::{
    compiler::RootStartResourceCompilerOriginalV2,
    current_storage::RootCurrentStoragePublicationOriginalV2, kind::ResourceKindV2,
    session::RootStartResourceFinalSessionOriginalV2,
};
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::journal::JournalError;
use crate::normal_root::RootHostLaunchStageReceivingV1;
use crate::policy_compiler::provisioning_current::{
    RootContinuationClockGateV1,
    apply_readonly::RootHostReadonlyContextV2,
    finality_readonly::{RootStartPreparationSessionReadOriginalV2, StartPreparationSessionKindV2},
};
use aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestV1;
use aos_sandbox_protocol::host_catalog_snapshot::HostCatalogSnapshot;

type Cause = Box<dyn std::error::Error>;

#[derive(Clone, Copy)]
enum Phase {
    NetworkRead,
    NetworkModel,
    MountRead,
    MountModel,
    Projection,
}

pub(super) struct RootHostCatalogInputsOriginalV2 {
    network: RootStartPreparationSessionReadOriginalV2,
    mount: RootStartPreparationSessionReadOriginalV2,
    network_model: Option<Box<RootStartResourceFinalSessionOriginalV2>>,
    mount_model: Option<Box<RootStartResourceFinalSessionOriginalV2>>,
    funding: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    catalog: Option<
        Result<
            HostCatalogSnapshot,
            crate::host_catalog_reconciliation::HostCatalogReconciliationError,
        >,
    >,
    result: Option<Result<(), Cause>>,
    phase: Phase,
    external_clock: bool,
    posts: bool,
    reentered: bool,
}

impl RootHostCatalogInputsOriginalV2 {
    pub(super) fn new() -> Self {
        Self {
            network: RootStartPreparationSessionReadOriginalV2::new(
                StartPreparationSessionKindV2::HostNetworkCatalog,
            ),
            mount: RootStartPreparationSessionReadOriginalV2::new(
                StartPreparationSessionKindV2::HostMountCatalog,
            ),
            network_model: None,
            mount_model: None,
            funding: None,
            catalog: None,
            result: None,
            phase: Phase::NetworkRead,
            external_clock: false,
            posts: false,
            reentered: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn observe_once_v2(
        &mut self,
        stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
        controller: &mut RootHostReadonlyContextV2,
        compiler: &RootStartResourceCompilerOriginalV2,
        storage: &RootCurrentStoragePublicationOriginalV2,
        network_manifest: &BrokerSessionManifestV1,
        mount_manifest: &BrokerSessionManifestV1,
        cutoff: u64,
    ) -> Result<(), JournalError> {
        if self.result.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.result = Some(self.observe_inner_v2(
            stage,
            clock,
            controller,
            compiler,
            storage,
            network_manifest,
            mount_manifest,
            cutoff,
        ));
        if matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn observe_inner_v2(
        &mut self,
        stage: &mut RootHostLaunchStageReceivingV1<'_, '_>,
        clock: &mut RootContinuationClockGateV1,
        controller: &mut RootHostReadonlyContextV2,
        compiler: &RootStartResourceCompilerOriginalV2,
        storage: &RootCurrentStoragePublicationOriginalV2,
        network_manifest: &BrokerSessionManifestV1,
        mount_manifest: &BrokerSessionManifestV1,
        cutoff: u64,
    ) -> Result<(), Cause> {
        storage.require_complete_v2()?;
        if let Err(cause) = self.network.observe_once_v2(stage, clock) {
            self.external_clock = self.network.failure().is_none() && clock.failure().is_some();
            return Err(cause.into());
        }
        self.phase = Phase::NetworkModel;
        // The reader's actual semantic invoice covers this whole model before
        // its Box, full signed history and retained method captures are built.
        self.network_model = Some(Box::new(RootStartResourceFinalSessionOriginalV2::new()));
        let sample = match clock.check_next_once_v1() {
            Ok(sample) => sample,
            Err(cause) => {
                self.external_clock = true;
                return Err(cause.into());
            }
        };
        self.network_model
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .observe_current_inventory_once_v2(
                self.network.session_v2()?,
                ResourceKindV2::Network,
                network_manifest,
                compiler,
                sample,
                cutoff,
            )?;

        self.phase = Phase::MountRead;
        if let Err(cause) = self.mount.observe_once_v2(stage, clock) {
            self.external_clock = self.mount.failure().is_none() && clock.failure().is_some();
            return Err(cause.into());
        }
        self.phase = Phase::MountModel;
        self.mount_model = Some(Box::new(RootStartResourceFinalSessionOriginalV2::new()));
        let sample = match clock.check_next_once_v1() {
            Ok(sample) => sample,
            Err(cause) => {
                self.external_clock = true;
                return Err(cause.into());
            }
        };
        self.mount_model
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?
            .observe_current_inventory_once_v2(
                self.mount.session_v2()?,
                ResourceKindV2::Mount,
                mount_manifest,
                compiler,
                sample,
                cutoff,
            )?;

        self.phase = Phase::Projection;
        let network = self
            .network_model
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .current_network_inventory_v2()?;
        let destinations = self
            .mount_model
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .current_mount_inventory_v2()?;
        let assignment = compiler.compiled_v2()?.manifest_v2();
        let mut namespaces = destinations.namespace_anchors_v1().iter().filter(|row| {
            row.fence().sandbox_id() == assignment.manifest().sandbox().as_bytes()
                && row.fence().incarnation_id() == assignment.manifest().incarnation().as_bytes()
                && row.namespace_generation() == assignment.manifest().namespace_generation().get()
        });
        let namespace = namespaces.next().ok_or(JournalError::ProtectedBoundary)?;
        if namespaces.next().is_some() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let journal = controller.controller_mut_v2()?;
        let demand = crate::host_catalog_reconciliation::start_projection_receiving_demand_data_v2(
            journal,
            storage.inventory_v2()?,
            network,
            destinations,
        )?;
        self.funding =
            Some(stage.admit_host_catalog_models_once_v2(
                RootContinuationDemandV1::from_demand_v1(demand),
            ));
        if !matches!(self.funding, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        match clock.check_next_once_v1() {
            Ok(_) => {}
            Err(cause) => {
                self.external_clock = true;
                return Err(cause.into());
            }
        }
        self.catalog = Some(
            crate::host_catalog_reconciliation::project_start_successor_catalog_data_v2(
                journal,
                compiler.previous_v2()?.manifest_v2(),
                assignment,
                compiler.specification_v2()?,
                storage.inventory_v2()?,
                network,
                destinations,
                namespace,
            ),
        );
        self.catalog
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .map(|_| ())
            .ok_or_else(|| JournalError::ProtectedBoundary.into())
    }

    pub(super) fn finish_posts_once_v2(&mut self) {
        if self.posts {
            return;
        }
        self.posts = true;
        // Each reader retains and attempts its own reached independent posts.
        self.network.finish_posts_once_v2();
        self.mount.finish_posts_once_v2();
    }

    pub(super) fn require_complete_v2(&self) -> Result<(), JournalError> {
        if self.reentered || !self.posts || !matches!(self.result, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.network.require_complete_v2()?;
        self.mount.require_complete_v2()?;
        self.network_model
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .require_complete_v2()?;
        self.mount_model
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .require_complete_v2()
    }

    pub(super) fn catalog_v2(&self) -> Result<&HostCatalogSnapshot, JournalError> {
        // Pair construction may precede the common outer post finisher; no
        // Root reply escapes until require_complete checks both native posts.
        if self.reentered || !matches!(self.result, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.catalog
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let selected = match self.phase {
            Phase::NetworkRead => self.network.failure(),
            Phase::NetworkModel => self
                .network_model
                .as_ref()
                .and_then(|model| model.failure()),
            Phase::MountRead => self.mount.failure(),
            Phase::MountModel => self.mount_model.as_ref().and_then(|model| model.failure()),
            Phase::Projection => self
                .funding
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| {
                    self.catalog
                        .as_ref()
                        .and_then(|value| value.as_ref().err())
                        .map(|cause| cause as _)
                }),
        };
        selected
            .or_else(|| {
                if self.external_clock {
                    None
                } else {
                    self.result
                        .as_ref()?
                        .as_ref()
                        .err()
                        .map(|cause| cause.as_ref())
                }
            })
            .or_else(|| {
                if matches!(self.result, Some(Err(_))) {
                    None
                } else {
                    self.network.failure().or_else(|| self.mount.failure())
                }
            })
            .or_else(|| self.reentered.then_some(&CLOSED as _))
    }
}

const CLOSED: JournalError = JournalError::ProtectedBoundary;
