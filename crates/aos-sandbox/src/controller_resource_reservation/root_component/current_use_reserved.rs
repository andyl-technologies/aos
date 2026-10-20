//! Funds the actual reserved-use turn and fresh Controller read under the same R.

use crate::normal_root::{NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1};
use crate::policy_compiler::create_storage_current::{
    controller_readonly::RootCurrentControllerReadonlyStateV1,
    source_current::{RootCurrentSourceQueryStateV1, RootCurrentSourceExchangeStateV1},
    cache_current::RootCurrentCacheProofStateV1,
    ready::RootCurrentReadyStateV1,
    pins::RootCurrentPinsStateV1,
    ownership_trust::RootCurrentOwnershipTrustStateV1,
    bundle_ownership::RootCurrentBundleOwnershipStateV1,
    root_open::RootCurrentOpenStateV1,
    use_authorized::RootCurrentUseAuthorizedStateV1,
    use_reserved::{RootCurrentUseReservedStateV1, received::RootCurrentUseReservedReceivedV1},
};
use super::{RootReceivingOriginalV1,
    current_controller_readonly::RootCurrentControllerReadonlyProvisionV1,
    current_provision::{RootCurrentProvisionV1, RootCurrentStageV1}};
use super::super::ResourceReservationErrorV1;

#[derive(Default)]
pub(super) struct RootCurrentUseReservedProvisionV1 {
    pub(super) frame: RootCurrentProvisionV1,
    pub(super) read: RootCurrentControllerReadonlyProvisionV1,
    pub(super) second_query: RootCurrentProvisionV1,
    pub(super) second_source: RootCurrentProvisionV1,
    pub(super) second_cache: RootCurrentProvisionV1,
}

impl RootCurrentUseReservedProvisionV1 {
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.frame.failure().or_else(|| self.read.failure())
            .or_else(|| self.second_query.failure())
            .or_else(|| self.second_source.failure())
            .or_else(|| self.second_cache.failure())
    }
}

#[derive(Clone, Copy)]
enum UseReadStageV1 { Fixed, Native, Semantic }

impl RootReceivingOriginalV1 {
    fn require_use_original(&self, root: &RootCurrentOpenStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1) -> Result<(), Error>
    {
        if self.failure().is_some() || authorization.require_complete_v1().is_err()
            || root.completed_receiver().map_err(|_| Error::Service)?
                != self.current_root_open_original_pair().map_err(|_| Error::Service)?
        { return Err(Error::Service); }
        let open = root.completed_body().map_err(|_| Error::Service)?;
        let body = authorization.completed_body_v1().map_err(|_| Error::Service)?;
        if body.root_nonce != open.root_nonce || body.ready != open.open.ready
            || body.association.controller_nonce != open.open.controller_nonce
        { return Err(Error::Service); }
        Ok(())
    }

    fn use_read_prefix(&self, stage: UseReadStageV1) -> Option<aos_sandbox_core::ResourceVector> {
        let read = &self.current_use_reserved_provision.as_ref()?.read;
        match stage {
            UseReadStageV1::Fixed => read.fixed.completed_prefix(),
            UseReadStageV1::Native => read.native.completed_prefix(),
            UseReadStageV1::Semantic => read.semantic.completed_prefix(),
        }
    }

    pub(crate) fn prepay_current_use_reserved_frame_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1) -> Result<(), Error>
    {
        if self.current_use_reserved_provision.is_some() || self.failure().is_some() {
            self.activation.latch_root_refusal_v1(); return Err(Error::Service);
        }
        self.current_use_reserved_provision = Some(Default::default());
        let permit = (|| {
            self.require_use_original(root, authorization)
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let base = self.current_use_authorized_provision.as_ref()
                .and_then(|stage| stage.completed_prefix())
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let complete = base.checked_add(RootCurrentUseReservedStateV1::frame_fixed_demand_v1()?)
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_use_reserved_provision.as_mut().ok_or(Error::Service)?.frame.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::UseReservedFrame)
    }

    pub(crate) fn prepay_current_use_controller_readonly_fixed_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1, received: &RootCurrentUseReservedReceivedV1)
        -> Result<(), Error>
    {
        self.require_use_original(root, authorization)?;
        if self.current_use_reserved_provision.as_ref().is_none_or(|stage| stage.read.fixed.permit.is_some())
            || received.require_received_v1().is_err()
        { self.activation.latch_root_refusal_v1(); return Err(Error::Service); }
        let permit = (|| {
            let base = self.current_use_reserved_provision.as_ref().and_then(|stage| stage.frame.completed_prefix())
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let complete = base.checked_add(RootCurrentControllerReadonlyStateV1::reserved_fixed_demand_v1()?)
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_use_reserved_provision.as_mut().ok_or(Error::Service)?.read.fixed.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::UseControllerReadonlyFixed)
    }

    pub(crate) fn prepay_current_use_controller_readonly_native_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1, state: &RootCurrentControllerReadonlyStateV1)
        -> Result<(), Error>
    {
        self.require_current_use_controller_readonly_fixed(root, authorization)?;
        if self.current_use_reserved_provision.as_ref().is_none_or(|stage| stage.read.native.permit.is_some()) {
            self.activation.latch_root_refusal_v1(); return Err(Error::Service);
        }
        let permit = (|| {
            let base = self.use_read_prefix(UseReadStageV1::Fixed)
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let complete = base.checked_add(state.additional_native_demand_v1()?)
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_use_reserved_provision.as_mut().ok_or(Error::Service)?.read.native.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::UseControllerReadonlyNative)
    }

    pub(crate) fn prepay_current_use_controller_readonly_semantic_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1, state: &RootCurrentControllerReadonlyStateV1)
        -> Result<(), Error>
    {
        self.require_use_original(root, authorization)?;
        if self.use_read_prefix(UseReadStageV1::Native).is_none()
            || self.current_use_reserved_provision.as_ref().is_none_or(|stage| stage.read.semantic.permit.is_some())
        { self.activation.latch_root_refusal_v1(); return Err(Error::Service); }
        let permit = (|| {
            let base = self.use_read_prefix(UseReadStageV1::Native)
                .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let complete = base.checked_add(state.additional_semantic_demand_v1()?)
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        self.native_refusal_original_v1().park_empty_result_v1(
            &mut self.current_use_reserved_provision.as_mut().ok_or(Error::Service)?.read.semantic.permit, permit,
        );
        self.finish_current_provision_once(startup, RootCurrentStageV1::UseControllerReadonlySemantic)
    }

    pub(crate) fn require_current_use_controller_readonly_fixed(&self,
        root: &RootCurrentOpenStateV1, authorization: &RootCurrentUseAuthorizedStateV1) -> Result<(), Error>
    {
        self.require_use_original(root, authorization)?;
        self.use_read_prefix(UseReadStageV1::Fixed).map(|_| ()).ok_or(Error::Service)
    }

    pub(crate) fn require_current_use_controller_readonly_semantic(&self,
        root: &RootCurrentOpenStateV1, authorization: &RootCurrentUseAuthorizedStateV1) -> Result<(), Error>
    {
        self.require_use_original(root, authorization)?;
        self.use_read_prefix(UseReadStageV1::Semantic).map(|_| ()).ok_or(Error::Service)
    }
}

/// Names only the three actual fixed continuations after the reserved read.
enum UseProofStageV1<'current> {
    Query {
        ready: &'current RootCurrentReadyStateV1,
        trust: &'current RootCurrentOwnershipTrustStateV1,
    },
    Source {
        ready: &'current RootCurrentReadyStateV1,
        query: &'current RootCurrentSourceQueryStateV1,
    },
    Cache {
        source: &'current RootCurrentSourceExchangeStateV1,
        pins: &'current RootCurrentPinsStateV1,
        ownership: &'current RootCurrentBundleOwnershipStateV1,
    },
}

impl RootReceivingOriginalV1 {
    pub(crate) fn prepay_current_use_source_query_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
        ready: &RootCurrentReadyStateV1, trust: &RootCurrentOwnershipTrustStateV1,
    ) -> Result<(), Error> {
        self.prepay_use_proof_once(startup, root, authorization, reserved,
            UseProofStageV1::Query { ready, trust })
    }

    pub(crate) fn prepay_current_use_source_exchange_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
        ready: &RootCurrentReadyStateV1, query: &RootCurrentSourceQueryStateV1,
    ) -> Result<(), Error> {
        self.prepay_use_proof_once(startup, root, authorization, reserved,
            UseProofStageV1::Source { ready, query })
    }

    pub(crate) fn prepay_current_use_cache_current_once(&mut self,
        startup: &ProductionNormalRootStartupV1, root: &RootCurrentOpenStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
        source: &RootCurrentSourceExchangeStateV1, pins: &RootCurrentPinsStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1,
    ) -> Result<(), Error> {
        self.prepay_use_proof_once(startup, root, authorization, reserved,
            UseProofStageV1::Cache { source, pins, ownership })
    }

    fn prepay_use_proof_once(&mut self, startup: &ProductionNormalRootStartupV1,
        root: &RootCurrentOpenStateV1, authorization: &RootCurrentUseAuthorizedStateV1,
        reserved: &RootCurrentUseReservedStateV1, stage: UseProofStageV1<'_>,
    ) -> Result<(), Error> {
        self.require_use_original(root, authorization)?;
        reserved.require_complete_v1().map_err(|_| Error::Service)?;
        let current = self.current_use_reserved_provision.as_ref().ok_or(Error::Service)?;
        let attempted = match &stage {
            UseProofStageV1::Query { .. } => current.second_query.permit.is_some(),
            UseProofStageV1::Source { .. } => current.second_source.permit.is_some(),
            UseProofStageV1::Cache { .. } => current.second_cache.permit.is_some(),
        };
        if attempted {
            self.activation.latch_root_refusal_v1();
            return Err(Error::Service);
        }
        let permit = (|| {
            let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
            let current = self.current_use_reserved_provision.as_ref().ok_or_else(invalid)?;
            let (base, additional) = match &stage {
                UseProofStageV1::Query { ready, trust } => {
                    ready.raw_ready_bytes().map_err(|_| invalid())?;
                    trust.require_complete().map_err(|_| invalid())?;
                    (current.read.semantic.completed_prefix(), RootCurrentSourceQueryStateV1::fixed_demand_v1()?)
                }
                UseProofStageV1::Source { ready, query } => {
                    query.require_complete_for_v1(root, ready).map_err(|_| invalid())?;
                    (current.second_query.completed_prefix(), RootCurrentSourceExchangeStateV1::fixed_demand_v1()?)
                }
                UseProofStageV1::Cache { source, pins, ownership } => {
                    source.require_use_complete_for_v1(root, authorization, reserved).map_err(|_| invalid())?;
                    pins.require_complete().map_err(|_| invalid())?;
                    ownership.require_complete_v1().map_err(|_| invalid())?;
                    startup.current_cache_signer_identity_data_v1().map_err(|_| invalid())?;
                    (current.second_source.completed_prefix(), RootCurrentCacheProofStateV1::use_fixed_demand_v1()?)
                }
            };
            let complete = base.ok_or_else(invalid)?.checked_add(additional).map_err(|_| invalid())?;
            self.require_receiving_demand_v1(complete)?;
            Ok(complete)
        })();
        let refusal = self.native_refusal_original_v1();
        let current = self.current_use_reserved_provision.as_mut().ok_or(Error::Service)?;
        let target = match stage {
            UseProofStageV1::Query { .. } => {
                refusal.park_empty_result_v1(&mut current.second_query.permit, permit);
                RootCurrentStageV1::UseSourceQuery
            }
            UseProofStageV1::Source { .. } => {
                refusal.park_empty_result_v1(&mut current.second_source.permit, permit);
                RootCurrentStageV1::UseSourceExchange
            }
            UseProofStageV1::Cache { .. } => {
                refusal.park_empty_result_v1(&mut current.second_cache.permit, permit);
                RootCurrentStageV1::UseCacheCurrent
            }
        };
        self.finish_current_provision_once(startup, target)
    }

    /// Borrows the SAME completed cumulative R prefix after both fresh proofs.
    pub(crate) fn completed_use_current_prefix_v1(&self, root: &RootCurrentOpenStateV1,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
        source: &RootCurrentSourceExchangeStateV1, cache: &RootCurrentCacheProofStateV1,
    ) -> Result<aos_sandbox_core::ResourceVector, Error> {
        self.require_use_original(root, authorization)?;
        reserved.require_complete_v1().map_err(|_| Error::Service)?;
        source.require_use_complete_for_v1(root, authorization, reserved).map_err(|_| Error::Service)?;
        cache.require_use_complete_for_v1(root, authorization, reserved).map_err(|_| Error::Service)?;
        self.current_use_reserved_provision.as_ref()
            .and_then(|current| current.second_cache.completed_prefix()).ok_or(Error::Service)
    }
}
