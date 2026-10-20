//! Retains actual Delete key/message/result custody through independent posts.
//!
//! The same exclusive collection supplies its fresh Storage preimage. Only the
//! genuine Bank borrower enters construction; this owner never signs raw plans
//! or adopts decoded Root data as authority. A failed body always closes the
//! primary and runs the actual independently prepaid C/Root/clock afters.

use super::*;
use aos_sandbox_broker::prepared_plan_signing::{PreparedBrokerPlanSigningV1,
    PreparedBrokerPlanCompletionErrorV1};
use aos_sandbox_core::model::SignatureBytes;
use aos_sandbox_protocol::domain_ledger::delete_root::inventory_cuts::DeleteSessionInventoryCutDataV2;
use aos_sandbox_protocol::domain_ledger::delete_root::resource_exchange::DeleteRootResourcePurposeDataV3;
use crate::controller_service::plan_signer::ControllerBrokerPlanSignerV1;

type Cause = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy)]
enum First { Entry, Inputs, Native, Body, Key, Completion, After, Reentry }

#[derive(Default)]
pub(super) struct ControllerDeleteResourceSigningOriginalV2 {
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    inputs: Option<Result<(), crate::controller_service::plan_signer::ControllerBrokerPlanSignerError>>,
    key: Option<Result<PreparedBrokerPlanSigningV1, Box<dyn std::error::Error + Send + Sync>>>,
    signature: Option<SignatureBytes>,
    completion: Option<Result<(), PreparedBrokerPlanCompletionErrorV1>>,
    body: Option<Result<(), Cause>>,
    after: Option<Result<(), ResourceReservationErrorV1>>,
    first: Option<First>,
    entered: bool,
}

impl ControllerDeleteResourceSigningOriginalV2 {
    pub(super) fn sign_once_v2(&mut self, bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        pending: &mut aos_sandbox::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        local: &ControllerDeleteLocalRuntimeFieldsV1<'_>,
        model: &aos_sandbox::lifecycle::DeletePlanningBrokerInventoryDataV2,
        session: DeleteSessionInventoryCutDataV2<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.sign_inner_v3(bank, pending, client, controller, profile, local,
            model, session, DeleteRootResourcePurposeDataV3::Preparation26)
    }

    pub(super) fn sign_apply_once_v3(&mut self, bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        pending: &mut aos_sandbox::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        local: &ControllerDeleteLocalRuntimeFieldsV1<'_>,
        model: &aos_sandbox::lifecycle::DeletePlanningBrokerInventoryDataV2,
        session: DeleteSessionInventoryCutDataV2<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.sign_inner_v3(bank, pending, client, controller, profile, local,
            model, session, DeleteRootResourcePurposeDataV3::Apply7)
    }

    pub(super) fn sign_network_once_v4(&mut self, bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        pending: &mut aos_sandbox::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'_>, controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        local: &ControllerDeleteLocalRuntimeFieldsV1<'_>,
        model: &aos_sandbox::lifecycle::DeletePlanningBrokerInventoryDataV2,
        session: DeleteSessionInventoryCutDataV2<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.sign_inner_v3(bank, pending, client, controller, profile, local,
            model, session, DeleteRootResourcePurposeDataV3::Network9)
    }

    pub(super) fn sign_mount_once_v4(&mut self, bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        pending: &mut aos_sandbox::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'_>, controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        local: &ControllerDeleteLocalRuntimeFieldsV1<'_>,
        model: &aos_sandbox::lifecycle::DeletePlanningBrokerInventoryDataV2,
        session: DeleteSessionInventoryCutDataV2<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.sign_inner_v3(bank, pending, client, controller, profile, local,
            model, session, DeleteRootResourcePurposeDataV3::MountReap62)
    }

    fn sign_inner_v3(&mut self, bank: &aos_sandbox::ControllerResourceBankOpeningV1,
        pending: &mut aos_sandbox::ControllerDeletePendingOriginalV2<'_, '_>,
        client: &mut aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'_>,
        controller: &mut Journal,
        profile: &aos_sandbox::normal_root::ProductionControllerNormalRootProfileV1,
        local: &ControllerDeleteLocalRuntimeFieldsV1<'_>,
        model: &aos_sandbox::lifecycle::DeletePlanningBrokerInventoryDataV2,
        session: DeleteSessionInventoryCutDataV2<'_>,
        purpose: DeleteRootResourcePurposeDataV3,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.entered = true;
        let signer = local.signer.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let configuration = local.ownership.get().ok_or(ResourceReservationErrorV1::Conflict)?;
        let verifier = configuration.verifier();
        let (authority, scope) = match signer.create_plan_inputs_v1() {
            Ok(inputs) => { self.inputs = Some(Ok(())); inputs }
            Err(error) => {
                self.inputs = Some(Err(error)); self.first = Some(First::Inputs);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        let entry = match purpose {
            DeleteRootResourcePurposeDataV3::MountReap62 =>
                bank.begin_retained_delete_mount_resource_signing_once_v4(
                    pending, client, controller, profile, authority, verifier),
            DeleteRootResourcePurposeDataV3::Preparation26 =>
                bank.begin_retained_delete_resource_signing_once_v2(
                    pending, client, controller, profile, authority, verifier),
            DeleteRootResourcePurposeDataV3::Apply7 =>
                bank.begin_retained_delete_apply_resource_signing_once_v3(
                    pending, client, controller, profile, authority, verifier),
            DeleteRootResourcePurposeDataV3::Network9 =>
                bank.begin_retained_delete_network_resource_signing_once_v4(
                    pending, client, controller, profile, authority, verifier),
        };
        let mut loan = match entry {
            Ok(loan) => { self.entry = Some(Ok(())); loan }
            Err(error) => {
                self.entry = Some(Err(error)); self.first = Some(First::Entry);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        };
        self.body = Some((|| {
            loan.prepare_once_v2(controller, model, session, authority, scope, verifier)?;
            // Close the original gate before classifying a key-constructor
            // failure; the signer repeats the same pure gate before expansion.
            loan.signing_preparation_v2(controller)?;
            self.key = Some(signer.prepare_original_delete_resource_plan_v2(&mut loan, controller));
            let key = match self.key.as_mut().and_then(|r| r.as_mut().ok()) {
                Some(key) => key,
                None => { self.first = Some(First::Key); return Err(ResourceReservationErrorV1::Conflict.into()); }
            };
            let key_message = match key.key_message_loan() {
                Ok(message) => message,
                Err(error) => { self.first = Some(First::Body); return Err(Box::new(error) as Cause); }
            };
            let now = loan.final_signing_clock_once_v2(controller)?;
            self.signature = Some(key_message.sign());
            let signature = self.signature.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
            let signed = match key.complete_once(signature, now.wall_seconds()) {
                Ok(signed) => { self.completion = Some(Ok(())); signed }
                Err(error) => {
                    self.completion = Some(Err(error)); self.first = Some(First::Completion);
                    return Err(ResourceReservationErrorV1::Conflict.into());
                }
            };
            loan.send_signed_once_v2(controller, signed)?;
            Ok(())
        })());
        if !matches!(self.body, Some(Ok(()))) {
            self.first.get_or_insert(First::Native);
            loan.refuse_signer_once_v2();
        }
        // No fallible body exit skips these independently paid destinations.
        self.after = Some(loan.finish_once_v2(controller));
        if !matches!(self.after, Some(Ok(()))) { self.first.get_or_insert(First::After); }
        drop(loan);
        if self.first.is_some() { return Err(ResourceReservationErrorV1::Conflict); }
        // Only wholly successful pure crypto scratch is retired. The actual
        // signed plan/request remains on the client; failed key owners stay.
        drop(self.key.take());
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Entry => self.entry.as_ref()?.as_ref().err().map(|e| e as _),
            First::Inputs => self.inputs.as_ref()?.as_ref().err().map(|e| e as _),
            First::Body => self.body.as_ref()?.as_ref().err().map(|e| e.as_ref() as &(dyn std::error::Error + 'static)),
            First::Key => self.key.as_ref()?.as_ref().err().map(|e| e.as_ref() as _),
            First::Completion => self.completion.as_ref()?.as_ref().err().map(|e| e as _),
            First::Native => self.body.as_ref()?.as_ref().err().map(|e| e.as_ref() as &(dyn std::error::Error + 'static)),
            First::After => self.after.as_ref()?.as_ref().err().map(|e| e as _),
            First::Reentry => None,
        }
    }
}

/// Formats the actual selected cause while both custody owners remain borrowed.
pub(super) struct SigningFailureViewV2<'borrow, 'profile, 'scope, 'original> {
    signing: &'borrow ControllerDeleteResourceSigningOriginalV2,
    source_readiness_failed: bool,
    preparation: &'borrow super::preparation::ControllerDeleteStoragePreparationOriginalV3,
    apply: &'borrow super::apply::ControllerDeleteStorageApplyOriginalV3,
    network: &'borrow super::network_apply::ControllerDeleteNetworkApplyOriginalV4,
    host_confirmation: &'borrow super::host_confirmation::ControllerDeleteHostConfirmationOriginalV4,
    mount: &'borrow super::mount::ControllerDeleteMountReapOriginalV4,
    apply_root_failed: bool,
    client: &'borrow aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'profile>,
    pending: &'borrow aos_sandbox::ControllerDeletePendingOriginalV2<'scope, 'original>,
}

impl std::fmt::Display for SigningFailureViewV2<'_, '_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.preparation.failed() {
            if self.preparation.original_selected() {
                if self.pending.delete_preparation_root_failure_is_selected_v3() {
                    return std::fmt::Display::fmt(&self.client.failure_view_v2(self.pending), f);
                }
                return match self.pending.failure() {
                    Some(cause) => std::fmt::Display::fmt(cause, f),
                    None => f.write_str("Delete26 original remains closed with custody retained"),
                };
            }
            return match self.preparation.failure() {
                Some(cause) => std::fmt::Display::fmt(cause, f),
                None => f.write_str("Delete26 SDK remains closed with custody retained"),
            };
        }
        if self.source_readiness_failed {
            if self.pending.source_readiness_root_failure_is_selected_v3() {
                return std::fmt::Display::fmt(&self.client.failure_view_v2(self.pending), f);
            }
            return match self.pending.failure() {
                Some(cause) => std::fmt::Display::fmt(cause, f),
                None => f.write_str("Delete Source readiness failure is unavailable"),
            };
        }
        if self.apply.failed() {
            if self.apply.original_selected() {
                if self.pending.delete_apply_root_failure_is_selected_v3() {
                    return std::fmt::Display::fmt(&self.client.failure_view_v2(self.pending), f);
                }
                return match self.pending.failure() {
                    Some(cause) => std::fmt::Display::fmt(cause, f),
                    None => f.write_str("Delete7 original remains closed with custody retained"),
                };
            }
            return match self.apply.failure() {
                Some(cause) => std::fmt::Display::fmt(cause, f),
                None => f.write_str("Delete7 SDK remains closed with custody retained"),
            };
        }
        if self.network.failed() {
            if self.network.original_selected() {
                if self.pending.delete_network_root_failure_is_selected_v4() {
                    return std::fmt::Display::fmt(&self.client.failure_view_v2(self.pending), f);
                }
                return match self.pending.failure() {
                    Some(cause) => std::fmt::Display::fmt(cause, f),
                    None => f.write_str("Delete9 original remains closed with custody retained"),
                };
            }
            return match self.network.failure() {
                Some(cause) => std::fmt::Display::fmt(cause, f),
                None => f.write_str("Delete9 SDK remains closed with custody retained"),
            };
        }
        if self.host_confirmation.failed_v4() {
            if self.client.host_cleanup_original_failure_is_selected_v4(self.pending) {
                return std::fmt::Display::fmt(&self.client.failure_view_v2(self.pending), f);
            }
            return match self.pending.failure().or_else(|| self.host_confirmation.failure_v4()) {
                Some(cause) => std::fmt::Display::fmt(cause, f),
                None => f.write_str("Delete Host confirmation remains closed with custody retained"),
            };
        }
        if self.mount.failed() {
            if self.mount.original_selected() {
                if self.pending.delete_mount_root_failure_is_selected_v4() {
                    return std::fmt::Display::fmt(&self.client.failure_view_v2(self.pending), f);
                }
                return match self.pending.failure() {
                    Some(cause) => std::fmt::Display::fmt(cause, f),
                    None => f.write_str("Delete Mount original remains closed with custody retained"),
                };
            }
            return match self.mount.failure() {
                Some(cause) => std::fmt::Display::fmt(cause, f),
                None => f.write_str("Delete Mount SDK remains closed with custody retained"),
            };
        }
        if self.apply_root_failed {
            return std::fmt::Display::fmt(&self.client.failure_view_v2(self.pending), f);
        }
        if self.client.resource_signing_original_failure_is_selected_v2() {
            return std::fmt::Display::fmt(&self.client.failure_view_v2(self.pending), f);
        }
        match self.signing.failure() {
            Some(error) => std::fmt::Display::fmt(error, f),
            None => f.write_str("Delete resource signing failure is unavailable"),
        }
    }
}

impl<'sessions, 'cache, 'profile> ControllerDeletePlanningCollectionV2<'sessions, 'cache, 'profile> {
    /// Lends the selected guarded original or external signing cause.
    pub(in crate::controller_service) fn resource_signing_failure_view_v2<'borrow, 'client, 'scope, 'original>(
        &'borrow self,
        client: &'borrow aos_sandbox::ControllerDeletePendingRootClientOriginalV2<'client>,
        pending: &'borrow aos_sandbox::ControllerDeletePendingOriginalV2<'scope, 'original>,
    ) -> impl std::fmt::Display + 'borrow {
        let signing = if self.mount_resource_signing.entered {
            &self.mount_resource_signing
        } else if self.network_resource_signing.entered {
            &self.network_resource_signing
        } else if self.apply_resource_signing.entered {
            &self.apply_resource_signing
        } else {
            &self.resource_signing
        };
        SigningFailureViewV2 { signing, preparation: &self.storage_preparation,
            apply: &self.storage_apply, network: &self.network_apply,
            host_confirmation: &self.host_confirmation,
            mount: &self.mount_reap,
            apply_root_failed: matches!(self.apply_resource_exchange, Some(Err(_)))
                || matches!(self.apply_approval, Some(Err(_)))
                || matches!(self.network_resource_exchange, Some(Err(_)))
                || matches!(self.network_approval, Some(Err(_)))
                || matches!(self.mount_resource_exchange, Some(Err(_)))
                || matches!(self.mount_approval, Some(Err(_))),
            source_readiness_failed: matches!(self.source_readiness, Some(Err(_)))
                || matches!(self.controller_acceptance, Some(Err(_)))
                || matches!(self.source_completion, Some(Err(_))), client, pending }
    }
}
