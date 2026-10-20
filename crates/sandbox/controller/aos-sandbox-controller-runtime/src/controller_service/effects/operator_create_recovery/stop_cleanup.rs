//! Retains the genuine fresh Stop22, Host Session and continuously held Root.
//!
//! The disposed Recover prefix supplies only its exact accepted association.
//! Fresh native Source22 finances cold authentication, two actual Host queries,
//! the general signed Root plan and any intervening Host1. Source settlement,
//! Controller terminal metadata and positive disposal remain separate joins.

use super::*;
use aos_sandbox_controller_domain::controller_lifecycle_stop::{
    ControllerHostStopCleanupSourceLoanV1, ControllerLifecycleStopOriginalV4,
    ControllerHostStopCleanupCompletionV1,
};
use aos_sandbox_controller_domain::normal_root::{RootStopCleanupClientOriginalV1, RootStopCleanupClientClosedV1};
use aos_sandbox_broker_session_security::{
    OperatorStopCleanupSourceInventoryOriginalV1, OperatorStopCleanupSourceSessionOpenV1,
};
use crate::controller_service::plan_signer::ControllerBrokerPlanSignerV1;
use aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier;

mod host_apply;
mod signing;

type Source<'owner, 'source> = ControllerHostStopCleanupSourceLoanV1<'owner, 'source>;

pub(super) struct StopCleanupRecoveryOriginalV1 {
    entered: bool,
    original: Option<ControllerLifecycleStopOriginalV4>,
    // Prearmed under the startup carrier invoice. Positive retirement drops
    // this graph in place; it never constructs or moves a replacement SDK on
    // the reconciler's finite native stack.
    sdk: Option<Sdk>,
}

impl Default for StopCleanupRecoveryOriginalV1 {
    fn default() -> Self {
        Self {
            entered: false,
            original: None,
            sdk: Some(Sdk::default()),
        }
    }
}

#[derive(Default)]
struct Sdk {
    image: Option<Result<Pid1LaunchImageV1, Closed>>,
    cold: Option<Box<OperatorStopCleanupSourceSessionOpenV1>>,
    opened: Option<Result<(), BrokerSessionSecurityError>>,
    session: Option<Box<DormantAuthenticatedBrokerSessionV1>>,
    inventories: [Option<Box<OperatorStopCleanupSourceInventoryOriginalV1>>; 2],
    queries: [Option<Result<(), InventoryClosed>>; 2],
    bindings: [Option<Result<(), InventoryClosed>>; 2],
    root: Box<RootStopCleanupClientOriginalV1>,
    root_entry: Option<Result<(), RootStopCleanupClientClosedV1>>,
    signing: Box<signing::StopCleanupSigningOriginalV1>,
    apply: Box<host_apply::StopCleanupHostApplyOriginalV1>,
    child_body: Option<Result<(), Closed>>,
    child_after: Option<Result<(), RootStopCleanupClientClosedV1>>,
    root_finish: Option<Result<(), RootStopCleanupClientClosedV1>>,
    program: Option<Result<(), Closed>>,
    append: Option<aos_sandbox_controller_domain::lifecycle::StopCleanupSourceAppendOriginalV1>,
    appended: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
    terminal: Option<Result<(), aos_sandbox_controller_domain::ResourceReservationErrorV1>>,
}

// Taking the loan for positive disposal is permitted only after this guard
// has drained the independently owed Source/C/clock posts. Its Drop also
// drains them on body unwind, before releasing the actual Source reference.
struct SourcePosts<'owner, 'source, 'controller> {
    source: Option<Source<'owner, 'source>>,
    controller: &'controller mut Journal,
    finished: bool,
    result: Option<Result<(), Closed>>,
}

impl SourcePosts<'_, '_, '_> {
    fn finish(&mut self) -> Result<(), Closed> {
        if !self.finished {
            self.finished = true;
            self.result = Some(match self.source.as_mut() {
                Some(source) => source.finish_native_posts_once_v1(self.controller).map_err(|_| Closed),
                None => Err(Closed),
            });
        }
        self.result.unwrap_or(Err(Closed))
    }
}

impl Drop for SourcePosts<'_, '_, '_> {
    fn drop(&mut self) { let _ = self.finish(); }
}

impl StopCleanupRecoveryOriginalV1 {
    // Fixed destinations are prepaid by RuntimeFixed before the first constructor.
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            Sdk::inactive_receiving_bytes_v1(),
        ])
    }

    fn run_source_once(&mut self, controller: &mut Journal,
        source_domain: &mut aos_sandbox_controller_domain::source_domain::ProtectedSourceDomainJournalOwnerV1,
        completed: &aos_sandbox_controller_domain::OperatorStopCleanupRecoveryCompletedHandoffV1<'_>,
        signer: Option<&ControllerBrokerPlanSignerV1>, verifier: Option<&OwnershipAuthorityVerifier>,
    ) -> Result<(aos_sandbox_api::aos::sandbox::v1::Operation, ControllerHostStopCleanupCompletionV1), Closed> {
        let subject = completed.cleanup_subject_data_v1(controller, source_domain).map_err(|_| Closed)?;
        let association = completed.cleanup_association_data_v1(controller, source_domain).map_err(|_| Closed)?;
        // This is compiled geometry only: both the resident Runtime graph and
        // its real on-stack post guard are paid before Source entry. No second
        // instance is constructed to obtain this requirement.
        let source = ControllerLifecycleStopOriginalV4::begin_host_stop_cleanup_source_once_v1::<(Self, SourcePosts<'_, '_, '_>)>(
            &mut self.original, controller, source_domain, completed, subject, association)
            .map_err(|_| Closed)?;
        let mut posts = SourcePosts { source: Some(source), controller, finished: false, result: None };
        let body = (|| {
            let sdk = self.sdk.as_mut().ok_or(Closed)?;
            let source = posts.source.as_mut().ok_or(Closed)?;
            let controller = &mut *posts.controller;
            sdk.run_root_program_once(source, controller, signer, verifier)?;
            let root = sdk.root.borrow_completed_once_v1(source, controller).map_err(|_| Closed)?;
            let final_inventory = sdk.inventories[1].as_mut().ok_or(Closed)?;
            let proof = final_inventory.borrow_stop_cleanup_completion_once_v1(source, controller,
                root, sdk.session.as_ref().ok_or(Closed)?).map_err(|_| Closed)?;
            sdk.append = Some(aos_sandbox_controller_domain::lifecycle::StopCleanupSourceAppendOriginalV1::new());
            sdk.appended = Some(source.run_stop_completion_append_once_v1(controller,
                &proof, sdk.append.as_mut().ok_or(Closed)?));
            if !matches!(sdk.appended, Some(Ok(()))) { return Err(Closed); }
            drop(proof);
            // Commits the ordinary Stop terminal and current Recover success
            // together with any exact older pending Stop-cleanup Recover
            // supersession metadata, before the current Source22 interval
            // retires. The historical Source attempt remains byte-literal.
            sdk.terminal = Some(source.complete_controller_terminal_once_v1(controller,
                sdk.append.as_ref().ok_or(Closed)?));
            if !matches!(sdk.terminal, Some(Ok(()))) { return Err(Closed); }
            Ok(())
        })();
        if body.is_err() {
            if let Some(source) = posts.source.as_mut() { source.retain_cold_sdk_refusal_v1(); }
        }
        let after = posts.finish();
        if body.is_err() || after.is_err() {
            if let Some(sdk) = self.sdk.as_ref() { sdk.report_retained_causes(); }
            if let Some(cause) = posts.source.as_ref().and_then(|source| source.failure_v1()) {
                eprintln!("aos-sandboxd: Stop cleanup Source/C: {cause}");
            }
            return Err(Closed);
        }

        let source = posts.source.take().ok_or(Closed)?;
        // The pending owner retains the genuine Core slot and native originals.
        // SDK/Root/Session/cold destruction must precede in-place Core retirement
        // and release of the actual Source-only positive disposer.
        let pending = match source.prepare_positive_disposal_once_v1(posts.controller) {
            Ok(disposal) => disposal,
            Err(cause) => {
                if let Some(sdk) = self.sdk.as_ref() { sdk.report_retained_causes(); }
                eprintln!("aos-sandboxd: Stop cleanup positive-disposal preparation: {cause}");
                return Err(Closed);
            }
        };
        drop(posts);
        // Assignment destroys the same SDK in its resident slot. No default
        // graph is constructed and no whole SDK crosses a by-value boundary.
        self.sdk = None;
        let disposal = pending.retire_core_in_place_once_v1();
        disposal.complete_after_disposal_v1(controller).map_err(|cause| {
            eprintln!("aos-sandboxd: Stop cleanup positive Source/C disposition: {cause}");
            Closed
        })
    }
}

impl ProductionEffectExecutor {
    pub(super) fn complete_stop_cleanup_recovery_v1(&mut self,
        controller: &mut Journal, original: &mut OperatorCreateRecoveryOriginalV1,
    ) -> Result<(aos_sandbox_api::aos::sandbox::v1::Operation, ControllerHostStopCleanupCompletionV1), Closed> {
        let state = &mut self.operator_recover.stop_cleanup_recovery;
        if state.entered { return Err(Closed); }
        state.entered = true;
        let bank = self.resource_bank.as_ref().cloned().ok_or(Closed)?;
        let profile = self.execution_profile.as_ref().cloned().ok_or(Closed)?;
        let sdk = state.sdk.as_mut().ok_or(Closed)?;
        sdk.image = Some((|| {
            let sessions = self.sessions.lock().map_err(|_| Closed)?;
            sessions.launch_image.clone().ok_or(Closed)
        })());
        if !matches!(sdk.image, Some(Ok(_))) { return Err(Closed); }
        let completed = {
            let held = bank.lock().map_err(|_| Closed)?;
            original.completed_stop_cleanup_handoff_v1(&held, controller, &self.source_domains)
                .map_err(|_| Closed)?
        };
        let target = completed.target_operation_data_v1(controller).map_err(|_| Closed)?;
        state.original = Some(ControllerLifecycleStopOriginalV4::new_v4(target, bank, profile));
        // The fixed credential owner remains the existing process resident
        // owner. Only an effect decision opens its finite signing borrower;
        // observation-complete recovery never requires or uses a signature.
        let verifier = self.snapshot_ownership.as_ref().and_then(|ownership| ownership.get())
            .map(|ownership| ownership.verifier());
        state.run_source_once(controller, &mut self.source_domains, &completed,
            self.broker_plan_signer.as_ref(), verifier)
    }
}

impl Sdk {
    // Fixed destinations are prepaid by RuntimeFixed before the first constructor.
    pub(in crate::controller_service) fn inactive_receiving_bytes_v1() -> Option<usize> {
        use crate::controller_service::effects::resident_geometry::{boxed_bytes, sum_bytes};
        sum_bytes([
            boxed_bytes::<OperatorStopCleanupSourceSessionOpenV1>(),
            boxed_bytes::<DormantAuthenticatedBrokerSessionV1>(),
            boxed_bytes::<RootStopCleanupClientOriginalV1>(),
            boxed_bytes::<signing::StopCleanupSigningOriginalV1>(),
            boxed_bytes::<host_apply::StopCleanupHostApplyOriginalV1>(),
            boxed_bytes::<OperatorStopCleanupSourceInventoryOriginalV1>()?.checked_mul(2),
            host_apply::StopCleanupHostApplyOriginalV1::inactive_receiving_bytes_v1(),
        ])
    }

    fn observe_inventory_once(&mut self, source: &mut Source<'_, '_>, controller: &mut Journal,
        index: usize,
    ) -> Result<(), Closed> {
        // Only the two literal call sites below supply ordinals. The actual
        // Source22 borrower independently verifies ordering before native IO.
        let destination = self.inventories.get_mut(index).ok_or(Closed)?;
        if destination.is_some() { return Err(Closed); }
        *destination = Some(Default::default());
        let inventory = destination.as_mut().ok_or(Closed)?;
        let session = self.session.as_mut().ok_or(Closed)?;
        let cold = self.cold.as_ref().ok_or(Closed)?;
        self.queries[index] = Some(inventory.observe_once_v1(source, controller, cold, session, index));
        if !matches!(self.queries[index], Some(Ok(()))) { return Err(Closed); }
        self.bindings[index] = Some(inventory.bind_completed_inventory_once_v1(source, controller, session, index));
        if !matches!(self.bindings[index], Some(Ok(()))) { return Err(Closed); }
        Ok(())
    }

    fn run_root_program_once(&mut self, source: &mut Source<'_, '_>, controller: &mut Journal,
        signer: Option<&ControllerBrokerPlanSignerV1>, verifier: Option<&OwnershipAuthorityVerifier>,
    ) -> Result<(), Closed> {
        if self.program.is_some() { return Err(Closed); }
        self.program = Some((|| {
            let image = self.image.as_ref().and_then(|value| value.as_ref().ok()).cloned().ok_or(Closed)?;
            self.cold = Some(Default::default());
            self.opened = Some(self.cold.as_mut().ok_or(Closed)?.open_once_v1(source, controller, image));
            if !matches!(self.opened, Some(Ok(()))) { return Err(Closed); }
            self.session = self.cold.as_mut().ok_or(Closed)?.take_completed_once_v1().map(Box::new);
            self.observe_inventory_once(source, controller, 0)?;
            self.root_entry = Some(self.root.begin_once_v1(source, controller));
            if !matches!(self.root_entry, Some(Ok(()))) { return Err(Closed); }
            if self.root.requires_signing_v1(source, controller).map_err(|_| Closed)? {
                self.signing.sign_once_v1(&mut self.root, source, controller,
                    signer.ok_or(Closed)?, verifier.ok_or(Closed)?)?;
            }

            let mut child = self.root.begin_child_once_v1(source, controller).map_err(|_| Closed)?;
            self.child_body = Some((|| {
                source.bind_root_child_once_v1(controller, &child).map_err(|_| Closed)?;
                if child.effect_v1(source, controller).map_err(|_| Closed)?.is_some() {
                    self.apply.run_once_v1(source, controller, &child,
                        self.session.as_mut().ok_or(Closed)?)?;
                }
                // The observed-complete branch takes this same real second
                // Host3 without signing or Host1. It never reuses index0.
                if self.inventories[1].is_some() { return Err(Closed); }
                let inventory = self.inventories[1].insert(Default::default());
                let session = self.session.as_mut().ok_or(Closed)?;
                self.queries[1] = Some(inventory.observe_once_v1(source, controller,
                    self.cold.as_ref().ok_or(Closed)?, session, 1));
                if !matches!(self.queries[1], Some(Ok(()))) { return Err(Closed); }
                self.bindings[1] = Some(inventory.bind_completed_inventory_once_v1(
                    source, controller, session, 1));
                if !matches!(self.bindings[1], Some(Ok(()))) { return Err(Closed); }
                Ok(())
            })());
            self.child_after = Some(child.finish_native_once_v1(matches!(self.child_body, Some(Ok(())))));
            drop(child);
            if !matches!(self.child_body, Some(Ok(()))) || !matches!(self.child_after, Some(Ok(()))) {
                return Err(Closed);
            }
            self.root_finish = Some(self.root.finish_once_v1(source, controller));
            if !matches!(self.root_finish, Some(Ok(()))) { return Err(Closed); }
            Ok(())
        })());
        if !matches!(self.program, Some(Ok(()))) {
            source.retain_cold_sdk_refusal_v1();
            return Err(Closed);
        }
        Ok(())
    }

    fn report_retained_causes(&self) {
        if let Some(cause) = self.image.as_ref().and_then(|value| value.as_ref().err()) {
            eprintln!("aos-sandboxd: Stop cleanup launch image: {cause}");
        }
        if let Some(cause) = self.cold.as_ref().and_then(|cold| cold.failure_v1()) {
            eprintln!("aos-sandboxd: Stop cleanup cold Session: {cause}");
        }
        if let Some(cause) = self.opened.as_ref().and_then(|value| value.as_ref().err()) {
            eprintln!("aos-sandboxd: Stop cleanup cold result: {cause}");
        }
        for inventory in self.inventories.iter().flatten() {
            if let Some(cause) = self.session.as_ref().and_then(|session| inventory.failure_v1(session)) {
                eprintln!("aos-sandboxd: Stop cleanup Host inventory: {cause}");
            }
        }
        if let Some(cause) = self.signing.failure_v1() {
            eprintln!("aos-sandboxd: Stop cleanup Controller signing: {cause}");
        }
        if let Some(cause) = self.apply.failure_v1() {
            eprintln!("aos-sandboxd: Stop cleanup Host apply: {cause}");
        }
        if let Some(cause) = self.root.failure_v1() {
            eprintln!("aos-sandboxd: Stop cleanup Root exchange: {cause}");
        }
        if let Some(cause) = self.append.as_ref().and_then(|append| append.failure()) {
            eprintln!("aos-sandboxd: Stop cleanup native Source append: {cause}");
        }
        if let Some(cause) = self.appended.as_ref().and_then(|value| value.as_ref().err()) {
            eprintln!("aos-sandboxd: Stop cleanup Source append: {cause}");
        }
        if let Some(cause) = self.terminal.as_ref().and_then(|value| value.as_ref().err()) {
            eprintln!("aos-sandboxd: Stop cleanup Controller terminal: {cause}");
        }
    }
}
