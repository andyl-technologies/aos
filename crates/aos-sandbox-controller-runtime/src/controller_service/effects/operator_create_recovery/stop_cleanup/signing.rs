//! Lends the ordinary Controller key only to the actual held Stop Root draft.

use super::*;
use crate::controller_service::plan_signer::{
    ControllerBrokerPlanSignerV1, ControllerBrokerPlanSignerError,
};
use aos_sandbox::normal_root::{RootStopCleanupClientOriginalV1, RootStopCleanupClientClosedV1};
use aos_sandbox_broker::prepared_plan_signing::{
    PreparedBrokerPlanSigningV1, PreparedBrokerPlanCompletionErrorV1,
};
use aos_sandbox_core::model::SignatureBytes;
use aos_sandbox_ownership_protocol::OwnershipAuthorityVerifier;

type Cause = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy)]
enum First { Inputs, Entry, Key, Completion, Body, After, Reentry }

#[derive(Default)]
pub(super) struct StopCleanupSigningOriginalV1 {
    entered: bool,
    inputs: Option<Result<(), ControllerBrokerPlanSignerError>>,
    entry: Option<Result<(), RootStopCleanupClientClosedV1>>,
    key: Option<Result<PreparedBrokerPlanSigningV1, Cause>>,
    signature: Option<SignatureBytes>,
    completion: Option<Result<(), PreparedBrokerPlanCompletionErrorV1>>,
    body: Option<Result<(), Cause>>,
    after: Option<Result<(), RootStopCleanupClientClosedV1>>,
    first: Option<First>,
}

impl StopCleanupSigningOriginalV1 {
    pub(super) fn sign_once_v1(&mut self, root: &mut RootStopCleanupClientOriginalV1,
        source: &mut Source<'_, '_>, controller: &Journal,
        signer: &ControllerBrokerPlanSignerV1, verifier: &OwnershipAuthorityVerifier,
    ) -> Result<(), Closed> {
        if self.entered { self.first.get_or_insert(First::Reentry); return Err(Closed); }
        self.entered = true;
        let (authority, scope) = match signer.create_plan_inputs_v1() {
            Ok(value) => { self.inputs = Some(Ok(())); value }
            Err(cause) => { self.inputs = Some(Err(cause)); self.first = Some(First::Inputs); return Err(Closed); }
        };
        let mut loan = match root.begin_signing_once_v1(source, controller, authority, verifier, scope) {
            Ok(loan) => { self.entry = Some(Ok(())); loan }
            Err(cause) => { self.entry = Some(Err(cause)); self.first = Some(First::Entry); return Err(Closed); }
        };
        self.body = Some((|| {
            loan.signing_preparation_v1(controller)?;
            self.key = Some(signer.prepare_original_stop_cleanup_plan_v1(&loan, controller));
            let key = match self.key.as_mut().and_then(|value| value.as_mut().ok()) {
                Some(key) => key,
                None => { self.first = Some(First::Key); return Err(Box::new(Closed) as Cause); }
            };
            let message = key.key_message_loan()?;
            let now = loan.final_signing_clock_once_v1()?;
            self.signature = Some(message.sign());
            let signature = self.signature.as_ref().ok_or(Closed)?;
            let signed = match key.complete_once(signature, now.wall_seconds()) {
                Ok(signed) => { self.completion = Some(Ok(())); signed }
                Err(cause) => {
                    self.completion = Some(Err(cause)); self.first = Some(First::Completion);
                    return Err(Box::new(Closed) as Cause);
                }
            };
            loan.send_signed_once_v1(signed)?;
            Ok(())
        })());
        if !matches!(self.body, Some(Ok(()))) { self.first.get_or_insert(First::Body); }
        // The actual typed Root loan also drains this after during unwind.
        // Its interval cannot become positive after an uncompleted signature.
        self.after = Some(loan.finish_native_once_v1());
        if !matches!(self.after, Some(Ok(()))) { self.first.get_or_insert(First::After); }
        drop(loan);
        if self.first.is_some() { return Err(Closed); }
        Ok(())
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Inputs => error(&self.inputs),
            First::Entry => error(&self.entry),
            First::Key => self.key.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::Completion => error(&self.completion),
            First::Body => self.body.as_ref()?.as_ref().err().map(|cause| cause.as_ref() as _),
            First::After => error(&self.after),
            First::Reentry => None,
        }
    }
}

fn error<T, E: std::error::Error + 'static>(value: &Option<Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}
