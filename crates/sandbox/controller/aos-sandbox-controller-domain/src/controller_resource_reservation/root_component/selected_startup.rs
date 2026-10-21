//! Continues the same original Root receiving through selected startup.
//!
//! Fixed profile/kernel custody and actual selected-image demand share one
//! cumulative RootR permit. The completed startup and its original payer move
//! together; a failed handoff keeps the complete original inside its error.

use crate::normal_root::{NormalRootStartupErrorV1, ProductionNormalRootStartupV1,
    RootReceivingStartupFailureV1, RootSelectedStartupReceivingV1, RootServiceCurrentnessV1};

use super::RootReceivingOriginalV1;

impl RootReceivingOriginalV1 {
    pub(crate) fn into_selected_startup_parts(
        mut self,
        identities: [u32; 4],
    ) -> Result<(ProductionNormalRootStartupV1, Self), NormalRootStartupErrorV1> {
        if self.admit_selected_once(identities).is_err() {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Receiving(Box::new(
                RootReceivingStartupFailureV1::new(self),
            )));
        }
        // The sealed startup stays in its actual owner while the native
        // handoff is checked. A refusal cannot drop successful physical fields.
        let settled = match self.selected.as_ref().and_then(|selected| selected.completed()) {
            Some(startup) => self.activation.settle_serving_startup_once_v1(
                startup.native_startup_original_v1(),
            ),
            None => Err(aos_sandbox_broker::receiving::RootObservationErrorV1::Service),
        };
        if settled.is_err() {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Receiving(Box::new(
                RootReceivingStartupFailureV1::new(self),
            )));
        }
        let attachment = match self.selected.as_mut() {
            Some(selected) => selected.attach_serving_financial_once_v1(&mut self.activation),
            None => Err(NormalRootStartupErrorV1::Service),
        };
        if let Err(cause) = attachment {
            self.selected_completion = Some(Err(cause));
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Receiving(Box::new(
                RootReceivingStartupFailureV1::new(self),
            )));
        }
        let native_prior = self.activation.borrow_selected_provision_v1().map(|original| {
            aos_sandbox_policy::native::RootStartupProvisionOriginalV1::new_selected_v1(&original)
        });
        match native_prior {
            Ok(original) => self.native_startup_prior = Some(original),
            Err(cause) => {
                self.selected_completion = Some(Err(cause.into()));
                self.activation.latch_root_refusal_v1();
                return Err(NormalRootStartupErrorV1::Receiving(Box::new(
                    RootReceivingStartupFailureV1::new(self),
                )));
            }
        }
        let completed = self.selected.as_mut().and_then(|selected| selected.take_completed());
        let Some(startup) = completed else {
            self.activation.latch_root_refusal_v1();
            self.selected_completion = Some(Err(NormalRootStartupErrorV1::Service));
            return Err(NormalRootStartupErrorV1::Receiving(Box::new(
                RootReceivingStartupFailureV1::new(self),
            )));
        };
        Ok((startup, self))
    }

    fn admit_selected_once(&mut self, identities: [u32; 4]) -> Result<(), NormalRootStartupErrorV1> {
        if self.selected.is_some() || self.failure().is_some()
            || !matches!(self.recipient_binding, Some(Ok(())))
            || self.activation.process_id_v1() != std::process::id()
        {
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.activation.admit_role_selected_once_v1()
            .map_err(|_| NormalRootStartupErrorV1::Service)?;

        self.selected = Some(RootSelectedStartupReceivingV1::default());
        let returned = (|| {
            self.activation.prepare_startup_identity_once()?;
            let selected = self.selected.as_mut().ok_or(NormalRootStartupErrorV1::Service)?;
            selected.prepare_once(identities, &mut self.activation)?;
            selected.assemble_once(&mut self.activation)?;
            Ok(())
        })();
        self.native_refusal_original_v1().park_empty_result_v1(&mut self.selected_completion, returned);
        if !matches!(self.selected_completion, Some(Ok(()))) {
            return Err(NormalRootStartupErrorV1::Service);
        }

        // Temporarily borrow the completed DATA through the selected owner;
        // the mechanical observer never recurses through startup.recheck().
        let startup = self.selected.as_ref().and_then(|selected| selected.completed())
            .ok_or(NormalRootStartupErrorV1::Service)?;
        self.service_currentness = Some(RootServiceCurrentnessV1::observe_actual_once(
            &mut self.activation, startup,
        ));
        let attempt = self.service_currentness.as_ref().ok_or(NormalRootStartupErrorV1::Service)?;
        if attempt.is_positive() {
            Ok(())
        } else {
            Err(NormalRootStartupErrorV1::Service)
        }
    }

    pub(crate) fn recheck_service(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.failure().is_some() || self.activation.process_id_v1() != std::process::id()
            || !matches!(self.selected_completion, Some(Ok(())))
            || !self.service_currentness.as_ref().is_some_and(|attempt| attempt.is_positive())
        {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        self.prepay_service_recheck_once_v1()?;
        self.observe_service_currentness_prepaid_v1(startup)
    }

    // Only healthy recheck reaches this after its new one-row traffic debit.
    // Independently owed posts use a separately prearmed native owner instead.
    fn observe_service_currentness_prepaid_v1(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        if self.activation.process_id_v1() != std::process::id()
            || !matches!(self.selected_completion, Some(Ok(())))
            || !self.service_currentness.as_ref().is_some_and(|attempt| attempt.is_positive())
        {
            self.activation.latch_root_refusal_v1();
            return Err(NormalRootStartupErrorV1::Service);
        }
        // The adapter marker and actual native sampler dispose only after
        // complete positive settlement; no original R is replaced or reset.
        self.service_currentness = None;
        self.service_currentness = Some(RootServiceCurrentnessV1::observe_actual_once(
            &mut self.activation, startup,
        ));
        let attempt = self.service_currentness.as_ref().ok_or(NormalRootStartupErrorV1::Service)?;
        if attempt.is_positive() {
            Ok(())
        } else {
            self.activation.latch_root_refusal_v1();
            Err(NormalRootStartupErrorV1::Service)
        }
    }
}
