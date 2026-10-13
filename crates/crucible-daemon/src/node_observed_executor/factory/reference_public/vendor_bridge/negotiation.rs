//! Retains ordinary reference negotiation beneath the original native queue slot.
//!
//! This holder is allocated before Child. It remains inside the same queue entry
//! as the native guard, including after an uncertain Hello, rejected controller
//! construction, or attachment refusal. Its contents are private operational
//! originals; they must never be published as qualification evidence.

use std::time::Duration;

use crucible::node_adapters::cnp::CnpLaunchGuard;
use crucible_node_provider::{
    ProviderError,
    client::{
        ClientCustody, ClientSession, OriginalHelloJournal, ReferenceController,
        ReferenceControllerPreparationFailure,
    },
    handshake::Handshake,
    reference_service::{ReferenceProfile, ReferenceServiceBootstrap},
};

pub(in crate::node_observed_executor::factory::reference_public) struct OriginalReferenceNegotiation
{
    pub(super) hello: OriginalHelloJournal,
    pub(super) birth_currency: super::currency::OriginalBirthCurrency,
    pub(super) upload: super::launch_upload::OriginalLaunchUpload,
    pub(super) handshake: Option<Handshake>,
    pub(super) session: Option<ClientSession>,
    journal: Option<ClientCustody>,
    controller: Option<ReferenceController>,
    failed_controller: Option<Box<ReferenceControllerPreparationFailure>>,
    controller_attempted: bool,
}

impl OriginalReferenceNegotiation {
    /// Reserves the original data holders before any Child or Hello effect.
    pub(super) fn new(
        hello: OriginalHelloJournal,
        handshake: Handshake,
        journal: ClientCustody,
        upload: super::launch_upload::OriginalLaunchUpload,
        birth_currency: super::currency::OriginalBirthCurrency,
    ) -> Self {
        Self {
            hello,
            upload,
            birth_currency,
            handshake: Some(handshake),
            session: None,
            journal: Some(journal),
            controller: None,
            failed_controller: None,
            controller_attempted: false,
        }
    }

    /// Reports unused data storage without authenticating a peer or source.
    pub(in crate::node_observed_executor::factory::reference_public) fn is_unstarted(
        &self,
    ) -> bool {
        self.upload.is_unstarted()
            && !self.hello.attempted()
            && self.handshake.is_some()
            && self.session.is_none()
            && self.journal.is_some()
            && self.controller.is_none()
            && self.failed_controller.is_none()
            && !self.controller_attempted
    }

    pub(in crate::node_observed_executor::factory::reference_public) fn write_attached_originals(
        &self,
        output: &mut impl std::io::Write,
    ) -> Result<(), ProviderError> {
        if !self.controller_attempted
            || self.handshake.is_some()
            || self.session.is_some()
            || self.journal.is_some()
            || self.controller.is_some()
            || self.failed_controller.is_some()
            || !self.hello.attempted()
        {
            return Err(ProviderError::Correlation(
                "original negotiation was not completely attached",
            ));
        }
        let hello = self
            .hello
            .response()
            .ok_or(ProviderError::Correlation("original Hello unresolved"))?;
        let launch = self.upload.completed_original()?;
        serde_json::to_writer(
            output,
            &(
                self.hello.request(),
                hello,
                launch,
                self.birth_currency.scope(),
            ),
        )
        .map_err(crucible_node_contract::ContractError::from)?;
        Ok(())
    }

    /// Transfers the negotiated session only through the retaining constructor.
    ///
    /// The fixed source caller bounds and validates profile/bootstrap originals
    /// before Child. This constructor performs no transport or installed callback.
    /// Every returned failure is installed in this queue-owned holder before the
    /// caller can inspect it; there is no re-encoded request or replacement peer.
    ///
    /// # Errors
    /// Refuses an absent session/journal, another constructor attempt or invalid
    /// controller preparation. The original returned failure remains retained.
    pub(super) fn prepare_controller(
        &mut self,
        profile: ReferenceProfile,
        bootstrap: ReferenceServiceBootstrap,
        qualifications: Vec<crucible_node_contract::ContentRef>,
        budget: Duration,
    ) -> Result<(), ProviderError> {
        if self.controller_attempted
            || self.session.is_none()
            || self.journal.is_none()
            || self.controller.is_some()
            || self.failed_controller.is_some()
        {
            return Err(ProviderError::Correlation(
                "ordinary reference controller original is unavailable or used",
            ));
        }
        self.controller_attempted = true;

        let Some(session) = self.session.take() else {
            return Err(ProviderError::Correlation(
                "ordinary reference session original absent",
            ));
        };
        let Some(journal) = self.journal.take() else {
            // Exclusive access and the precondition make this unreachable. Keep
            // the taken session nevertheless; refusal cannot discard its owner.
            self.session = Some(session);
            return Err(ProviderError::Correlation(
                "ordinary reference journal original absent",
            ));
        };

        match ReferenceController::new_qualified_owned(
            profile,
            bootstrap,
            session,
            journal,
            budget,
            qualifications,
        ) {
            Ok(controller) => {
                self.controller = Some(controller);
                Ok(())
            }
            Err(original) => {
                self.failed_controller = Some(original);
                Err(ProviderError::Correlation(
                    "ordinary reference controller preparation refused",
                ))
            }
        }
    }

    /// Moves both validated originals directly into their existing Child capsule.
    ///
    /// # Errors
    /// Leaves both originals here on missing/foreign/occupied native attachment.
    pub(super) fn attach_original(
        &mut self,
        guard: &mut CnpLaunchGuard,
    ) -> Result<(), ProviderError> {
        guard.attach_original(&mut self.controller, &mut self.handshake)
    }
}
