//! Installed issue-only continuation retaining actual administrative resources.
//!
//! This branch precedes ordinary listeners, broker effects and READY. Returned
//! startup custody, then actual journals and credential descriptions, are
//! parked before later checks. Every failure terminates with those resources
//! resident; armed Drop fences unwinding before their fields are released.

use aos_sandbox::controller_service::journal::{
    production_journal_limits, validate_controller_journal,
};
use aos_sandbox::normal_root::{
    ProductionControllerNormalRootProfileV1, SourceSuccessorCredentialCustodyV2,
    SourceSuccessorCredentialErrorV2,
};

use super::*;

#[derive(Debug, thiserror::Error)]
enum IssuerAdmissionErrorV2 {
    #[error("Source successor original credential admission failed")]
    Credential(#[from] SourceSuccessorCredentialErrorV2),
    #[error("Source successor resident administrative admission failed")]
    Runtime(#[from] ControllerRuntimeError),
    #[error("Source successor genuine selected profile is unavailable")]
    Profile,
    #[error("Source successor original administrative invocation was abandoned")]
    Abandoned,
}

struct ResidentInvocationV2<'profile> {
    profile: &'profile ProductionControllerNormalRootProfileV1,
    launch_image: Option<crate::production_startup::Pid1LaunchImageV1>,
    credentials: Option<SourceSuccessorCredentialCustodyV2<'profile>>,
    journal: Option<Journal>,
    source: Option<ProtectedSourceDomainJournalOwnerV1>,
    controller: Option<ProductionController>,
    first_cause: Option<IssuerAdmissionErrorV2>,
    armed: bool,
}

impl ResidentInvocationV2<'_> {
    fn fail(&mut self, cause: IssuerAdmissionErrorV2) -> ! {
        if self.first_cause.is_none() {
            self.first_cause = Some(cause);
        }
        if let Some(credentials) = &mut self.credentials {
            credentials.end_failed();
        }
        // No ordinary Err/ExitCode or destructor release precedes termination.
        std::process::exit(1)
    }

    fn admit_controller(
        &mut self,
        configuration: &RuntimeConfiguration,
    ) -> Result<(), IssuerAdmissionErrorV2> {
        self.profile.park_source_successor_credentials_v2(&mut self.credentials)?;
        let node_id = read_node_id()?;
        let (journal, _) = Journal::open_existing_protected_at_for_uid(
            STATE_DIRECTORY,
            JOURNAL_NAME,
            production_journal_limits(),
            configuration.uid,
        ).map_err(ControllerRuntimeError::from)?;
        self.journal = Some(journal);

        let (source, _) = ProtectedSourceDomainJournalOwnerV1::open_existing_fixed_protected_for_uid(configuration.uid)
            .map_err(ControllerRuntimeError::from)?;
        self.source = Some(source);

        let journal = self.journal.as_mut().ok_or(IssuerAdmissionErrorV2::Profile)?;
        // The legacy validator can initialize an empty journal. Issue mode
        // rejects that case before invoking it; it cannot manufacture genesis.
        if journal.all_records().next().is_none() {
            return Err(IssuerAdmissionErrorV2::Profile);
        }
        validate_controller_journal(journal, node_id).map_err(ControllerRuntimeError::from)?;
        validate_process_controller_hold_credentials_v1(None)
            .map_err(|_| ControllerRuntimeError::InvalidControllerHoldCredential)?;
        let scope = ControllerRequestScopeV1::new(ObjectDigest::from_bytes(REQUEST_SCOPE))
            .map_err(ControllerRuntimeError::from)?;
        let limits = NodeControllerLimits::new(1024 * 1024, 65_536, 1)
            .map_err(ControllerRuntimeError::from)?;
        let sessions = Arc::new(Mutex::new(ControllerBrokerSessions::default()));
        self.credentials.as_mut()
            .ok_or(IssuerAdmissionErrorV2::Profile)?
            .recheck()?;
        self.profile.recheck().map_err(ControllerRuntimeError::NormalRootProfile)?;

        // Both slots were checked before taking either handle. From this point
        // to storing NodeController there are only infallible moves; no owner
        // is reconstructed and the ordinary constructor is not called.
        if self.journal.is_none() || self.source.is_none() {
            return Err(IssuerAdmissionErrorV2::Profile);
        }
        let Some(journal) = self.journal.take() else {
            return Err(IssuerAdmissionErrorV2::Profile);
        };
        let Some(source) = self.source.take() else {
            // The preceding check makes this unreachable without mutation.
            // Retain the already taken writer before reporting the refusal.
            self.journal = Some(journal);
            return Err(IssuerAdmissionErrorV2::Profile);
        };
        let executor = ProductionEffectExecutor::from_retained_source(
            sessions,
            scope,
            None,
            None,
            None,
            source,
            configuration.uid,
            NodeId::from_bytes(node_id),
            None,
        );
        self.controller = Some(NodeController::new(
            scope,
            limits,
            ProductionOperationCompilerV1::new(),
            Reconciler::new(journal, executor),
        ));
        Ok(())
    }
}

impl Drop for ResidentInvocationV2<'_> {
    fn drop(&mut self) {
        if self.armed {
            if self.first_cause.is_none() {
                self.first_cause = Some(IssuerAdmissionErrorV2::Abandoned);
            }
            if let Some(credentials) = &mut self.credentials {
                credentials.end_failed();
            }
            std::process::abort();
        }
    }
}

pub(super) fn run(
    configuration: &RuntimeConfiguration,
    startup: &mut crate::production_startup::ControllerStartupContinuationV1,
) -> Result<(), ControllerRuntimeError> {
    // Optional publisher/Nix roles are already forbidden by mode parsing and
    // the complete capture validator. No later descriptor or profile is read.
    if !startup.admit_root_once(configuration.uid, configuration.gid) {
        startup.terminate_failed();
    }
    let Some(profile) = startup.profile() else {
        // The issue-only admission never settles an absent Root profile.
        // Keep the actual parent and nested attempt resident at process death.
        std::process::exit(1);
    };
    let mut resident = ResidentInvocationV2 {
        profile,
        launch_image: startup.image_share(),
        credentials: None,
        journal: None,
        source: None,
        controller: None,
        first_cause: None,
        armed: true,
    };
    if let Err(cause) = resident.admit_controller(configuration) {
        resident.fail(cause);
    }

    let Some(controller) = resident.controller.as_mut() else {
        resident.fail(IssuerAdmissionErrorV2::Profile);
    };
    let Some(credentials) = resident.credentials.as_mut() else {
        resident.fail(IssuerAdmissionErrorV2::Profile);
    };
    match controller.issue_source_successor_v2(resident.profile, credentials) {
        Ok(_) => {}
        Err(failed) => failed.terminate_failed(),
    };
    // End the owning Result/loans before moving the resident owner. Core
    // success includes SAME-flight Finish; no Root predicate follows it.
    resident.armed = false;
    drop(resident);
    startup.complete_issue_finish();
    Ok(())
}
