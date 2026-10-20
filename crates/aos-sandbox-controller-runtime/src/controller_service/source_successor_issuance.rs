//! Installed issue-only continuation retaining actual administrative resources.
//!
//! This branch precedes ordinary listeners, broker effects and READY. Returned
//! startup custody, then actual journals and credential descriptions, are
//! parked before later checks. Every failure terminates with those resources
//! resident; armed Drop fences unwinding before their fields are released.

use aos_sandbox::normal_root::{
    ProductionControllerNormalRootProfileV1, SourceSuccessorCredentialCustodyV2,
    SourceSuccessorCredentialErrorV2,
};

use super::activation::configuration::RuntimeConfiguration;
use super::activation::read_node_id;
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
    launch_image: Option<aos_sandbox_broker_session_security::controller_composition::Pid1LaunchImageV1>,
    credentials: Option<SourceSuccessorCredentialCustodyV2<'profile>>,
    resource_opening: aos_sandbox::ControllerResourceBankOpeningV1,
    controller_construction: aos_sandbox::journal::controller::ControllerJournalConstructionV1,
    source_construction: aos_sandbox::source_domain::ControllerSourceJournalConstructionV1,
    construction_result: Option<Result<(), ()>>,
    journal: Option<Journal>,
    source: Option<ProtectedSourceDomainJournalOwnerV1>,
    controller: Option<ProductionController>,
    first_cause: Option<IssuerAdmissionErrorV2>,
    armed: bool,
    configured_capture: aos_sandbox::hierarchy::controller_genesis_input::ControllerSourceGenesisInputStartupV1,
    configured: Option<Result<Option<ProvisionedControllerSourceGenesisInputV1>, ControllerSourceGenesisInputErrorV1>>,
}

impl ResidentInvocationV2<'_> {
    fn open_existing_writers(
        &mut self,
        configuration: &RuntimeConfiguration,
        node: [u8; 16],
    ) -> Result<(), IssuerAdmissionErrorV2> {
        if self.resource_opening.admit_preopen_once(self.profile).is_err() {
            return Err(IssuerAdmissionErrorV2::Profile);
        }
        let loan = match self.resource_opening.borrow_preopen(self.profile) {
            Ok(loan) => loan,
            Err(_) => return Err(IssuerAdmissionErrorV2::Profile),
        };
        let mut source_loan = match loan.arm_source_construction_once_v1() {
            Ok(loan) => loan,
            Err(_) => return Err(IssuerAdmissionErrorV2::Profile),
        };
        self.construction_result = Some((|| {
            self.controller_construction.open_existing_once(
                &loan, std::path::Path::new(STATE_DIRECTORY), configuration.uid, node,
            )?;
            self.source_construction.open_existing_once(&mut source_loan)?;
            self.controller_construction.validate_existing_after_source_once()?;
            Ok(())
        })());
        // Both independent observations stay owed on every entered outcome,
        // including Controller refusal before the Source body can begin.
        let source_post = self.source_construction.finish_posts(&mut source_loan);
        let controller_post = self.controller_construction.finish_posts(&loan);
        if !matches!(self.construction_result, Some(Ok(())))
            || source_post.is_err() || controller_post.is_err()
        {
            let _first_cause = self.controller_construction.primary_failure()
                .or_else(|| self.source_construction.primary_failure_with_loan(&source_loan))
                .or_else(|| self.source_construction.postcheck_debt_with_loan(&source_loan))
                .or_else(|| self.controller_construction.postcheck_debt());
            // The loan and every partial original remain in place until death.
            // Returning would drop an unsettled native/profile obligation.
            std::process::exit(1);
        }
        self.journal = self.controller_construction.take_journal();
        self.source = self.source_construction.take_source();
        if self.journal.is_none() || self.source.is_none() {
            std::process::exit(1);
        }
        Ok(())
    }

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
        // Configured discovery owns the returned writers before histories and
        // its selected genesis flight; administrative park stays after them.
        let has_configured = matches!(self.configured, Some(Ok(Some(_))));
        if !has_configured {
            self.profile.park_source_successor_credentials_v2(&mut self.credentials)?;
        }
        let node_id = read_node_id()?;
        self.open_existing_writers(configuration, node_id)?;

        validate_process_controller_hold_credentials_v1(None)
            .map_err(|_| ControllerRuntimeError::InvalidControllerHoldCredential)?;
        let scope = ControllerRequestScopeV1::new(ObjectDigest::from_bytes(REQUEST_SCOPE))
            .map_err(ControllerRuntimeError::from)?;
        let limits = NodeControllerLimits::new(1024 * 1024, 65_536, 1)
            .map_err(ControllerRuntimeError::from)?;
        let sessions = Arc::new(Mutex::new(ControllerBrokerSessions::default()));
        if !has_configured {
            self.credentials.as_mut()
                .ok_or(IssuerAdmissionErrorV2::Profile)?
                .recheck()?;
        }
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
    startup: &mut super::startup::ControllerRuntimeStartupV1,
) -> Result<(), ControllerRuntimeError> {
    // Optional publisher/Nix roles are already forbidden by mode parsing and
    // the complete capture validator. No later descriptor or profile is read.
    if !startup.admit_root_once(configuration.uid, configuration.gid) {
        startup.terminate_failed();
    }
    let Some(profile) = startup.profile_share() else {
        // The issue-only admission never settles an absent Root profile.
        // Keep the actual parent and nested attempt resident at process death.
        std::process::exit(1);
    };
    let Some(mut resource_opening) = startup.take_resource_opening() else {
        startup.terminate_failed();
    };
    // The actual retained parent and separately allocated sessions body/control
    // are representation DATA; neither type supplies a payer or continuation.
    type IssueCarriers<'profile> = (ResidentInvocationV2<'profile>, ControllerBrokerSessions, [usize; 4]);
    if resource_opening.prepare_source_successor_issue_once::<IssueCarriers<'_>>(
        &profile, ProductionEffectExecutor::inactive_receiving_bytes_v1(),
    ).is_err() {
        std::process::exit(1);
    }
    let mut resident = ResidentInvocationV2 {
        profile: &profile,
        launch_image: startup.image_share(),
        credentials: None,
        resource_opening,
        controller_construction: aos_sandbox::journal::controller::ControllerJournalConstructionV1::new(),
        source_construction: aos_sandbox::source_domain::ControllerSourceJournalConstructionV1::new(),
        construction_result: None,
        journal: None,
        source: None,
        controller: None,
        first_cause: None,
        armed: true,
        configured_capture: aos_sandbox::hierarchy::controller_genesis_input::ControllerSourceGenesisInputStartupV1::new(),
        configured: None,
    };
    // A returned pair and its failure are parked before history discovery or
    // credential admission. None keeps the old credential-before-writers path;
    // a configured pair intentionally adds discovery before administrative park.
    if resident.configured_capture.capture_once().is_err() {
        std::process::exit(1);
    }
    let Some(configured) = resident.configured_capture.take_success() else {
        std::process::exit(1);
    };
    resident.configured = Some(Ok(configured));
    let has_configured = matches!(resident.configured, Some(Ok(Some(_))));
    let admitted = resident.admit_controller(configuration);
    if let Err(cause) = admitted { resident.fail(cause); }

    if has_configured {
        let Some(Ok(Some(input))) = &resident.configured else { std::process::exit(1); };
        let Some(controller) = resident.controller.as_mut() else { std::process::exit(1); };
        let selection_result = controller.configured_project_startup_selection_v3(input);
        let selection = match &selection_result {
            Ok(selection) => *selection,
            Err(_) => std::process::exit(1),
        };
        if selection == aos_sandbox::controller::ConfiguredProjectStartupSelectionV3::MixedProject {
            {
                let returned = controller.coordinate_predecessor_successor_v3(input, resident.profile);
                if let Err(failed) = &returned { let _first_cause = failed.first_cause(); std::process::exit(1); }
            }
            {
                let returned = controller.coordinate_configured_project_genesis_v3(input, resident.profile);
                if let Err(failed) = &returned { let _first_cause = failed.first_cause(); std::process::exit(1); }
            }
            // The B genesis Result/loan has ended. Only now does genuine NEW
            // administrative custody park, followed by the NEW issuer Root-last.
            let parked = resident.profile.park_source_successor_credentials_v2(&mut resident.credentials);
            if parked.is_err() { std::process::exit(1); }
            let Some(credentials) = resident.credentials.as_mut() else { std::process::exit(1); };
            let project_result = credentials.source_successor_project_data_v3();
            let credential_post = credentials.recheck();
            let input_post = input.recheck();
            let profile_post = resident.profile.recheck();
            if project_result.as_ref().ok() != Some(&input.project())
                || credential_post.is_err() || input_post.is_err() || profile_post.is_err()
            { std::process::exit(1); }
            let returned = controller.issue_project_source_successor_v3(resident.profile, credentials);
            if let Err(failed) = &returned { let _first_cause = failed.first_cause(); std::process::exit(1); }
            drop(returned);
            resident.armed = false;
            drop(resident);
            startup.complete_issue_finish();
            return Ok(());
        }
        // Same-global discovery reuses the already-held writers. It never
        // reopens them or claims the configured branch had the old syscall order.
        let parked = resident.profile.park_source_successor_credentials_v2(&mut resident.credentials);
        if parked.is_err() { std::process::exit(1); }
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
