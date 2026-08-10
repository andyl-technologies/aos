//! No-op CLI decomposition recorder used by normal dispatch.

use super::*;

#[derive(Default)]
pub(super) struct NullOperationRecorder;

pub(super) fn execute_cli_dispatch_plan(
    plan: &CliThinWrapperPlan,
    recorder: &mut impl CliOperationRecorder,
) -> Result<(), CliError> {
    if !plan.proves_t_cli_2() {
        return Err(CliError::Backend(
            "CLI invocation violates the RFC-0010 thin-wrapper contract".to_string(),
        ));
    }

    for command in &plan.session_commands {
        recorder.record_session_command(*command);
    }
    for call in &plan.api_calls {
        recorder.record_api_call(*call);
    }
    for driver in &plan.delegated_drivers {
        recorder.record_driver(*driver);
    }
    for reference in &plan.state_references {
        recorder.record_state_reference(*reference);
    }

    Ok(())
}

impl CliOperationRecorder for NullOperationRecorder {
    fn record_session_command(&mut self, _command: SessionCommandKind) {}

    fn record_api_call(&mut self, _call: CliApiCall) {}

    fn record_driver(&mut self, _driver: CliDelegatedDriver) {}

    fn record_state_reference(&mut self, _reference: CliStateReferenceKind) {}
}
