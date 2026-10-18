//! Validated dispatch through the selected backend route.

use super::*;

pub(in super::super) fn execute_backend_routed_command(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: Option<&RunInvocationPlan>,
    verify_plan: Option<&VerifyInvocationPlan>,
    save_plan: Option<&SaveInvocationPlan>,
    runner: &mut impl BackendCommandRunner,
) -> Result<BackendCommandOutcome, CliError> {
    if !thin_plan.proves_t_cli_2() || !backend_plan.has_consistent_route() {
        return Err(CliError::Backend(
            "CLI command route violates the RFC-0010 backend split".to_string(),
        ));
    }
    if thin_plan.subcommand != backend_plan.subcommand {
        return Err(CliError::Backend(
            "CLI backend route does not match the command dispatch plan".to_string(),
        ));
    }

    let execution = match (
        &backend_plan.target,
        &backend_plan.resolved_backend,
        &backend_plan.daemon,
    ) {
        (BackendExecutionTarget::Local, Some(backend), None) => runner.run_local(
            backend,
            thin_plan,
            backend_plan,
            ergonomics_plan,
            run_plan,
            verify_plan,
            save_plan,
        ),
        (BackendExecutionTarget::RemoteDaemon, None, Some(daemon)) => runner.run_remote(
            daemon,
            thin_plan,
            backend_plan,
            ergonomics_plan,
            run_plan,
            verify_plan,
            save_plan,
        ),
        _ => Err(CliError::Backend(
            "CLI backend route is internally inconsistent".to_string(),
        )),
    }?;
    validate_backend_execution_evidence(backend_plan, &execution.evidence)?;
    Ok(execution.outcome)
}
