//! Shares one Preparation transaction and its independent cleanup decision.
//!
//! The issued Source adapter retains every reached object on the already-paid
//! operation. RESULT remains correlation DATA until actual leader death, empty
//! cgroup and the independent manager completion receipt.

use super::super::*;

pub(super) trait PreparationNativeV4 {
    type Output;
    fn begin(&mut self) -> Result<(), NetworkWorkerRuntimeError>;
    fn ready(&mut self) -> Result<(), NetworkWorkerRuntimeError>;
    fn population(&mut self) -> Result<(), NetworkWorkerRuntimeError>;
    fn custody(&mut self) -> Result<(), NetworkWorkerRuntimeError>;
    fn exchange(&mut self) -> Result<NetworkWorkerResultV1, NetworkWorkerRuntimeError>;
    fn natural_exit(&mut self) -> Result<(), NetworkWorkerRuntimeError>;
    fn cleanup(&mut self) -> Result<(), NetworkWorkerRuntimeError>;
    fn fail_stop(&mut self);
    fn output(&mut self, result: NetworkWorkerResultV1) -> Self::Output;
}

pub(super) fn execute_prepare_recipe_v4<N: PreparationNativeV4>(
    native: &mut N,
) -> Result<N::Output, NetworkWorkerRuntimeError> {
    native.begin()?;
    native.ready()?;
    native.population()?;

    // Custody precedes every dispatch frame. Failure in either branch still
    // owes the already-armed exact helper cleanup; it grants no new target.
    let custody = native.custody();
    let exchange = exchange_after_confirmed_custody(custody, || native.exchange());
    match exchange {
        Ok(result) => {
            match release_after_quiescence(native.natural_exit(), || native.output(result)) {
                Ok(output) => Ok(output),
                Err(natural_error) => match native.cleanup() {
                    Ok(()) => Err(NetworkWorkerRuntimeError::Quiescence(format!(
                        "successful worker did not terminate naturally: {natural_error}"
                    ))),
                    Err(cancellation_error) => {
                        native.fail_stop();
                        Err(NetworkWorkerRuntimeError::Quiescence(format!(
                            "successful worker remained live ({natural_error}); cancellation was not proved ({cancellation_error})"
                        )))
                    }
                },
            }
        }
        Err(error) => match native.cleanup() {
            Ok(()) => Err(error),
            Err(cancellation_error) => {
                native.fail_stop();
                Err(NetworkWorkerRuntimeError::Quiescence(format!(
                    "worker exchange failed ({error}); cancellation was not proved ({cancellation_error})"
                )))
            }
        },
    }
}
