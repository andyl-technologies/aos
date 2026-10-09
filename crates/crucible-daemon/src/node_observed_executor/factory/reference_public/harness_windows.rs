//! Executes the fixed original native-window schedule beneath borrowed actor custody.
//!
//! The owning actor retains every runtime, process, observer and pending result.
//! This child selects no backend and mints no admission; it consumes only the
//! original common-runtime grants and exact predeclared success or loss fixture.

use std::task::{Context, Waker};
#[cfg(test)]
use std::{cell::RefCell, rc::Rc};

use crucible::node_admission::AdmittedGraph;
use crucible::node_contract::{NodeRuntime, WorldActivation};
use crucible_node_provider::ProviderError;

use super::failure;
use crate::node_qualification::{
    ReferenceWindowCase, ReferenceWindowObservation, collect_reference_window,
};

pub(super) struct OriginalWindowExecution<'a> {
    pub(super) runtime: &'a mut NodeRuntime,
    pub(super) graph: &'a AdmittedGraph,
    pub(super) activation: &'a WorldActivation,
    pub(super) planned: &'a [Vec<ReferenceWindowCase>],
    pub(super) windows: &'a mut [Vec<ReferenceWindowObservation>],
    pub(super) runtime_retries:
        &'a mut [Vec<super::super::runtime_retries::RuntimeCachedRecovery>],
    pub(super) phase: &'a mut &'static str,
    #[cfg(test)]
    pub(super) window_loss:
        Option<&'a Rc<super::super::source_window_provider_loss::SourceWindowProviderLoss>>,
    #[cfg(test)]
    pub(super) original_loss:
        Option<&'a Rc<super::super::source_original_response_loss::SourceOriginalResponseLoss>>,
    #[cfg(test)]
    pub(super) transmission_observers:
        &'a [Rc<RefCell<Option<crucible_node_provider::client::TransmissionObservationHandle>>>],
}

/// Executes only the authored original schedule and retains failures in the caller.
///
/// # Errors
/// Refuses unresolved native results, changed original input/grant or any
/// failure to retain the source-declared uncertain original and cached denial.
pub(super) fn collect_original_windows(
    state: OriginalWindowExecution<'_>,
) -> Result<(), ProviderError> {
    let OriginalWindowExecution {
        runtime,
        graph,
        activation,
        planned,
        windows,
        runtime_retries,
        phase,
        #[cfg(test)]
        window_loss,
        #[cfg(test)]
        original_loss,
        #[cfg(test)]
        transmission_observers,
    } = state;
    if planned.len() != 2
        || planned.iter().any(|cases| cases.len() != 3)
        || windows.len() != 2
        || runtime_retries.len() != 2
    {
        return Err(ProviderError::Correlation(
            "original window execution population differs",
        ));
    }
    #[cfg(test)]
    if transmission_observers.len() != 2 {
        return Err(ProviderError::Correlation(
            "original window observer roster differs",
        ));
    }

    let mut context = Context::from_waker(Waker::noop());
    for (index, quantum) in [(1usize, 0usize), (0, 0), (0, 1), (1, 1), (0, 2), (1, 2)] {
        // The single connection credit remains in original custody until
        // consumer input ACK. Consume the pending prefix before granting
        // another producer window; no horizon or capacity is widened.
        let case = &planned[index][quantum];
        #[cfg(test)]
        if index == 0
            && quantum == 1
            && let Some(loss) = window_loss
        {
            *phase = "known-window-duplicate-provider-loss";
            loss.record_predecessor(windows[0].last().ok_or(ProviderError::Correlation(
                "loss original predecessor window absent",
            ))?)?;
            super::super::source_window_provider_loss::collect_original_uncertain_window(
                runtime,
                graph,
                activation,
                case,
                &mut context,
                loss,
                &transmission_observers[0],
            )?;
            return Err(ProviderError::Correlation(
                "source-declared provider loss retains original nonpassing attempt",
            ));
        }
        #[cfg(test)]
        if index == 0
            && quantum == 1
            && let Some(loss) = original_loss
        {
            *phase = "original-sent-begin-response-loss";
            loss.record_predecessor(windows[0].last().ok_or(ProviderError::Correlation(
                "original-loss predecessor absent",
            ))?)?;
            super::super::source_original_response_loss::collect_original_response_loss(
                runtime,
                graph,
                activation,
                case,
                &mut context,
                loss,
            )?;
            return Err(ProviderError::Correlation(
                "source-declared original response loss retains nonpassing attempt",
            ));
        }
        windows[index].push(
            collect_reference_window(runtime, graph, activation, case, &mut context)
                .map_err(failure)?,
        );
        *phase = "original-runtime-cached-recovery";
        let window = windows[index].last().ok_or(ProviderError::Frame(
            "original window unavailable for recovery",
        ))?;
        runtime_retries[index].push(super::super::runtime_retries::collect(
            runtime,
            graph,
            activation,
            case,
            window,
            &mut context,
        )?);
        *phase = "original-native-windows";
    }
    Ok(())
}
