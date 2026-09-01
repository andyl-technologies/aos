//! Canonical material for stateful signal operators.

use super::*;

pub(super) fn stateful_material(specification: &StatefulSignalSpecification) -> String {
    match specification {
        StatefulSignalSpecification::Hysteresis {
            initial,
            set_when,
            clear_when,
            minimum_residence_nanos,
        } => format!(
            "initial={initial};set_when={};clear_when={};minimum_residence_nanos={minimum_residence_nanos}",
            set_when.material(),
            clear_when.material()
        ),
        StatefulSignalSpecification::Debounce {
            initial,
            residence_nanos,
        } => format!(
            "initial={};residence_nanos={residence_nanos}",
            initial.material()
        ),
        StatefulSignalSpecification::Integrator {
            initial,
            cadence_nanos,
            time_unit_nanos,
            rounding,
            overflow,
        } => format!(
            "initial={};cadence_nanos={cadence_nanos};time_unit_nanos={time_unit_nanos};rounding={};overflow={}",
            initial.material(),
            rounding_name(*rounding),
            overflow_name(*overflow)
        ),
        StatefulSignalSpecification::LeakyIntegrator {
            initial,
            cadence_nanos,
            time_unit_nanos,
            decay_ratio,
            maximum_catch_up_steps,
            rounding,
            overflow,
        } => format!(
            "initial={};cadence_nanos={cadence_nanos};time_unit_nanos={time_unit_nanos};decay_ratio={}/{};maximum_catch_up_steps={maximum_catch_up_steps};rounding={};overflow={}",
            initial.material(),
            decay_ratio.numerator(),
            decay_ratio.denominator(),
            rounding_name(*rounding),
            overflow_name(*overflow)
        ),
        StatefulSignalSpecification::FiniteStateMachine {
            states,
            initial,
            transitions,
            unmatched_event,
        } => format!(
            "states={};initial={};transitions={};unmatched_event={}",
            id_list_material(states),
            initial.as_str(),
            transitions
                .iter()
                .map(transition_material)
                .collect::<Vec<_>>()
                .join(","),
            unmatched_event.as_str()
        ),
        StatefulSignalSpecification::MarkovChain {
            states,
            initial,
            opportunity,
            probability_rows,
        } => format!(
            "states={};initial={};opportunity={};probability_rows={}",
            id_list_material(states),
            initial.as_str(),
            opportunity.as_str(),
            probability_rows
                .iter()
                .map(|row| row.iter().map(u32::to_string).collect::<Vec<_>>().join("/"))
                .collect::<Vec<_>>()
                .join(",")
        ),
        StatefulSignalSpecification::BurstProcess {
            initial_bad,
            good_to_bad_millionths,
            bad_to_good_millionths,
            opportunity,
        } => format!(
            "initial_bad={initial_bad};good_to_bad_millionths={good_to_bad_millionths};bad_to_good_millionths={bad_to_good_millionths};opportunity={}",
            opportunity.as_str()
        ),
        StatefulSignalSpecification::Counter {
            initial,
            maximum,
            overflow,
            reset_event,
        } => format!(
            "initial={initial};maximum={maximum};overflow={};reset_event={}",
            overflow_name(*overflow),
            optional_id_material(reset_event)
        ),
        StatefulSignalSpecification::QueueModel {
            capacity,
            discipline,
            overflow,
        } => format!(
            "capacity={capacity};discipline={};overflow={}",
            discipline.as_str(),
            overflow.as_str()
        ),
    }
}
