//! Canonical material for stateful signal operators.

use super::*;

pub(super) fn stateful_material(
    specification: &StatefulSignalSpecification,
) -> impl std::fmt::Display + '_ {
    display(move |formatter| match specification {
        StatefulSignalSpecification::Hysteresis {
            initial,
            set_when,
            clear_when,
            minimum_residence_nanos,
        } => write!(
            formatter,
            "initial={initial};set_when={};clear_when={};minimum_residence_nanos={minimum_residence_nanos}",
            value_material(set_when),
            value_material(clear_when)
        ),
        StatefulSignalSpecification::Debounce {
            initial,
            residence_nanos,
        } => write!(
            formatter,
            "initial={};residence_nanos={residence_nanos}",
            value_material(initial)
        ),
        StatefulSignalSpecification::Integrator {
            initial,
            cadence_nanos,
            time_unit_nanos,
            rounding,
            overflow,
        } => write!(
            formatter,
            "initial={};cadence_nanos={cadence_nanos};time_unit_nanos={time_unit_nanos};rounding={};overflow={}",
            value_material(initial),
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
        } => write!(
            formatter,
            "initial={};cadence_nanos={cadence_nanos};time_unit_nanos={time_unit_nanos};decay_ratio={}/{};maximum_catch_up_steps={maximum_catch_up_steps};rounding={};overflow={}",
            value_material(initial),
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
        } => write!(
            formatter,
            "states={};initial={};transitions={};unmatched_event={}",
            id_list_material(states),
            initial.as_str(),
            joined(transitions.iter().map(transition_material), ","),
            unmatched_event.as_str()
        ),
        StatefulSignalSpecification::MarkovChain {
            states,
            initial,
            opportunity,
            probability_rows,
        } => write!(
            formatter,
            "states={};initial={};opportunity={};probability_rows={}",
            id_list_material(states),
            initial.as_str(),
            opportunity.as_str(),
            joined(
                probability_rows.iter().map(|row| joined(row.iter(), "/")),
                ","
            )
        ),
        StatefulSignalSpecification::BurstProcess {
            initial_bad,
            good_to_bad_millionths,
            bad_to_good_millionths,
            opportunity,
        } => write!(
            formatter,
            "initial_bad={initial_bad};good_to_bad_millionths={good_to_bad_millionths};bad_to_good_millionths={bad_to_good_millionths};opportunity={}",
            opportunity.as_str()
        ),
        StatefulSignalSpecification::Counter {
            initial,
            maximum,
            overflow,
            reset_event,
        } => write!(
            formatter,
            "initial={initial};maximum={maximum};overflow={};reset_event={}",
            overflow_name(*overflow),
            optional_id_material(reset_event)
        ),
        StatefulSignalSpecification::QueueModel {
            capacity,
            discipline,
            overflow,
        } => write!(
            formatter,
            "capacity={capacity};discipline={};overflow={}",
            discipline.as_str(),
            overflow.as_str()
        ),
    })
}
