//! Canonical material for pure signal operators.

use super::*;

pub(super) fn pure_material(specification: &PureSignalSpecification) -> String {
    match specification {
        PureSignalSpecification::Simple { operator, overflow } => format!(
            "operator={};overflow={}",
            operator_name(*operator),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::RatioArithmetic {
            operator,
            ratio,
            rounding,
            overflow,
        } => format!(
            "operator={};ratio={}/{};rounding={};overflow={}",
            operator_name(*operator),
            ratio.numerator(),
            ratio.denominator(),
            rounding_name(*rounding),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::Clamp {
            minimum,
            maximum,
            overflow,
        } => format!(
            "minimum={};maximum={};overflow={}",
            minimum.material(),
            maximum.material(),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::LookupStep {
            points,
            before,
            after,
        } => format!(
            "points={};before={};after={}",
            value_pair_list_material(points),
            boundary_material(before),
            boundary_material(after)
        ),
        PureSignalSpecification::PiecewiseLinear {
            points,
            rounding,
            overflow,
        } => format!(
            "points={};rounding={};overflow={}",
            value_pair_list_material(points),
            rounding_name(*rounding),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::EnumMap { entries } => format!(
            "entries={}",
            entries
                .iter()
                .map(|(variant, value)| format!("{}=>{}", variant.as_str(), value.material()))
                .collect::<Vec<_>>()
                .join(",")
        ),
        PureSignalSpecification::UnitConvert {
            from_unit,
            to_unit,
            ratio,
            offset,
            rounding,
            overflow,
        } => format!(
            "from_unit={};to_unit={};ratio={}/{};offset={}/{};rounding={};overflow={}",
            from_unit.material(),
            to_unit.material(),
            ratio.numerator(),
            ratio.denominator(),
            offset.numerator(),
            offset.denominator(),
            rounding_name(*rounding),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::Delay {
            delay,
            retained_samples,
        } => format!("delay={delay};retained_samples={retained_samples}"),
        PureSignalSpecification::SampleHold {
            cadence,
            epoch,
            retained_samples,
        } => {
            format!(
                "cadence={cadence};epoch={};retained_samples={retained_samples}",
                coordinate_material(epoch)
            )
        }
        PureSignalSpecification::Window {
            operator,
            window,
            sampling_cadence,
            retained_samples,
            rounding,
            overflow,
        } => format!(
            "operator={};window={window};sampling_cadence={sampling_cadence};retained_samples={retained_samples};rounding={};overflow={}",
            operator_name(*operator),
            rounding_name(*rounding),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::Distance { metric, rounding } => format!(
            "metric={};rounding={}",
            metric.as_str(),
            rounding_name(*rounding)
        ),
        PureSignalSpecification::ZoneContains { zone } => {
            format!("zone={}", zone.as_str())
        }
        PureSignalSpecification::FieldSample => String::new(),
        PureSignalSpecification::OrientationDelta { convention } => {
            format!("convention={}", convention.as_str())
        }
        PureSignalSpecification::MergeEvents {
            source_sequence_limit,
        } => {
            format!(
                "same_coordinate_order=source_then_sequence;source_sequence_limit={source_sequence_limit}"
            )
        }
        PureSignalSpecification::GateEvents => String::new(),
    }
}
