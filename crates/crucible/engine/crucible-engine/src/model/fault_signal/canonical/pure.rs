//! Canonical material for pure signal operators.

use super::*;

pub(super) fn pure_material(
    specification: &PureSignalSpecification,
) -> impl std::fmt::Display + '_ {
    display(move |formatter| match specification {
        PureSignalSpecification::Simple { operator, overflow } => write!(
            formatter,
            "operator={};overflow={}",
            operator_name(*operator),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::RatioArithmetic {
            operator,
            ratio,
            rounding,
            overflow,
        } => write!(
            formatter,
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
        } => write!(
            formatter,
            "minimum={};maximum={};overflow={}",
            value_material(minimum),
            value_material(maximum),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::LookupStep {
            points,
            before,
            after,
        } => write!(
            formatter,
            "points={};before={};after={}",
            value_pair_list_material(points),
            boundary_material(before),
            boundary_material(after)
        ),
        PureSignalSpecification::PiecewiseLinear {
            points,
            rounding,
            overflow,
        } => write!(
            formatter,
            "points={};rounding={};overflow={}",
            value_pair_list_material(points),
            rounding_name(*rounding),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::EnumMap { entries } => write!(
            formatter,
            "entries={}",
            joined(
                entries
                    .iter()
                    .map(|(variant, value)| display(move |formatter| write!(
                        formatter,
                        "{}=>{}",
                        variant.as_str(),
                        value_material(value)
                    ))),
                ","
            )
        ),
        PureSignalSpecification::UnitConvert {
            from_unit,
            to_unit,
            ratio,
            offset,
            rounding,
            overflow,
        } => write!(
            formatter,
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
        } => write!(
            formatter,
            "delay={delay};retained_samples={retained_samples}"
        ),
        PureSignalSpecification::SampleHold {
            cadence,
            epoch,
            retained_samples,
        } => {
            write!(
                formatter,
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
        } => write!(
            formatter,
            "operator={};window={window};sampling_cadence={sampling_cadence};retained_samples={retained_samples};rounding={};overflow={}",
            operator_name(*operator),
            rounding_name(*rounding),
            overflow_name(*overflow)
        ),
        PureSignalSpecification::Distance { metric, rounding } => write!(
            formatter,
            "metric={};rounding={}",
            metric.as_str(),
            rounding_name(*rounding)
        ),
        PureSignalSpecification::ZoneContains { zone } => {
            write!(formatter, "zone={}", zone.as_str())
        }
        PureSignalSpecification::FieldSample => formatter.write_str(""),
        PureSignalSpecification::OrientationDelta { convention } => {
            write!(formatter, "convention={}", convention.as_str())
        }
        PureSignalSpecification::MergeEvents {
            source_sequence_limit,
        } => {
            write!(
                formatter,
                "same_coordinate_order=source_then_sequence;source_sequence_limit={source_sequence_limit}"
            )
        }
        PureSignalSpecification::GateEvents => formatter.write_str(""),
    })
}
