//! Canonical material for signal source specifications.

use super::*;

pub(super) fn source_material(specification: &SignalSourceSpecification) -> String {
    match specification {
        SignalSourceSpecification::Step { points, before } => format!(
            "points={};before={}",
            point_list_material(points),
            boundary_material(before)
        ),
        SignalSourceSpecification::Pulse {
            start,
            duration,
            inactive,
            active,
        } => format!(
            "start={};duration={duration};inactive={};active={}",
            coordinate_material(start),
            inactive.material(),
            active.material()
        ),
        SignalSourceSpecification::PeriodicPulse {
            epoch,
            period,
            width,
            phase,
            inactive,
            active,
        } => format!(
            "epoch={};period={period};width={width};phase={phase};inactive={};active={}",
            coordinate_material(epoch),
            inactive.material(),
            active.material()
        ),
        SignalSourceSpecification::Ramp {
            start,
            end,
            start_value,
            end_value,
            rounding,
        } => format!(
            "start={};end={};start_value={};end_value={};rounding={}",
            coordinate_material(start),
            coordinate_material(end),
            start_value.material(),
            end_value.material(),
            rounding_name(*rounding)
        ),
        SignalSourceSpecification::Triangle {
            epoch,
            period,
            phase,
            minimum,
            maximum,
            rounding,
        }
        | SignalSourceSpecification::Sawtooth {
            epoch,
            period,
            phase,
            minimum,
            maximum,
            rounding,
        } => format!(
            "epoch={};period={period};phase={phase};minimum={};maximum={};rounding={}",
            coordinate_material(epoch),
            minimum.material(),
            maximum.material(),
            rounding_name(*rounding)
        ),
        SignalSourceSpecification::EventSequence { events } => {
            format!("events={}", point_list_material(events))
        }
        SignalSourceSpecification::Trace {
            artifact,
            raw_provenance,
            channel,
            quality_channel,
            quality_accept,
            interpolation,
            before,
            after,
            missing,
            time_mapping,
        } => format!(
            "artifact={};raw_provenance={};channel={};quality_channel={};quality_accept={};interpolation={};before={};after={};missing={};time_mapping={}",
            artifact.to_hex(),
            raw_provenance.to_hex(),
            channel.as_str(),
            optional_id_material(quality_channel),
            optional_i64_material(*quality_accept),
            interpolation_name(*interpolation),
            boundary_material(before),
            boundary_material(after),
            missing_name(*missing),
            time_mapping_material(time_mapping)
        ),
        SignalSourceSpecification::Telemetry {
            adapter,
            target,
            field,
            boundary_delay,
        } => format!(
            "adapter={};target={};field={};boundary_delay={boundary_delay}",
            adapter.as_str(),
            target.as_str(),
            field.as_str()
        ),
        SignalSourceSpecification::PointSet {
            artifact,
            coordinate_frame,
            interpolation,
            outside,
        } => format!(
            "artifact={};coordinate_frame={};interpolation={};outside={}",
            artifact.to_hex(),
            coordinate_frame.as_str(),
            interpolation_name(*interpolation),
            boundary_material(outside)
        ),
        SignalSourceSpecification::RegularGrid {
            artifact,
            coordinate_frame,
            origin_mm,
            cell_size_mm,
            dimensions,
            interpolation,
            outside,
        } => format!(
            "artifact={};coordinate_frame={};origin_mm={};cell_size_mm={};dimensions={};interpolation={};outside={}",
            artifact.to_hex(),
            coordinate_frame.as_str(),
            i64_array_material(origin_mm),
            u64_array_material(cell_size_mm),
            u32_array_material(dimensions),
            interpolation_name(*interpolation),
            boundary_material(outside)
        ),
        SignalSourceSpecification::TiledGrid {
            manifest,
            coordinate_frame,
            tile_size_mm,
            interpolation,
            outside,
        } => format!(
            "manifest={};coordinate_frame={};tile_size_mm={};interpolation={};outside={}",
            manifest.to_hex(),
            coordinate_frame.as_str(),
            u64_array_material(tile_size_mm),
            interpolation_name(*interpolation),
            boundary_material(outside)
        ),
        SignalSourceSpecification::ZoneMap {
            artifact,
            coordinate_frame,
            boundary,
            overlap,
        } => format!(
            "artifact={};coordinate_frame={};boundary={};overlap={}",
            artifact.to_hex(),
            coordinate_frame.as_str(),
            boundary.as_str(),
            overlap.as_str()
        ),
        SignalSourceSpecification::PathProfile {
            artifact,
            path,
            interpolation,
            before,
            after,
        } => format!(
            "artifact={};path={};interpolation={};before={};after={}",
            artifact.to_hex(),
            path.as_str(),
            interpolation_name(*interpolation),
            boundary_material(before),
            boundary_material(after)
        ),
        SignalSourceSpecification::SeededField {
            field_seed_domain,
            coordinate_frame,
            quantization_mm,
            correlation_mm,
            distribution,
            distribution_parameters,
        } => format!(
            "field_seed_domain={};coordinate_frame={};quantization_mm={};correlation_mm={};distribution={};distribution_parameters={}",
            field_seed_domain.as_str(),
            coordinate_frame.as_str(),
            u64_array_material(quantization_mm),
            u64_array_material(correlation_mm),
            distribution.as_str(),
            i64_slice_material(distribution_parameters)
        ),
        SignalSourceSpecification::TransmitterField {
            transmitter,
            coordinate_frame,
            position_signal,
            orientation_signal,
            model,
            lookup,
            environment_signals,
        } => format!(
            "transmitter={};coordinate_frame={};position_signal={};orientation_signal={};model={};lookup={};environment_signals={}",
            transmitter.as_str(),
            coordinate_frame.as_str(),
            position_signal.as_str(),
            optional_id_material(orientation_signal),
            model.as_str(),
            lookup.to_hex(),
            id_list_material(environment_signals)
        ),
        SignalSourceSpecification::Bernoulli {
            probability_millionths,
            key_domain,
            opportunity_filter,
        } => format!(
            "probability_millionths={probability_millionths};key_domain={};opportunity_filter={}",
            key_domain_name(*key_domain),
            optional_id_material(opportunity_filter)
        ),
        SignalSourceSpecification::UniformInteger {
            minimum,
            maximum,
            key_domain,
            opportunity_filter,
        } => format!(
            "minimum={minimum};maximum={maximum};key_domain={};opportunity_filter={}",
            key_domain_name(*key_domain),
            optional_id_material(opportunity_filter)
        ),
        SignalSourceSpecification::ExponentialWait {
            rate,
            sampler_version,
            sampler_table,
            key_domain,
            maximum_nanos,
        } => format!(
            "rate={}/{};sampler_version={sampler_version};sampler_table={};key_domain={};maximum_nanos={}",
            rate.numerator(),
            rate.denominator(),
            sampler_table.to_hex(),
            key_domain_name(*key_domain),
            optional_u64_material(*maximum_nanos)
        ),
        SignalSourceSpecification::WeibullWait {
            shape,
            scale_nanos,
            sampler_version,
            sampler_table,
            key_domain,
            maximum_nanos,
        } => format!(
            "shape={}/{};scale_nanos={scale_nanos};sampler_version={sampler_version};sampler_table={};key_domain={};maximum_nanos={}",
            shape.numerator(),
            shape.denominator(),
            sampler_table.to_hex(),
            key_domain_name(*key_domain),
            optional_u64_material(*maximum_nanos)
        ),
    }
}
