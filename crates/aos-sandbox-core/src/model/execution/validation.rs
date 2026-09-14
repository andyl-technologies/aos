//! Checked cross-field invariants and allocation preflights for execution v1.

use sha2::{Digest as _, Sha256};

use crate::model::spec::{LimitDimension, LimitValue, ResourceProfile};
use crate::model::view::Environment;
use crate::{FeatureRef, GrantId, ObjectDigest, ResourceDimension, ResourceVector};

use super::{
    ExecutionAccessRouteV1, ExecutionCapturedOutputV1, ExecutionCapturedStreamKindV1,
    ExecutionCommandV1, ExecutionEndpointCapabilityV1, ExecutionFailureReasonV1,
    ExecutionObservationPhaseV1, ExecutionOutputModeV1, ExecutionResourceAdmissionV1,
    ExecutionResourceRequestV1, ExecutionResourceRequestValueV1, ExecutionResourceSublimitV1,
    ExecutionResourceSublimitValueV1, ExecutionTargetV1, ExecutionTerminalModeV1,
    ExecutionTerminalResultV1, InvalidExecutionSpec, MAX_EXECUTION_ARGUMENT_BYTES,
    MAX_EXECUTION_ARGUMENT_STRING_BYTES, MAX_EXECUTION_ARGUMENTS,
    MAX_EXECUTION_BASE_ENVIRONMENT_BYTES, MAX_EXECUTION_BASE_ENVIRONMENT_CBOR_ITEMS,
    MAX_EXECUTION_CAPTURED_STREAMS, MAX_EXECUTION_ENVIRONMENT_BYTES,
    MAX_EXECUTION_ENVIRONMENT_ENTRIES, OUTPUT_RESERVATION_COMMITMENT_DOMAIN,
    RUNTIME_ARGUMENT_EVIDENCE_DOMAIN,
};

pub(super) fn runtime_argument_evidence_commitment(
    runtime_profile: &FeatureRef,
    runtime_profile_commitment: ObjectDigest,
    target: &ExecutionTargetV1,
    runtime_limit_bytes: u64,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(RUNTIME_ARGUMENT_EVIDENCE_DOMAIN);
    digest.update((runtime_profile.namespace().len() as u64).to_be_bytes());
    digest.update(runtime_profile.namespace().as_bytes());
    digest.update(runtime_profile.major().to_be_bytes());
    digest.update(runtime_profile.minor().to_be_bytes());
    digest.update(runtime_profile_commitment.as_bytes());
    digest.update(target.sandbox().as_bytes());
    digest.update(target.incarnation().as_bytes());
    digest.update(target.assignment_epoch().get().to_be_bytes());
    digest.update(target.assignment_digest().as_bytes());
    digest.update(target.namespace_generation().get().to_be_bytes());
    digest.update(target.payload_boot_id().as_bytes());
    digest.update(runtime_limit_bytes.to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(super) fn output_enforcement_feature() -> Result<FeatureRef, InvalidExecutionSpec> {
    FeatureRef::new("aos.sandbox.enforcement.broker-ledger", 1, 0)
        .map_err(|_| InvalidExecutionSpec::ResourceEnforcementMismatch)
}

pub(super) fn output_reservation_commitment(
    requested_bytes: u64,
    admitted_bytes: u64,
    parent_reservations: ResourceVector,
    assignment_digest: ObjectDigest,
    enforcement: &FeatureRef,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(OUTPUT_RESERVATION_COMMITMENT_DOMAIN);
    digest.update([ResourceDimension::OutputBytes as u8]);
    digest.update(requested_bytes.to_be_bytes());
    digest.update(admitted_bytes.to_be_bytes());
    for dimension in ResourceDimension::ALL {
        digest.update(parent_reservations.get(dimension).to_be_bytes());
    }
    digest.update(assignment_digest.as_bytes());
    digest.update((enforcement.namespace().len() as u64).to_be_bytes());
    digest.update(enforcement.namespace().as_bytes());
    digest.update(enforcement.major().to_be_bytes());
    digest.update(enforcement.minor().to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(super) fn validate_terminal_result(
    phase: ExecutionObservationPhaseV1,
    result: Option<ExecutionTerminalResultV1>,
) -> Result<(), InvalidExecutionSpec> {
    if matches!(
        result,
        Some(ExecutionTerminalResultV1::Signaled {
            signal,
            core_dumped: true,
        }) if !signal.can_dump_core()
    ) {
        return Err(InvalidExecutionSpec::InvalidTerminalResult);
    }
    let valid = matches!(
        (phase, result),
        (
            ExecutionObservationPhaseV1::Requested
                | ExecutionObservationPhaseV1::Admitted
                | ExecutionObservationPhaseV1::Starting
                | ExecutionObservationPhaseV1::Running,
            None
        ) | (
            ExecutionObservationPhaseV1::Exited,
            Some(ExecutionTerminalResultV1::Exited { .. })
                | Some(ExecutionTerminalResultV1::Signaled { .. })
        ) | (
            ExecutionObservationPhaseV1::Canceled,
            Some(ExecutionTerminalResultV1::Canceled)
        ) | (
            ExecutionObservationPhaseV1::Failed,
            Some(ExecutionTerminalResultV1::Failed { .. })
        ) | (
            ExecutionObservationPhaseV1::Lost,
            Some(ExecutionTerminalResultV1::Lost)
        )
    );
    if valid {
        Ok(())
    } else {
        Err(InvalidExecutionSpec::InvalidTerminalResult)
    }
}

pub(super) fn is_terminal_phase(phase: ExecutionObservationPhaseV1) -> bool {
    matches!(
        phase,
        ExecutionObservationPhaseV1::Exited
            | ExecutionObservationPhaseV1::Canceled
            | ExecutionObservationPhaseV1::Failed
            | ExecutionObservationPhaseV1::Lost
    )
}

pub(super) fn validate_captured_output(
    phase: ExecutionObservationPhaseV1,
    terminal_result: Option<ExecutionTerminalResultV1>,
    captured_output: Option<&ExecutionCapturedOutputV1>,
    output_mode: ExecutionOutputModeV1,
) -> Result<(), InvalidExecutionSpec> {
    let output_capture_failed = matches!(
        terminal_result,
        Some(ExecutionTerminalResultV1::Failed {
            reason: ExecutionFailureReasonV1::OutputCapture,
        })
    );
    if output_capture_failed
        && (!matches!(output_mode, ExecutionOutputModeV1::Capture { .. })
            || !matches!(
                captured_output,
                Some(ExecutionCapturedOutputV1::Unavailable)
                    | Some(ExecutionCapturedOutputV1::Partial { .. })
            ))
    {
        return Err(InvalidExecutionSpec::InvalidCapturedOutput);
    }
    if !is_terminal_phase(phase) || matches!(output_mode, ExecutionOutputModeV1::Stream) {
        return if captured_output.is_none() {
            Ok(())
        } else {
            Err(InvalidExecutionSpec::InvalidCapturedOutput)
        };
    }

    let captured_output = captured_output.ok_or(InvalidExecutionSpec::InvalidCapturedOutput)?;
    if matches!(phase, ExecutionObservationPhaseV1::Exited)
        && !matches!(captured_output, ExecutionCapturedOutputV1::Complete { .. })
    {
        return Err(InvalidExecutionSpec::InvalidCapturedOutput);
    }
    let streams = captured_output.streams();
    let valid_disposition = match captured_output {
        ExecutionCapturedOutputV1::Unavailable => streams.is_empty(),
        ExecutionCapturedOutputV1::Partial { .. } => !streams.is_empty(),
        ExecutionCapturedOutputV1::Complete { .. } => {
            streams.len() == MAX_EXECUTION_CAPTURED_STREAMS
                && streams[0].stream() == ExecutionCapturedStreamKindV1::Stdout
                && streams[1].stream() == ExecutionCapturedStreamKindV1::Stderr
        }
    };
    if !valid_disposition
        || streams.len() > MAX_EXECUTION_CAPTURED_STREAMS
        || !streams
            .windows(2)
            .all(|pair| pair[0].stream() < pair[1].stream())
    {
        return Err(InvalidExecutionSpec::InvalidCapturedOutput);
    }

    let ExecutionOutputModeV1::Capture {
        maximum_stdout_bytes,
        maximum_stderr_bytes,
    } = output_mode
    else {
        return Err(InvalidExecutionSpec::InvalidCapturedOutput);
    };
    for stream in streams {
        let maximum = match stream.stream() {
            ExecutionCapturedStreamKindV1::Stdout => maximum_stdout_bytes,
            ExecutionCapturedStreamKindV1::Stderr => maximum_stderr_bytes,
        };
        if stream.captured_bytes() > maximum
            || (stream.truncated() && stream.captured_bytes() != maximum)
        {
            return Err(InvalidExecutionSpec::InvalidCapturedOutput);
        }
    }
    Ok(())
}

pub(super) fn checked_environment_encoded_size(
    environment: &Environment,
) -> Result<usize, InvalidExecutionSpec> {
    let mut total = cbor_head_size(5)?;
    add_environment_encoded_size(&mut total, cbor_unsigned_size(1))?;

    add_environment_encoded_size(&mut total, cbor_head_size(environment.closure().len())?)?;
    for descriptor in environment.closure() {
        add_environment_encoded_size(&mut total, cbor_head_size(4)?)?;
        add_environment_text_size(&mut total, descriptor.media_type().as_str())?;
        add_environment_encoded_size(&mut total, cbor_unsigned_size(1))?;
        add_environment_byte_string_size(&mut total, descriptor.digest().as_bytes().len())?;
        add_environment_encoded_size(&mut total, cbor_unsigned_size(descriptor.encoded_size()))?;
    }

    add_environment_encoded_size(&mut total, cbor_head_size(environment.variables().len())?)?;
    for entry in environment.variables() {
        add_environment_encoded_size(&mut total, cbor_head_size(2)?)?;
        add_environment_text_size(&mut total, entry.name())?;
        add_environment_text_size(&mut total, entry.value())?;
    }

    add_environment_encoded_size(
        &mut total,
        cbor_head_size(environment.command_search_path().len())?,
    )?;
    for path in environment.command_search_path() {
        add_environment_encoded_size(&mut total, cbor_head_size(path.components().len())?)?;
        for component in path.components() {
            add_environment_byte_string_size(&mut total, component.as_bytes().len())?;
        }
    }

    add_environment_encoded_size(
        &mut total,
        cbor_head_size(environment.required_features().len())?,
    )?;
    for feature in environment.required_features() {
        add_environment_encoded_size(&mut total, cbor_head_size(3)?)?;
        add_environment_text_size(&mut total, feature.namespace())?;
        add_environment_encoded_size(&mut total, cbor_unsigned_size(u64::from(feature.major())))?;
        add_environment_encoded_size(&mut total, cbor_unsigned_size(u64::from(feature.minor())))?;
    }
    Ok(total)
}

pub(super) fn checked_environment_cbor_items(
    environment: &Environment,
) -> Result<usize, InvalidExecutionSpec> {
    // Top-level array, version, and the four collection arrays.
    let mut items = 6_usize;
    add_environment_items(&mut items, environment.closure().len(), 5)?;
    add_environment_items(&mut items, environment.variables().len(), 3)?;
    add_environment_items(&mut items, environment.required_features().len(), 4)?;
    for path in environment.command_search_path() {
        add_environment_items(&mut items, 1, 1)?;
        add_environment_items(&mut items, path.components().len(), 1)?;
    }
    Ok(items)
}

pub(super) fn add_environment_items(
    total: &mut usize,
    count: usize,
    items_per_value: usize,
) -> Result<(), InvalidExecutionSpec> {
    let additional = count
        .checked_mul(items_per_value)
        .ok_or(InvalidExecutionSpec::BaseEnvironmentExceeded)?;
    *total = total
        .checked_add(additional)
        .ok_or(InvalidExecutionSpec::BaseEnvironmentExceeded)?;
    if *total > MAX_EXECUTION_BASE_ENVIRONMENT_CBOR_ITEMS {
        return Err(InvalidExecutionSpec::BaseEnvironmentExceeded);
    }
    Ok(())
}

pub(super) fn add_environment_text_size(
    total: &mut usize,
    value: &str,
) -> Result<(), InvalidExecutionSpec> {
    add_environment_byte_string_size(total, value.len())
}

pub(super) fn add_environment_byte_string_size(
    total: &mut usize,
    length: usize,
) -> Result<(), InvalidExecutionSpec> {
    add_environment_encoded_size(total, cbor_head_size(length)?)?;
    add_environment_encoded_size(total, length)
}

pub(super) fn add_environment_encoded_size(
    total: &mut usize,
    additional: usize,
) -> Result<(), InvalidExecutionSpec> {
    *total = total
        .checked_add(additional)
        .ok_or(InvalidExecutionSpec::BaseEnvironmentExceeded)?;
    if *total > MAX_EXECUTION_BASE_ENVIRONMENT_BYTES {
        return Err(InvalidExecutionSpec::BaseEnvironmentExceeded);
    }
    Ok(())
}

pub(super) fn cbor_head_size(value: usize) -> Result<usize, InvalidExecutionSpec> {
    let value = u64::try_from(value).map_err(|_| InvalidExecutionSpec::BaseEnvironmentExceeded)?;
    Ok(cbor_unsigned_size(value))
}

pub(super) fn cbor_unsigned_size(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

pub(super) fn validate_arguments(arguments: &[Vec<u8>]) -> Result<(), InvalidExecutionSpec> {
    if arguments.first().is_none_or(Vec::is_empty) || arguments.len() > MAX_EXECUTION_ARGUMENTS {
        return Err(InvalidExecutionSpec::InvalidArguments);
    }
    let total_bytes = arguments.iter().try_fold(0_usize, |total, argument| {
        if argument.len() > MAX_EXECUTION_ARGUMENT_STRING_BYTES || argument.contains(&0) {
            return None;
        }
        total.checked_add(argument.len())
    });
    if total_bytes.is_none_or(|total| total > MAX_EXECUTION_ARGUMENT_BYTES) {
        return Err(InvalidExecutionSpec::InvalidArguments);
    }
    Ok(())
}

pub(super) fn validate_environment_overlay(
    environment: &[ExecutionEnvironmentEntry],
) -> Result<(), InvalidExecutionSpec> {
    if environment.len() > MAX_EXECUTION_ENVIRONMENT_ENTRIES
        || !environment
            .windows(2)
            .all(|pair| pair[0].name() < pair[1].name())
    {
        return Err(InvalidExecutionSpec::EnvironmentNotCanonical);
    }
    let total_bytes = environment.iter().try_fold(0_usize, |total, entry| {
        total
            .checked_add(entry.name().len())?
            .checked_add(entry.value().len())
    });
    if total_bytes.is_none_or(|total| total > MAX_EXECUTION_ENVIRONMENT_BYTES) {
        return Err(InvalidExecutionSpec::EnvironmentNotCanonical);
    }
    Ok(())
}

pub(super) fn visit_effective_environment(
    base: &Environment,
    command: &ExecutionCommandV1,
    mut visit: impl FnMut(&str, &[u8]) -> Result<(), InvalidExecutionSpec>,
) -> Result<(), InvalidExecutionSpec> {
    let mut base_index = 0;
    let mut overlay_index = 0;
    while base_index < base.variables().len() || overlay_index < command.environment_overlay().len()
    {
        match (
            base.variables().get(base_index),
            command.environment_overlay().get(overlay_index),
        ) {
            (Some(base_entry), Some(overlay_entry)) => {
                match base_entry.name().cmp(overlay_entry.name()) {
                    std::cmp::Ordering::Less => {
                        visit(base_entry.name(), base_entry.value().as_bytes())?;
                        base_index += 1;
                    }
                    std::cmp::Ordering::Equal => {
                        visit(overlay_entry.name(), overlay_entry.value())?;
                        base_index += 1;
                        overlay_index += 1;
                    }
                    std::cmp::Ordering::Greater => {
                        visit(overlay_entry.name(), overlay_entry.value())?;
                        overlay_index += 1;
                    }
                }
            }
            (Some(base_entry), None) => {
                visit(base_entry.name(), base_entry.value().as_bytes())?;
                base_index += 1;
            }
            (None, Some(overlay_entry)) => {
                visit(overlay_entry.name(), overlay_entry.value())?;
                overlay_index += 1;
            }
            (None, None) => break,
        }
    }
    Ok(())
}

pub(super) fn validate_resource_value(
    dimension: LimitDimension,
    value: ExecutionResourceRequestValueV1,
) -> Result<(), InvalidExecutionSpec> {
    match value {
        ExecutionResourceRequestValueV1::Inherit => validate_execution_dimension(dimension),
        ExecutionResourceRequestValueV1::Maximum(maximum) => validate_maximum(dimension, maximum),
        ExecutionResourceRequestValueV1::RelativeWeight(weight) => {
            validate_weight(dimension, weight)
        }
    }
}

pub(super) fn validate_admitted_resource_value(
    dimension: LimitDimension,
    value: ExecutionResourceSublimitValueV1,
) -> Result<(), InvalidExecutionSpec> {
    match value {
        ExecutionResourceSublimitValueV1::Maximum(maximum) => validate_maximum(dimension, maximum),
        ExecutionResourceSublimitValueV1::RelativeWeight(weight) => {
            validate_weight(dimension, weight)
        }
    }
}

pub(super) fn validate_execution_dimension(
    dimension: LimitDimension,
) -> Result<(), InvalidExecutionSpec> {
    if matches!(
        dimension,
        LimitDimension::Processes
            | LimitDimension::Memory
            | LimitDimension::CpuWeight
            | LimitDimension::CpuQuota
            | LimitDimension::IoWeight
            | LimitDimension::IoBandwidth
            | LimitDimension::OpenFiles
    ) {
        Ok(())
    } else {
        Err(InvalidExecutionSpec::InvalidResourceSetting)
    }
}

pub(super) fn validate_maximum(
    dimension: LimitDimension,
    maximum: u64,
) -> Result<(), InvalidExecutionSpec> {
    let valid = match dimension {
        LimitDimension::Processes => (1..u64::from(u32::MAX)).contains(&maximum),
        LimitDimension::Memory | LimitDimension::CpuQuota | LimitDimension::IoBandwidth => {
            (1..=i64::MAX as u64).contains(&maximum)
        }
        LimitDimension::OpenFiles => (3..u64::from(u32::MAX)).contains(&maximum),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(InvalidExecutionSpec::InvalidResourceSetting)
    }
}

pub(super) fn validate_weight(
    dimension: LimitDimension,
    weight: u16,
) -> Result<(), InvalidExecutionSpec> {
    if matches!(
        dimension,
        LimitDimension::CpuWeight | LimitDimension::IoWeight
    ) && (1..=10_000).contains(&weight)
    {
        Ok(())
    } else {
        Err(InvalidExecutionSpec::InvalidResourceSetting)
    }
}

pub(super) fn validate_resource_admission(
    request: &ExecutionResourceRequestV1,
    admitted: &ExecutionResourceSublimitV1,
    parent: &ResourceProfile,
) -> Result<(), InvalidExecutionSpec> {
    validate_execution_enforcement(request.dimension(), request.enforcement())?;
    validate_execution_enforcement(admitted.dimension(), admitted.enforcement())?;
    if request.enforcement() != admitted.enforcement() {
        return Err(InvalidExecutionSpec::ResourceEnforcementMismatch);
    }
    if matches!(
        request.dimension(),
        LimitDimension::CpuWeight | LimitDimension::IoWeight
    ) {
        return match (request.value(), admitted.value()) {
            (
                ExecutionResourceRequestValueV1::RelativeWeight(requested),
                ExecutionResourceSublimitValueV1::RelativeWeight(admitted),
            ) if requested == admitted => Ok(()),
            _ => Err(InvalidExecutionSpec::RequiredWeightAdmissionMissing),
        };
    }

    let parent_limit = parent
        .limits()
        .iter()
        .find(|limit| limit.dimension() == request.dimension())
        .ok_or(InvalidExecutionSpec::ParentResourceUnavailable)?;
    if parent_limit.enforcement() != request.enforcement()
        || parent_limit.enforcement() != admitted.enforcement()
    {
        return Err(InvalidExecutionSpec::ParentResourceUnavailable);
    }
    validate_parent_resource_value(request.dimension(), parent_limit.value())?;
    match (request.value(), admitted.value(), parent_limit.value()) {
        (
            ExecutionResourceRequestValueV1::Inherit,
            ExecutionResourceSublimitValueV1::Maximum(admitted),
            LimitValue::Bounded(parent),
        ) if admitted <= parent => Ok(()),
        (
            ExecutionResourceRequestValueV1::Maximum(requested),
            ExecutionResourceSublimitValueV1::Maximum(admitted),
            LimitValue::Bounded(parent),
        ) if admitted <= requested && admitted <= parent => Ok(()),
        (
            ExecutionResourceRequestValueV1::Inherit,
            ExecutionResourceSublimitValueV1::Maximum(_),
            LimitValue::Unlimited(grant),
        ) if grant != GrantId::from_bytes([0; 16]) => Ok(()),
        (
            ExecutionResourceRequestValueV1::Maximum(requested),
            ExecutionResourceSublimitValueV1::Maximum(admitted),
            LimitValue::Unlimited(grant),
        ) if grant != GrantId::from_bytes([0; 16]) && admitted <= requested => Ok(()),
        (
            ExecutionResourceRequestValueV1::Inherit,
            ExecutionResourceSublimitValueV1::RelativeWeight(admitted),
            LimitValue::Bounded(parent),
        ) if u64::from(admitted) == parent => Ok(()),
        (
            ExecutionResourceRequestValueV1::RelativeWeight(requested),
            ExecutionResourceSublimitValueV1::RelativeWeight(admitted),
            LimitValue::Bounded(parent),
        ) if admitted == requested && u64::from(admitted) == parent => Ok(()),
        (_, _, LimitValue::Inherited) => Err(InvalidExecutionSpec::ParentResourceUnavailable),
        _ => Err(InvalidExecutionSpec::ResourceSublimitExceeded),
    }
}

pub(super) fn validate_execution_enforcement(
    dimension: LimitDimension,
    enforcement: &FeatureRef,
) -> Result<(), InvalidExecutionSpec> {
    if &execution_enforcement_feature(dimension)? == enforcement {
        Ok(())
    } else {
        Err(InvalidExecutionSpec::ResourceEnforcementMismatch)
    }
}

pub(super) fn execution_enforcement_feature(
    dimension: LimitDimension,
) -> Result<FeatureRef, InvalidExecutionSpec> {
    let expected_namespace = match dimension {
        LimitDimension::Processes
        | LimitDimension::Memory
        | LimitDimension::CpuWeight
        | LimitDimension::CpuQuota
        | LimitDimension::IoWeight
        | LimitDimension::IoBandwidth => "aos.sandbox.enforcement.cgroup-v2",
        LimitDimension::OpenFiles => "aos.sandbox.enforcement.broker-ledger",
        _ => return Err(InvalidExecutionSpec::InvalidResourceSetting),
    };
    FeatureRef::new(expected_namespace, 1, 0)
        .map_err(|_| InvalidExecutionSpec::ResourceEnforcementMismatch)
}

pub(super) fn validate_parent_resource_value(
    dimension: LimitDimension,
    value: LimitValue,
) -> Result<(), InvalidExecutionSpec> {
    match value {
        LimitValue::Inherited => Err(InvalidExecutionSpec::ParentResourceUnavailable),
        LimitValue::Bounded(value)
            if matches!(
                dimension,
                LimitDimension::CpuWeight | LimitDimension::IoWeight
            ) =>
        {
            let weight =
                u16::try_from(value).map_err(|_| InvalidExecutionSpec::InvalidResourceSetting)?;
            validate_weight(dimension, weight)
        }
        LimitValue::Bounded(value) => validate_maximum(dimension, value),
        LimitValue::Unlimited(grant)
            if grant.as_bytes() != &[0; 16]
                && !matches!(
                    dimension,
                    LimitDimension::CpuWeight | LimitDimension::IoWeight
                ) =>
        {
            validate_execution_dimension(dimension)
        }
        LimitValue::Unlimited(_) => Err(InvalidExecutionSpec::InvalidResourceSetting),
    }
}

pub(super) fn validate_endpoint_capabilities(
    terminal_mode: ExecutionTerminalModeV1,
    route: &ExecutionAccessRouteV1,
) -> Result<(), InvalidExecutionSpec> {
    let capabilities = route.capabilities();
    let has = |capability| capabilities.binary_search(&capability).is_ok();
    let resize_legal = !has(ExecutionEndpointCapabilityV1::TerminalResize)
        || terminal_mode == ExecutionTerminalModeV1::Pty;
    let stderr_legal = terminal_mode == ExecutionTerminalModeV1::None
        || !has(ExecutionEndpointCapabilityV1::StandardError);
    let subsystem_legal = !(has(ExecutionEndpointCapabilityV1::Sftp)
        && has(ExecutionEndpointCapabilityV1::Git))
        && (terminal_mode == ExecutionTerminalModeV1::None
            || (!has(ExecutionEndpointCapabilityV1::Sftp)
                && !has(ExecutionEndpointCapabilityV1::Git)));
    if resize_legal && stderr_legal && subsystem_legal {
        Ok(())
    } else {
        Err(InvalidExecutionSpec::InvalidEndpointCapabilities)
    }
}

pub(super) fn validate_capture_limit(
    output_mode: ExecutionOutputModeV1,
    resources: &ExecutionResourceAdmissionV1,
) -> Result<(), InvalidExecutionSpec> {
    let ExecutionOutputModeV1::Capture {
        maximum_stdout_bytes,
        maximum_stderr_bytes,
    } = output_mode
    else {
        return Ok(());
    };
    let total = maximum_stdout_bytes
        .checked_add(maximum_stderr_bytes)
        .ok_or(InvalidExecutionSpec::CaptureLimitExceeded)?;
    if total <= resources.output_retention_bound() {
        Ok(())
    } else {
        Err(InvalidExecutionSpec::CaptureLimitExceeded)
    }
}

pub(super) fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

pub(super) fn strictly_increasing_by_dimension<T>(
    values: &[T],
    dimension: impl Fn(&T) -> LimitDimension,
) -> bool {
    values
        .windows(2)
        .all(|pair| dimension(&pair[0]) < dimension(&pair[1]))
}
