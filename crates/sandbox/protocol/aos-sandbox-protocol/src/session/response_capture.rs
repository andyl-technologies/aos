//! Private reached response projections for an admitted terminal comparison.

use super::*;
use aos_sandbox_model::retained::CaptureValueV1;

#[derive(Default)]
pub(crate) struct ResponseEnvelopeCaptureV1 {
    pub(super) raw: BrokerResponseEnvelope,
    pub(super) error: Option<ValidatedBrokerError>,
    pub(super) feature: ErrorFeatureCaptureV1,
    pub(super) descriptor_table: DescriptorTableCaptureV1,
    pub(super) descriptors: Vec<ValidatedDescriptorEntry>,
    pub(super) dispositions: Vec<ValidatedDescriptorDisposition>,
}

#[derive(Default)]
pub(super) struct ErrorFeatureCaptureV1 {
    pub(super) namespace: Option<String>,
    pub(super) syntax: Option<Result<FeatureRef, aos_sandbox_model::selector::InvalidFeatureNamespace>>,
    pub(super) feature: Option<FeatureRef>,
}

#[derive(Default)]
pub(super) struct DescriptorTableCaptureV1 {
    pub(super) roles: Vec<BrokerDescriptorRole>,
    pub(super) descriptors: Vec<ValidatedDescriptorEntry>,
}

impl ResponseEnvelopeCaptureV1 {
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.feature.syntax.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

pub(crate) fn validate_decoded_response_envelope_engine(
    envelope: BrokerResponseEnvelope,
    expected_request_id: &[u8; 16],
    expected_method: BrokerMethod,
    request_descriptors: &[ValidatedDescriptorEntry],
    ancillary_descriptor_count: usize,
    capture: Option<&mut ResponseEnvelopeCaptureV1>,
) -> Result<ValidatedBrokerResponseEnvelope, ProtocolValidationError> {
    let (raw, error_slot, feature, descriptor_table, descriptors_slot, dispositions) =
        match capture {
            Some(capture) => (
                Some(&mut capture.raw), Some(&mut capture.error),
                Some(&mut capture.feature), Some(&mut capture.descriptor_table),
                Some(&mut capture.descriptors), Some(&mut capture.dispositions),
            ),
            None => (None, None, None, None, None, None),
        };
    let envelope = CaptureValueV1::new(envelope, raw);

    if !envelope.__buffa_unknown_fields.is_empty() || !envelope.signed_session_outcome.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let request_id = exact_nonzero::<16>(&envelope.request_id, "envelope.request_id")?;
    if &request_id != expected_request_id || envelope.method.as_known() != Some(expected_method) {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    if !valid_response_body_shape(
        expected_method,
        envelope.body.is_empty(),
        envelope.error.as_option().is_some(),
    ) {
        return Err(ProtocolValidationError::InvalidField(
            "response body/error shape",
        ));
    }
    let error = CaptureValueV1::new(
        envelope.error.as_option()
            .map(|error| validate_broker_error_engine(error, feature)).transpose()?,
        error_slot,
    );
    let descriptors = CaptureValueV1::new(
        validate_descriptor_table_engine(
            &envelope.descriptors, ancillary_descriptor_count, descriptor_table,
        )?,
        descriptors_slot,
    );
    if matches!(
        expected_method,
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_PAYLOAD_SCOPE
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1
            | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP
    ) {
        let expected_roles: &[BrokerDescriptorRole] = if error.is_some() {
            &[]
        } else if matches!(
            expected_method,
            BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
                | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE_IDENTITY_V1
        ) {
            &crate::mount_scope::MOUNT_SCOPE_DESCRIPTOR_ROLES
        } else if expected_method == BrokerMethod::BROKER_METHOD_HOST_OBSERVE_CONSUMER_CGROUP {
            &crate::host_consumer_cgroup::CONSUMER_CGROUP_DESCRIPTOR_ROLES_V1
        } else {
            &crate::payload_scope::PAYLOAD_SCOPE_DESCRIPTOR_ROLES
        };
        if !request_descriptors.is_empty()
            || descriptors.len() != expected_roles.len()
            || descriptors
                .iter()
                .zip(expected_roles)
                .any(|(actual, expected)| actual.role != *expected)
        {
            return Err(ProtocolValidationError::DescriptorTableMismatch);
        }
    } else if is_mount_source_acquisition_method(expected_method) {
        if !request_descriptors.is_empty() || !descriptors.is_empty() {
            return Err(ProtocolValidationError::DescriptorTableMismatch);
        }
    } else if descriptors
        .iter()
        .any(|entry| crate::payload_scope::PAYLOAD_SCOPE_DESCRIPTOR_ROLES.contains(&entry.role))
    {
        return Err(ProtocolValidationError::DescriptorTableMismatch);
    }
    let request_descriptor_dispositions = validate_descriptor_dispositions_engine(
        &envelope.request_descriptor_dispositions,
        request_descriptors,
        dispositions,
    )?;
    Ok(ValidatedBrokerResponseEnvelope {
        request_id,
        method: expected_method,
        body: envelope.take().body,
        descriptors: descriptors.take(),
        request_descriptor_dispositions,
        error: error.take(),
    })
}

pub(super) fn validate_broker_error_engine(
    error: &BrokerError,
    capture: Option<&mut ErrorFeatureCaptureV1>,
) -> Result<ValidatedBrokerError, ProtocolValidationError> {
    let (namespace, syntax, feature_slot) = match capture {
        Some(capture) => (Some(&mut capture.namespace), Some(&mut capture.syntax), Some(&mut capture.feature)),
        None => (None, None, None),
    };

    if !error.__buffa_unknown_fields.is_empty()
        || error.safe_message.is_empty()
        || error.safe_message.len() > MAXIMUM_SAFE_ERROR_MESSAGE_BYTES
        || error.safe_message.chars().any(char::is_control)
    {
        return Err(ProtocolValidationError::InvalidBrokerError);
    }
    let code = error
        .code
        .as_known()
        .filter(|code| *code != BrokerErrorCode::BROKER_ERROR_CODE_UNSPECIFIED)
        .ok_or(ProtocolValidationError::InvalidBrokerError)?;
    let missing_feature = CaptureValueV1::new(
        error.missing_feature.as_option()
            .map(|feature| validate_error_feature_engine(feature, namespace, syntax)).transpose()?,
        feature_slot,
    );
    if (code == BrokerErrorCode::BROKER_ERROR_CODE_REQUIRED_FEATURE_UNAVAILABLE)
        != missing_feature.is_some()
    {
        return Err(ProtocolValidationError::InvalidBrokerError);
    }
    Ok(ValidatedBrokerError {
        code,
        safe_message: error.safe_message.clone(),
        retryable: error.retryable,
        missing_feature: missing_feature.take(),
    })
}

pub(super) fn validate_error_feature_engine(
    feature: &aos_sandbox_api::aos::sandbox::local::v1::Feature,
    namespace: Option<&mut Option<String>>,
    syntax: Option<&mut Option<Result<FeatureRef, aos_sandbox_model::selector::InvalidFeatureNamespace>>>,
) -> Result<FeatureRef, ProtocolValidationError> {
    if !feature.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::InvalidBrokerError);
    }
    match namespace {
        Some(namespace) => {
            *namespace = Some(feature.namespace.clone());
            let syntax = syntax.ok_or(ProtocolValidationError::InvalidBrokerError)?;
            *syntax = Some(FeatureRef::new_retaining_v1(namespace, feature.major, feature.minor));
            if matches!(syntax, Some(Err(_))) {
                return Err(ProtocolValidationError::InvalidBrokerError);
            }
            syntax.take().ok_or(ProtocolValidationError::InvalidBrokerError)?
                .map_err(|_| ProtocolValidationError::InvalidBrokerError)
        }
        None => FeatureRef::new(feature.namespace.clone(), feature.major, feature.minor)
            .map_err(|_| ProtocolValidationError::InvalidBrokerError),
    }
}

pub(super) fn validate_descriptor_table_engine(
    source: &[BrokerDescriptorEntry],
    ancillary_descriptor_count: usize,
    capture: Option<&mut DescriptorTableCaptureV1>,
) -> Result<Vec<ValidatedDescriptorEntry>, ProtocolValidationError> {
    if source.len() > MAXIMUM_PACKET_DESCRIPTORS {
        return Err(ProtocolValidationError::TooManyEntries {
            field: "envelope.descriptors",
            maximum: MAXIMUM_PACKET_DESCRIPTORS,
        });
    }
    if source.len() != ancillary_descriptor_count {
        return Err(ProtocolValidationError::DescriptorTableMismatch);
    }
    let (roles_slot, descriptor_slot) = match capture {
        Some(capture) => (Some(&mut capture.roles), Some(&mut capture.descriptors)),
        None => (None, None),
    };
    let mut roles = CaptureValueV1::new(Vec::with_capacity(source.len()), roles_slot);
    let mut descriptors = CaptureValueV1::new(Vec::with_capacity(source.len()), descriptor_slot);
    for (index, entry) in source.iter().enumerate() {
        if !entry.__buffa_unknown_fields.is_empty() || usize::try_from(entry.index) != Ok(index) {
            return Err(ProtocolValidationError::DescriptorTableMismatch);
        }
        let role = entry
            .role
            .as_known()
            .filter(|role| *role != BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_UNSPECIFIED)
            .ok_or(ProtocolValidationError::DescriptorTableMismatch)?;
        if roles.contains(&role) {
            return Err(ProtocolValidationError::DescriptorTableMismatch);
        }
        roles.push(role);
        descriptors.push(ValidatedDescriptorEntry { role });
    }
    Ok(descriptors.take())
}

pub(super) fn validate_descriptor_dispositions_engine(
    source: &[BrokerDescriptorDispositionEntry],
    request_descriptors: &[ValidatedDescriptorEntry],
    capture: Option<&mut Vec<ValidatedDescriptorDisposition>>,
) -> Result<Vec<ValidatedDescriptorDisposition>, ProtocolValidationError> {
    if source.len() != request_descriptors.len() {
        return Err(ProtocolValidationError::DescriptorTableMismatch);
    }
    let mut dispositions = CaptureValueV1::new(Vec::with_capacity(source.len()), capture);
    for (index, (entry, request)) in source.iter().zip(request_descriptors).enumerate() {
        let disposition = entry.disposition.as_known().filter(|value| {
            *value != BrokerDescriptorDisposition::BROKER_DESCRIPTOR_DISPOSITION_UNSPECIFIED
        });
        if !entry.__buffa_unknown_fields.is_empty()
            || usize::try_from(entry.request_index) != Ok(index)
            || entry.role.as_known() != Some(request.role)
            || disposition.is_none()
        {
            return Err(ProtocolValidationError::DescriptorTableMismatch);
        }
        dispositions.push(ValidatedDescriptorDisposition {
            role: request.role,
            disposition: disposition.ok_or(ProtocolValidationError::DescriptorTableMismatch)?,
        });
    }
    Ok(dispositions.take())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_descriptor_refusal_keeps_actual_prior_role_and_entry() {
        let mut response = BrokerResponseEnvelope::default();
        response.request_id = vec![1; 16];
        response.method = BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES.into();
        response.body = vec![1];
        response.descriptors = vec![
            BrokerDescriptorEntry {
                index: 0,
                role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT.into(),
                ..Default::default()
            },
            BrokerDescriptorEntry {
                index: 1,
                role: BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT.into(),
                ..Default::default()
            },
        ];
        let mut original = ResponseEnvelopeCaptureV1::default();

        assert!(super::super::validate_decoded_response_envelope_engine(
            response, &[1; 16], BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
            &[], 2, Some(&mut original),
        ).is_err());

        assert_eq!(original.raw.descriptors.len(), 2);
        assert_eq!(original.descriptor_table.roles.len(), 1);
        assert_eq!(original.descriptor_table.descriptors.len(), 1);
    }

    #[test]
    fn error_feature_syntax_failure_keeps_actual_string_and_typed_error() {
        let feature = aos_sandbox_api::aos::sandbox::local::v1::Feature {
            namespace: "Invalid.NAMESPACE".to_owned(), major: 1, minor: 0,
            ..Default::default()
        };
        let mut original = ErrorFeatureCaptureV1::default();

        assert!(super::validate_error_feature_engine(
            &feature, Some(&mut original.namespace), Some(&mut original.syntax),
        ).is_err());

        assert_eq!(original.namespace.as_deref(), Some("Invalid.NAMESPACE"));
        assert!(matches!(original.syntax, Some(Err(_))));
    }
}
