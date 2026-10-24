//! Bounds the closed installation/policy validation reached by a fresh issuer.
//!
//! The configuration is the actual launch installation plus two copies of the
//! defining native feature roster, its key map and an empty required-schema Vec.
//! No validator, diagnostic constructor, configuration clone or issuer runs here.
//! Historical key-clone allowances remain conservative after borrowed ordering
//! removes those copies; this row does not discount existing constructor credit.

use super::clone_controls;
use crate::ProviderError;
use crate::handshake::{Limits, NegotiationPolicy, TrustedInstallation};
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::native_import18_hello_declaration_data;
use crucible_node_format::{
    ArtifactIdentity, ContentRef, ContractError, HashRef, Id, ImplementationIdentity, SchemaRef,
};
use std::mem::size_of;

type ValidationTransientFields = [usize; 10];

// Every reason belongs to the actual transitive Validate implementations.
// These are UTF-8 byte extents of their owned String, not character counts.
const VALIDATION_REASONS: [&str; 15] = [
    "expected 1–128 bounded ASCII identifier bytes",
    "unsupported hash algorithm",
    "expected 1–128 ASCII bytes",
    "expected 64 lowercase hexadecimal characters",
    "content must use cnp.blob.v1",
    "expected 1–128 printable ASCII bytes",
    "zero schema/facet edition is forbidden",
    "expected baseline version 1",
    "array exceeds 65536 elements",
    "set must be strictly sorted with no duplicates",
    "require positive receiving ceilings within baseline hard caps",
    "both endpoints must offer and require baseline core",
    "host requires unsupported feature",
    "require bounded strictly sorted schema editions",
    "extension registry names unsupported feature",
];

/// Bounds validation key windows, retained failures and validator controls.
///
/// The caller admits these quote controls before the walk and composes its row
/// with configuration cloning and the actual issuer/registry constructors.
///
/// # Errors
/// Refuses an invalid native declaration, zero restriction, checked overflow or
/// a validation row above the original independent complete-peak restriction.
pub(super) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let implementation = &launch.selection.provider.implementation;
    let mut keys = 0usize;
    for pair in implementation.artifacts.windows(2) {
        keys = keys.max(add(pair[0].id.as_str().len(), pair[1].id.as_str().len())?);
    }
    for pair in implementation.model_definitions.windows(2) {
        let left = add(pair[0].hash.domain.len(), pair[0].hash.digest.len())?;
        let right = add(pair[1].hash.domain.len(), pair[1].hash.digest.len())?;
        keys = keys.max(add(left, right)?);
    }
    for pair in implementation.formats.windows(2) {
        keys = keys.max(add(pair[0].id.as_str().len(), pair[1].id.as_str().len())?);
    }

    let declaration = native_import18_hello_declaration_data(launch)?;
    let mut feature_bytes = 0usize;
    for feature in declaration.features_data().iter().flatten() {
        feature_bytes = feature_bytes.max(feature.len());
    }
    // The retained roster is sorted before either Vec is cloned. Twice its
    // longest actual spelling bounds either adjacent pair without sorting here.
    keys = keys.max(feature_bytes.checked_mul(2).ok_or_else(refused)?);
    for (key, _) in declaration.keys_data().iter().flatten() {
        keys = keys.max(key.len());
    }

    let diagnostic = VALIDATION_REASONS
        .iter()
        .map(|reason| reason.len())
        .max()
        .ok_or_else(refused)?;
    let string_clone = clone_controls::string_data()?;
    let transient_fields: ValidationTransientFields = [
        keys,
        string_clone[0],
        size_of::<String>() * 4, // conservative legacy owned-key allowance
        size_of::<(String, String)>() * 2,
        size_of::<Id>() * 2,            // artifact/format key results
        size_of::<(Id, u16)>() * 2,     // conservative format comparison allowance
        size_of::<ContractError>() * 2, // actual validation error/return
        size_of::<ProviderError>() * 2, // conversion and constructor return
        size_of::<Result<(), ContractError>>() * 2,
        size_of::<Result<(), ProviderError>>() * 2,
    ];
    let transient = total(&transient_fields)?;
    let scratch = add(counter_scratch_data(), string_clone[1])?;
    let row = [diagnostic, transient, scratch];
    if maximum == 0 || total(&row)? > maximum {
        return Err(refused());
    }
    Ok(row)
}

/// Names the actual bounded quote and closed validator iteration controls.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<&PacketNative5SourceLaunch>()
        + size_of::<&TrustedInstallation>()
        + size_of::<&NegotiationPolicy>()
        + size_of::<&ImplementationIdentity>()
        + size_of::<std::slice::Windows<'static, ArtifactIdentity>>()
        + size_of::<std::slice::Windows<'static, ContentRef>>()
        + size_of::<std::slice::Windows<'static, SchemaRef>>()
        + size_of::<std::slice::Windows<'static, Id>>() * 2
        + size_of::<std::slice::Iter<'static, ArtifactIdentity>>()
        + size_of::<std::slice::Iter<'static, ContentRef>>()
        + size_of::<std::slice::Iter<'static, SchemaRef>>()
        + size_of::<std::slice::Iter<'static, Id>>() * 4
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<Option<usize>>()
        + size_of::<ValidationTransientFields>()
        + size_of::<std::collections::btree_map::Iter<'static, String, Id>>()
        + size_of::<&HashRef>()
        + size_of::<&ContentRef>()
        + size_of::<&SchemaRef>()
        + size_of::<&ArtifactIdentity>()
        + size_of::<std::str::Bytes<'static>>() * 4
        + size_of::<&str>() * 6
        + size_of::<Option<u8>>() * 4
        + size_of::<u8>() * 4
        + size_of::<bool>() * 6
        + size_of::<usize>() * 12
        + size_of::<[usize; 3]>() * 2
        + size_of::<[usize; 2]>()
        + size_of::<Result<usize, ProviderError>>() * 4
        + size_of::<Result<[usize; 3], ProviderError>>()
        + Limits::validation_counter_scratch_data()
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}

fn total(values: &[usize]) -> Result<usize, ProviderError> {
    values
        .iter()
        .try_fold(0usize, |sum, value| add(sum, *value))
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original Hello configuration validation")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::Handshake;
    use crucible_node_format::{MAX_ARRAY_ELEMENTS, U64};

    #[test]
    fn actual_retained_constructor_reasons_fit_the_closed_diagnostic_roster() {
        for fault in 0..VALIDATION_REASONS.len() {
            let (launch, mut installation, mut policy) =
                super::super::tests::configuration_data(false);
            let schema = SchemaRef {
                id: Id::new("fixture/schema").unwrap(),
                version: 1,
                definition: installation.launch_receipt.clone(),
                extensions: Default::default(),
            };
            match fault {
                0 => {
                    policy
                        .envelope_extension_features
                        .insert("?invalid".into(), Id::new("cnp.core/1").unwrap());
                }
                1 => installation.launch_receipt.hash.algorithm = "unsupported".into(),
                2 => installation.launch_receipt.hash.domain.clear(),
                3 => installation.launch_receipt.hash.digest = "A".repeat(64),
                4 => installation.launch_receipt.hash.domain = "other.valid".into(),
                5 => installation.launch_receipt.media_type.clear(),
                6 => {
                    installation.measured_implementation.formats = vec![SchemaRef {
                        version: 0,
                        ..schema
                    }]
                }
                7 => installation.measured_implementation.schema_version = 2,
                8 => {
                    policy.supported_features =
                        vec![Id::new("cnp.core/1").unwrap(); MAX_ARRAY_ELEMENTS + 1]
                }
                9 => policy.supported_features = vec![Id::new("cnp.core/1").unwrap(); 2],
                10 => policy.provider_limits.frame_bytes = U64::new(0),
                11 => policy.required_features.clear(),
                12 => {
                    policy.required_features = vec![
                        Id::new("cnp.core/1").unwrap(),
                        Id::new("zzz/unknown").unwrap(),
                    ]
                }
                13 => policy.required_schemas = vec![schema.clone(), schema],
                14 => {
                    policy
                        .envelope_extension_features
                        .insert("zzz/extension".into(), Id::new("zzz/unknown").unwrap());
                }
                _ => unreachable!(),
            }
            let row = construction_data(&launch, 268_435_456).unwrap();
            let mut installation = Some(installation);
            let mut policy = Some(policy);
            let mut output = None;

            let failure = Handshake::from_retained_configuration_data(
                &mut installation,
                &mut policy,
                &mut output,
            )
            .unwrap_err();

            let ProviderError::Contract(ContractError::Invalid { reason, .. }) = failure else {
                panic!("fault={fault}: unexpected error");
            };
            assert_eq!(reason, VALIDATION_REASONS[fault], "fault={fault}");
            assert!(reason.capacity() <= row[0]);
            assert!(installation.is_some());
            assert!(policy.is_some());
            assert!(output.is_none());
        }
    }

    #[test]
    fn both_real_native_configurations_validate_with_independent_peak_restriction() {
        for reactive in [false, true] {
            let (launch, installation, policy) = super::super::tests::configuration_data(reactive);
            let row = construction_data(&launch, 268_435_456).unwrap();
            let peak = row.into_iter().sum::<usize>();

            Handshake::new(installation, policy).unwrap();

            assert!(construction_data(&launch, peak - 1).is_err());
            assert!(construction_data(&launch, 0).is_err());
        }
    }
}
