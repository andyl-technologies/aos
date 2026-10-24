//! Exercises actual result ownership, bounded entropy progress and full clones.

use super::*;
use crate::reference_packet::service::complete_restore::import18::{
    hello::native_import18_hello_declaration_data, inert_bootstrap_fixtures,
};
use crucible_node_format::{Extensions, FacetSelection, Id, NodeManifest};
use serde_json::json;
use std::time::Duration;

fn fixture(
    reactive: bool,
) -> (
    PacketNative5SourceLaunch,
    PacketNativeImport18HelloSelectionData,
    HelloRequest,
) {
    let launch: PacketNative5SourceLaunch = serde_json::from_value(
        inert_bootstrap_fixtures::initial_selected_launch(reactive)["launch"].clone(),
    )
    .unwrap();
    let declaration = native_import18_hello_declaration_data(&launch).unwrap();
    let mut selection = None;
    declaration
        .retain_selection_into_data(&mut selection)
        .unwrap();
    let selection = selection.unwrap();
    let request = HelloRequest {
        versions: vec!["CNP/2".into(), "CNP/1".into()],
        session_id: launch.selection.realization.bindings[0]
            .authority
            .session_id
            .clone(),
        controller_nonce: Bytes::new(vec![19; 32]),
        required_features: selection.0.clone(),
        optional_features: vec![Id::new("vendor.unselected/1").unwrap()],
        limits: launch.limits,
        admission_token: launch.admission_token.clone(),
        resume_session: None,
        extensions: Extensions::new(),
    };
    (launch, selection, request)
}

fn quoted(launch: &PacketNative5SourceLaunch, cut: OperationalDeadline) -> (Attempt, [usize; 3]) {
    let row = super::super::construction_data(launch, 268_435_456).unwrap();
    let mut attempt = Attempt::empty_data();
    assert_eq!(attempt.retained_backing_data().unwrap(), 0);
    attempt.start_data(cut).unwrap();
    attempt.quote_data(row).unwrap();
    (attempt, row)
}

#[test]
fn actual_kernel_result_owns_both_challenges_and_the_complete_provider_manifest() {
    for reactive in [false, true] {
        let (launch, selection, request) = fixture(reactive);
        let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
        let (mut attempt, row) = quoted(&launch, cut);

        attempt
            .construct_data(&launch, &selection, &request, launch.limits, cut)
            .unwrap();
        let backing = attempt.retained_backing_data().unwrap();
        assert!(backing > 0 && backing <= row[0]);
        assert_eq!(attempt.filled, 32);
        let result = attempt.result.as_ref().unwrap();
        assert_eq!(result.version, "CNP/1");
        assert_eq!(result.controller_nonce, request.controller_nonce);
        assert_ne!(
            result.controller_nonce.as_slice().as_ptr(),
            request.controller_nonce.as_slice().as_ptr()
        );
        assert_eq!(result.provider_nonce.as_slice(), attempt.provider_nonce);
        assert_ne!(
            result.provider_nonce.as_slice().as_ptr(),
            attempt.provider_nonce.as_ptr()
        );
        assert_eq!(result.selected_features, selection.0);
        assert_eq!(result.limits, launch.limits);
        assert_eq!(result.provider_identity, launch.selection.provider);
        assert!(result.resume_token.0.is_none());
        assert!(result.resumed_operations.is_empty());
        let pointers = (
            result.provider_nonce.as_slice().as_ptr(),
            result.selected_features.as_ptr(),
        );

        attempt.complete_data().unwrap();
        assert_eq!(
            (
                attempt
                    .data(cut)
                    .unwrap()
                    .provider_nonce
                    .as_slice()
                    .as_ptr(),
                attempt.data(cut).unwrap().selected_features.as_ptr(),
            ),
            pointers
        );
        assert!(attempt.start_data(cut).is_err());
        assert_eq!(attempt.retained_backing_data().unwrap(), backing);
    }
}

#[test]
fn partial_entropy_and_interruption_fill_only_the_original_unwritten_suffix() {
    let (launch, _, _) = fixture(false);
    let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
    let (mut attempt, _) = quoted(&launch, cut);
    let mut calls = 0;

    attempt
        .fill_current_data(cut, |destination| {
            calls += 1;
            match calls {
                1 => {
                    assert_eq!(destination.len(), 32);
                    destination[..7].fill(19);
                    Ok(7)
                }
                2 => {
                    assert_eq!(destination.len(), 25);
                    Err(Errno::INTR)
                }
                3 => {
                    assert_eq!(destination.len(), 25);
                    destination.fill(23);
                    Ok(25)
                }
                _ => panic!("completed entropy must not be read again"),
            }
        })
        .unwrap();

    assert_eq!(calls, 3);
    assert_eq!(attempt.filled, 32);
    assert_eq!(&attempt.provider_nonce[..7], &[19; 7]);
    assert_eq!(&attempt.provider_nonce[7..], &[23; 25]);
    assert_eq!(attempt.entropy_error, Some(Errno::INTR));
    assert!(attempt.result.is_none());
    assert_eq!(attempt.retained_backing_data().unwrap(), 0);
    assert!(attempt.complete_data().is_err());
}

#[test]
fn unavailable_entropy_retains_partial_bytes_without_fallback_or_retry_credit() {
    let (launch, _, _) = fixture(false);
    let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
    let (mut attempt, _) = quoted(&launch, cut);
    let mut calls = 0;

    assert!(
        attempt
            .fill_current_data(cut, |destination| {
                calls += 1;
                if calls == 1 {
                    destination[..9].fill(31);
                    Ok(9)
                } else {
                    Err(Errno::AGAIN)
                }
            })
            .is_err()
    );
    attempt.refuse_data();

    assert_eq!(calls, 2);
    assert_eq!(attempt.filled, 9);
    assert_eq!(&attempt.provider_nonce[..9], &[31; 9]);
    assert_eq!(&attempt.provider_nonce[9..], &[0; 23]);
    assert_eq!(attempt.entropy_error, Some(Errno::AGAIN));
    assert!(attempt.result.is_none());
    assert!(attempt.start_data(cut).is_err());
    assert_eq!(attempt.retained_backing_data().unwrap(), 0);
}

#[test]
fn expired_or_substituted_original_cut_precedes_kernel_entropy_and_allocation() {
    let (launch, selection, request) = fixture(false);
    for expired in [false, true] {
        let cut = if expired {
            OperationalDeadline::expired_fixture()
        } else {
            OperationalDeadline::after(Duration::from_secs(5)).unwrap()
        };
        let (mut attempt, _) = quoted(&launch, cut);
        let supplied = if expired {
            cut
        } else {
            OperationalDeadline::after(Duration::from_secs(4)).unwrap()
        };

        assert!(
            attempt
                .construct_data(&launch, &selection, &request, launch.limits, supplied)
                .is_err()
        );

        assert_eq!(attempt.filled, 0);
        assert_eq!(attempt.provider_nonce, [0; 32]);
        assert!(attempt.entropy_error.is_none());
        assert!(attempt.result.is_none());
        assert!(attempt.start_data(cut).is_err());
        assert_eq!(attempt.retained_backing_data().unwrap(), 0);
    }
}

#[test]
fn full_profile_facet_and_extension_clones_fit_without_using_original_spare_capacity() {
    let (mut launch, selection, request) = fixture(false);
    let receipt = launch.selection.admission_receipt.clone();
    let schema = launch.selection.provider.implementation.formats[0].clone();
    launch
        .selection
        .provider
        .supported_profiles
        .push(NodeManifest {
            schema_version: 1,
            profile_id: Id::new("vendor/full-profile/1").unwrap(),
            roles: vec![Id::new("producer").unwrap()],
            configuration_schema: schema.clone(),
            allowed_combinations_ref: receipt.clone(),
            port_templates_ref: receipt.clone(),
            state_formats: vec![schema],
            operation_facets: vec![FacetSelection {
                id: Id::new("vendor/full-facet/1").unwrap(),
                version: 1,
                configuration_ref: receipt.clone(),
                guarantees_ref: receipt,
                extensions: Extensions::from([("vendor/facet".into(), json!({"x":[1,2,3]}))]),
            }],
            extensions: Extensions::from([("RawValue".into(), json!({"literal":"[plain text]"}))]),
        });
    let cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
    let (mut attempt, row) = quoted(&launch, cut);
    launch.selection.provider.supported_profiles.reserve(64);
    assert_eq!(
        super::super::construction_data(&launch, 268_435_456).unwrap(),
        row
    );

    attempt
        .construct_data(&launch, &selection, &request, launch.limits, cut)
        .unwrap();

    assert!(attempt.retained_backing_data().unwrap() <= row[0]);
    assert_eq!(
        attempt.result.as_ref().unwrap().provider_identity,
        launch.selection.provider
    );
    let peak = row.into_iter().sum::<usize>();
    assert_eq!(super::super::construction_data(&launch, peak).unwrap(), row);
    assert!(super::super::construction_data(&launch, peak - 1).is_err());
    assert!(super::super::construction_data(&launch, 0).is_err());
}
