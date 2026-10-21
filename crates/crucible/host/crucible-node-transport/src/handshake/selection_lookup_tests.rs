//! Checks direct advertised-set lookup against the original union semantics.

use super::*;

#[test]
fn validated_advertisements_match_an_independent_union_for_every_small_feature_combination() {
    let optional_names = ["cnp.core/1", "cnp.resume/1", "vendor.unselected/1"];
    for require_resume in [false, true] {
        for mask in 0..8 {
            for select_resume in [false, true] {
                let mut request = hello();
                if require_resume {
                    request.required_features.push(id("cnp.resume/1"));
                }
                request.optional_features = optional_names
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| mask & (1 << index) != 0)
                    .map(|(_, name)| id(name))
                    .collect();
                let mut response = result();
                if !select_resume {
                    response.selected_features = vec![id("cnp.core/1")];
                    response.resume_token = Nullable(None);
                }
                let offered: BTreeSet<_> = request
                    .required_features
                    .iter()
                    .chain(&request.optional_features)
                    .collect();
                let expected = response
                    .selected_features
                    .iter()
                    .all(|feature| offered.contains(feature))
                    && request
                        .required_features
                        .iter()
                        .all(|feature| response.selected_features.contains(feature));
                let mut issuer = handshake();
                let mut verifier = Verifier::default();

                let outcome =
                    issuer.admit_exchange(&request, &response, id("lookup/1"), &mut verifier);

                assert_eq!(
                    outcome.is_ok(),
                    expected,
                    "required={require_resume}, optional={mask}, selected={select_resume}"
                );
                assert_eq!(verifier.authenticated, usize::from(expected));
                assert_eq!(verifier.contracts, usize::from(expected));
                if let Ok(authority) = outcome {
                    assert_eq!(authority.selected_features(), &response.selected_features);
                    assert_eq!(
                        authority.envelope_extensions().contains("resume-envelope"),
                        select_resume
                    );
                    assert!(authority.ensure_live().is_ok());
                }
            }
        }
    }
}

#[test]
fn invalid_id_set_order_and_duplicates_refuse_before_direct_lookup_and_callbacks() {
    for required in [false, true] {
        let mut request = hello();
        if required {
            request.required_features.push(id("cnp.core/1"));
        } else {
            request.optional_features = vec![id("cnp.resume/1"), id("cnp.core/1")];
        }
        let mut verifier = Verifier::default();

        let outcome =
            handshake().admit_exchange(&request, &result(), id("invalid-lookup/1"), &mut verifier);

        assert!(matches!(outcome, Err(ProviderError::Contract(_))));
        assert_eq!(verifier.authenticated, 0);
        assert_eq!(verifier.contracts, 0);
    }
}

#[test]
fn selected_envelope_names_match_the_entire_installed_policy_projection() {
    for select_resume in [false, true] {
        for select_vendor in [false, true] {
            let names = std::collections::BTreeMap::from([
                ("baseline-envelope".to_owned(), id("cnp.core/1")),
                ("resume-envelope".to_owned(), id("cnp.resume/1")),
                ("second-baseline-envelope".to_owned(), id("cnp.core/1")),
                ("vendor-envelope".to_owned(), id("vendor.optional/1")),
            ]);
            let mut issuer = Handshake::new(
                TrustedInstallation {
                    session_id: id("session"),
                    incarnation_id: id("incarnation"),
                    measured_implementation: manifest().implementation,
                    launch_receipt: reference(),
                    admission_token: [7; 32],
                },
                NegotiationPolicy {
                    supported_features: vec![
                        id("cnp.core/1"),
                        id("cnp.resume/1"),
                        id("vendor.optional/1"),
                    ],
                    required_features: vec![id("cnp.core/1")],
                    provider_limits: limits(),
                    required_schemas: Vec::new(),
                    required_guarantees: reference(),
                    envelope_extension_features: names.clone(),
                },
            )
            .unwrap();
            let mut request = hello();
            request.optional_features.push(id("vendor.optional/1"));
            let mut response = result();
            if !select_resume {
                response.selected_features = vec![id("cnp.core/1")];
                response.resume_token = Nullable(None);
            }
            if select_vendor {
                response.selected_features.push(id("vendor.optional/1"));
            }
            let expected: BTreeSet<_> = names
                .into_iter()
                .filter(|(_, feature)| response.selected_features.contains(feature))
                .map(|(name, _)| name)
                .collect();

            let authority = issuer
                .admit_exchange(
                    &request,
                    &response,
                    id("policy-lookup/1"),
                    &mut Verifier::default(),
                )
                .unwrap();

            assert_eq!(authority.envelope_extensions(), &expected);
            assert_eq!(authority.selected_features(), &response.selected_features);
        }
    }
}
