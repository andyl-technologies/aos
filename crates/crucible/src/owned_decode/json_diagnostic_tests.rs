//! Closed-schema parity, malformed-input bounds and opaque diagnostic controls.

// crucible-lint: allow panic-shortcut -- fixture failures identify malformed-input acceptance, missing original credit, or premature physical payload/control close; no production panic or admission is added.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::owned_decode::json_diagnostic::{diagnostic_extent, input_debug_bytes};
use crate::owned_decode::json_profiles::{ClosedJsonProfile, assets, bootstrap, policy, workflow};
use crucible_linux_resource::test_support::TestAllocationObserver;
use std::fmt::{self, Write};

fn paid_error<'input, T: ClosedJsonProfile<'input>>(bytes: &'input [u8]) -> ClosedJsonError {
    let budget = DecodeBudget::new(authority(1 << 20), 1 << 20).unwrap();
    match from_json_slice_closed::<T>(bytes, &budget) {
        Ok(_) => panic!("malformed fixture was accepted"),
        Err(error) => error,
    }
}

fn compare_error<'input, T: ClosedJsonProfile<'input>>(bytes: &'input [u8]) {
    let ordinary = match serde_json::from_slice::<T>(bytes) {
        Ok(_) => panic!("malformed fixture was accepted by the ordinary parser"),
        Err(error) => error,
    };
    let ClosedJsonError::Json(paid) = paid_error::<T>(bytes) else {
        panic!("healthy original did not retain the actual JSON error");
    };

    assert_eq!(paid.to_string(), ordinary.to_string());
    assert_eq!(paid.classify(), ordinary.classify());
    assert_eq!(paid.line(), ordinary.line());
    assert_eq!(paid.column(), ordinary.column());
    assert!(Error::source(&paid).is_none());
    assert!(
        diagnostic_extent(bytes, T::DIAGNOSTIC_LABELS).unwrap()
            >= paid.to_string().len() as u64 + 80
    );
}

#[test]
fn all_closed_roots_preserve_actual_error_text_and_coordinates() {
    for bytes in [
        b"null".as_slice(),
        b"[]",
        b"{}",
        b"{",
        b"{\"unexpected\":1}",
        b"{\"schema\":false}",
    ] {
        compare_error::<policy::Projection<'_>>(bytes);
        compare_error::<bootstrap::Target<'_>>(bytes);
        compare_error::<workflow::WorkflowProjection<'_>>(bytes);
        compare_error::<assets::Projection>(bytes);
    }
    for bytes in [
        br#"{"schema":"a","schema":"b"}"#.as_slice(),
        br#"{"document":{"schema":"x","version":-1}}"#,
        br#"{"document":{"schema":"x","version":1.25}}"#,
        br#"{"document":{"schema":"x","version":18446744073709551616}}"#,
        br#"{"document":{"schema":"x","version":1,"bindings":[{"user_id":"x"}]}}"#,
        br#"{"schema":"escaped\nborrow"}"#,
    ] {
        compare_error::<policy::Projection<'_>>(bytes);
    }
    compare_error::<workflow::WorkflowProjection<'_>>(
        br#"{"serviceProfile":{"operator":{"campaignMode":"unknown"}}}"#,
    );
    compare_error::<assets::Projection>(br#"{"guestAssets":{"rootImageFormat":"unknown"}}"#);
    compare_error::<assets::Projection>(br#"{"rows":[{"attempts":[{"scenarioId":"invalid"}]}]}"#);
    compare_error::<assets::Projection>(
        br#"{"rows":[{"attempts":[{"campaignCreation":{"requestDigest":"invalid"}}]}]}"#,
    );
}

#[test]
fn healthy_policy_borrowing_and_values_survive_the_closed_entry() {
    let bytes = br#"{"schema":"projection","originalTomlBlake3":"hash","document":{"schema":"policy","version":1,"bindings":[{"user_id":7,"group_id":8,"principal":"operator"}],"grants":[]}}"#;
    let budget = DecodeBudget::new(authority(1 << 20), 1 << 20).unwrap();
    let custody = budget.custody();

    let paid: policy::Projection<'_> = from_json_slice_closed(bytes, &budget).unwrap();
    let ordinary: policy::Projection<'_> = serde_json::from_slice(bytes).unwrap();

    assert_eq!(paid.schema, ordinary.schema);
    assert_eq!(paid.document.version, ordinary.document.version);
    assert_eq!(paid.document.bindings[0].principal, "operator");
    let address = paid.document.bindings[0].principal.as_ptr() as usize;
    assert!((bytes.as_ptr() as usize..bytes.as_ptr() as usize + bytes.len()).contains(&address));
    assert!(budget.failure().unwrap().is_none());
    drop(paid);
    drop(custody);
}

#[test]
fn diagnostic_before_later_invalid_utf8_retains_its_full_input_contribution() {
    let name = "valid-identity".repeat(256);
    let mut bytes = format!("{{\"{name}\":0,\"later\":\"").into_bytes();
    bytes.push(0xff);
    bytes.extend_from_slice(b"\"}");

    compare_error::<policy::Projection<'_>>(&bytes);
    assert!(input_debug_bytes(&bytes).unwrap() >= name.len() as u64);
    let error = paid_error::<policy::Projection<'_>>(&bytes);
    assert!(error.to_string().contains(&name));
}

#[test]
fn ignored_invalid_utf8_before_later_diagnostic_does_not_zero_the_bound() {
    let name = "later-identity".repeat(256);
    let mut bytes = b"{\"hotFork\":\"".to_vec();
    bytes.push(0xff);
    bytes.extend_from_slice(format!("\",\"{name}\":0}}").as_bytes());

    compare_error::<assets::Projection>(&bytes);
    assert!(input_debug_bytes(&bytes).unwrap() >= name.len() as u64);
    let error = paid_error::<assets::Projection>(&bytes);
    assert!(error.to_string().contains(&name));
}

#[test]
fn lexical_unicode_and_debug_output_bytes_are_counted_without_allocating() {
    let bytes = br#"{"\u0000\ud83e\udd80":"\u007f"}"#;
    let (count, allocations) = TestAllocationObserver::count(|| input_debug_bytes(bytes).unwrap());

    assert_eq!(allocations.allocations, 0);
    assert_eq!(allocations.reallocations, 0);
    assert!(!allocations.overflow);
    assert!(
        count
            >= "\0🦀\u{7f}"
                .chars()
                .flat_map(char::escape_debug)
                .map(|c| c.len_utf8() as u64)
                .sum()
    );
    compare_error::<policy::Projection<'_>>(bytes);
}

#[test]
fn diagnostic_refusal_precedes_the_actual_serde_error_allocation() {
    let budget = DecodeBudget::new(authority(1024), 1024).unwrap();
    let (result, identities) = TestAllocationObserver::capture_controls([40; 3], || {
        from_json_slice_closed::<policy::Projection<'_>>(b"{", &budget)
    });

    assert!(matches!(result, Err(ClosedJsonError::Admission(_))));
    assert!(identities.iter().all(Option::is_none));
    assert!(budget.failure().unwrap().is_some());
}

#[test]
fn an_existing_original_refusal_stays_first_without_new_allocation() {
    let budget = DecodeBudget::new(authority(1 << 20), 1 << 20).unwrap();
    let first = refusal("first original cause");
    budget.record_failure(first.clone());

    let (result, count) = TestAllocationObserver::count(|| {
        from_json_slice_closed::<policy::Projection<'_>>(b"{", &budget)
    });

    let Err(ClosedJsonError::Admission(actual)) = result else {
        panic!("the first original was replaced");
    };
    assert_eq!(actual, first);
    assert_eq!(count.allocations, 0);
    assert_eq!(count.reallocations, 0);
}

struct Sink {
    bytes: [u8; 16 * 1024],
    used: usize,
}

impl Write for Sink {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.used.checked_add(value.len()).ok_or(fmt::Error)?;
        let target = self.bytes.get_mut(self.used..end).ok_or(fmt::Error)?;
        target.copy_from_slice(value.as_bytes());
        self.used = end;
        Ok(())
    }
}

#[test]
fn concurrent_and_reentrant_formatting_has_no_raw_error_or_allocating_debug() {
    let ClosedJsonError::Json(error) =
        paid_error::<policy::Projection<'_>>(br#"{"unknown":"value"}"#)
    else {
        panic!("expected JSON diagnostic");
    };
    assert!(Error::source(&error).is_none());

    std::thread::scope(|scope| {
        for _ in 0..2 {
            let error = &error;
            scope.spawn(move || {
                let ((), count) = TestAllocationObserver::count(|| {
                    let mut sink = Sink {
                        bytes: [0; 16 * 1024],
                        used: 0,
                    };
                    write!(&mut sink, "{error} / {error:?}").unwrap();
                    assert!(sink.used > 0);
                });
                assert_eq!(count.allocations, 0);
                assert_eq!(count.reallocations, 0);
            });
        }
    });

    struct Reentrant<'a>(&'a PaidJsonError);
    impl fmt::Display for Reentrant<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{} / {:?}", self.0, self.0)
        }
    }
    let ((), count) = TestAllocationObserver::count(|| {
        let mut sink = Sink {
            bytes: [0; 16 * 1024],
            used: 0,
        };
        write!(&mut sink, "{}", Reentrant(&error)).unwrap();
    });
    assert_eq!(count.allocations, 0);
    assert_eq!(count.reallocations, 0);
}

#[test]
fn parser_scratch_refusal_frees_unused_diagnostic_without_a_serde_error() {
    let original = authority(1 << 20);
    let probe = DecodeBudget::new(original.clone(), 1 << 20).unwrap();
    let initial = original.used.load(Ordering::SeqCst);
    drop(probe);
    assert_eq!(original.used.load(Ordering::SeqCst), 0);
    let diagnostic =
        crate::owned_decode::json_diagnostic::reservation_extent::<policy::Projection<'_>>(b"{")
            .unwrap();
    let budget = DecodeBudget::new(original.clone(), initial + diagnostic).unwrap();

    let (result, identities) = TestAllocationObserver::capture_controls([40; 3], || {
        from_json_slice_closed::<policy::Projection<'_>>(b"{", &budget)
    });

    assert!(matches!(result, Err(ClosedJsonError::Admission(_))));
    assert!(identities.iter().all(Option::is_none));
    assert!(budget.failure().unwrap().is_some());
    assert_eq!(original.used.load(Ordering::SeqCst), initial);
}

#[test]
fn typed_seed_refusal_preserves_the_original_over_its_serde_relay() {
    let original = authority(1 << 20);
    let probe = DecodeBudget::new(original.clone(), 1 << 20).unwrap();
    let initial = original.used.load(Ordering::SeqCst);
    drop(probe);
    let bytes = b"{";
    let diagnostic =
        crate::owned_decode::json_diagnostic::reservation_extent::<policy::Projection<'_>>(bytes)
            .unwrap();
    let parser = 3 * (bytes.len() as u64 + 16);
    let budget = DecodeBudget::new(original, initial + diagnostic + parser).unwrap();

    let error = match from_json_slice_closed::<policy::Projection<'_>>(bytes, &budget) {
        Ok(_) => panic!("unadmitted typed seed reached the parser"),
        Err(error) => error,
    };

    let ClosedJsonError::Admission(actual) = error else {
        panic!("the temporary Serde marker replaced its original cause");
    };
    assert_eq!(Some(actual), budget.failure().unwrap());
}

#[test]
fn canonical_hash_parse_has_no_roundtrip_allocation_and_rejects_each_nonhex_byte() {
    let text = "0123456789abcdef".repeat(4);
    let (hash, counts) =
        TestAllocationObserver::count(|| crucible_campaign::CampaignHash::parse(&text));
    assert_eq!(hash.unwrap().to_hex(), text);
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    for index in 0..64 {
        for byte in [b'A', b'F', b'G', b'/', b' ', 0x80, 0xff] {
            let mut invalid = text.as_bytes().to_vec();
            invalid[index] = byte;
            // Invalid UTF-8 cannot enter the str API. The same byte is refused
            // by the JSON slice parser before an identity visitor sees it.
            if let Ok(invalid) = std::str::from_utf8(&invalid) {
                assert!(matches!(
                    crucible_campaign::CampaignHash::parse(invalid),
                    Err(crucible_campaign::CampaignCodecError::InvalidHex)
                ));
            }
        }
    }
    for invalid in ["", "0", &text[..63]] {
        assert!(crucible_campaign::CampaignHash::parse(invalid).is_err());
    }
    assert!(crucible_campaign::CampaignHash::parse(&(text + "0")).is_err());
}

#[test]
fn an_actual_json_primary_survives_a_later_recorded_original_refusal() {
    let budget = DecodeBudget::new(authority(1 << 20), 1 << 20).unwrap();
    let bytes = br#"{"unknown":0}"#;
    let diagnostic = crate::owned_decode::json_diagnostic::PreparedDiagnostic::prepare::<
        policy::Projection<'_>,
    >(&budget, bytes)
    .unwrap();
    let source: Result<policy::Projection<'_>, _> = serde_json::from_slice(bytes);
    let expected = source.as_ref().err().unwrap().to_string();
    let later = refusal("later original refusal");
    budget.record_failure(later.clone());

    let result = crate::owned_decode::serde_budget::finish_closed_json(&budget, diagnostic, source);

    let Err(ClosedJsonError::Json(actual)) = result else {
        panic!("a later original displaced the actual JSON primary");
    };
    assert_eq!(actual.to_string(), expected);
    assert_eq!(budget.failure().unwrap(), Some(later));
}
