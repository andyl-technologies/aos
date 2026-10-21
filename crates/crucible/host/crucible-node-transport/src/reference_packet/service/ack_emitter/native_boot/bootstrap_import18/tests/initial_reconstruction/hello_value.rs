//! Exercises strict parsing under the actual retained public literal and cut.

use super::super::super::hello_value::OriginalImport18HelloValueAdmission;
use super::*;
use std::cell::Cell;

pub(super) fn body_data(case: &str) -> Vec<u8> {
    match case {
        "initial_hello_value_duplicate" => br#"{"k":0,"k":1}"#.to_vec(),
        "initial_hello_value_unicode" => br#""\uD800""#.to_vec(),
        "initial_hello_value_nonfinite" => b"1e999".to_vec(),
        "initial_hello_value_malformed" => b"[".to_vec(),
        "initial_hello_value_depth64" | "initial_hello_value_depth65" => {
            let depth = if case.ends_with("64") { 64 } else { 65 };
            let mut bytes = vec![b'['; depth];
            bytes.push(b'0');
            bytes.extend(std::iter::repeat_n(b']', depth));
            bytes
        }
        "initial_hello_value_raw_value_key" => {
            br#"{"$serde_json::private::RawValue":"[[[ordinary string]]]"}"#.to_vec()
        }
        _ => br#"{"hello":"ordinary DATA"}"#.to_vec(),
    }
}

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    before: usize,
    row: Cell<Option<[usize; 3]>>,
}

impl OriginalImport18HelloValueAdmission for Admission<'_> {
    fn quote_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        scratch: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert!(scratch > 0);
        assert!(original.hello_value.row_fixture_data().is_none());
        assert_eq!(original.hello_value.retained_backing_data().unwrap(), 0);
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        if self.case == "initial_hello_value_quote_refused" {
            return Err(ProviderError::Conflict("actual Hello quote admission"));
        }
        if self.case == "initial_hello_value_quote_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }

    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(2), 1);
        assert_eq!(original.hello_value.row_fixture_data(), Some(row));
        assert!(row.into_iter().all(|axis| axis > 0));
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        assert!(original.hello_value.value_fixture_data().is_none());
        self.row.set(Some(row));
        if self.case == "initial_hello_value_construct_refused" {
            return Err(ProviderError::Conflict("actual Hello Value admission"));
        }
        if self.case == "initial_hello_value_construct_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }

    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(3), 2);
        assert_eq!(
            original.hello_value.retained_backing_data().unwrap(),
            actual
        );
        assert!(actual <= self.row.get().unwrap()[0]);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + actual
        );
        if self.case == "initial_hello_value_finish_refused" {
            return Err(ProviderError::Conflict("actual Hello Value terminal"));
        }
        if self.case == "initial_hello_value_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    if case != "initial_hello_value_unchecked_literal" {
        super::hello_literal::construct_for_value(owner);
    }
    let before = owner.retained_requested_bytes().unwrap();
    let pointers = owner.bodies.each_ref().map(|body| body.as_ptr());
    let admission = Admission {
        case,
        calls: Cell::new(0),
        before,
        row: Cell::new(None),
    };
    if case == "initial_hello_value_before_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    let outcome = owner.decode_hello_value_data(&admission);
    let complete = matches!(
        case,
        "initial_hello_value_complete"
            | "initial_hello_value_reactive"
            | "initial_hello_value_depth64"
            | "initial_hello_value_raw_value_key"
            | "initial_hello_value_callback_refused"
            | "initial_hello_value_loan_expired"
    );
    assert_eq!(outcome.is_ok(), complete, "{case}: {outcome:?}");
    assert_eq!(
        admission.calls.get(),
        match case {
            "initial_hello_value_before_expired" | "initial_hello_value_unchecked_literal" => 0,
            "initial_hello_value_quote_refused" | "initial_hello_value_quote_expired" => 1,
            "initial_hello_value_construct_refused" => 2,
            _ => 3,
        }
    );
    let retained = owner.retained_requested_bytes().unwrap();
    if complete {
        let actual = owner.hello_value.value_fixture_data().unwrap() as *const Value;
        let result = owner.with_hello_value_data(|value| {
            assert!(std::ptr::eq(actual, value));
            if case == "initial_hello_value_depth64" {
                let mut leaf = value;
                for _ in 0..64 {
                    leaf = &leaf.as_array().unwrap()[0];
                }
                assert_eq!(leaf, &json!(0));
            } else if case == "initial_hello_value_raw_value_key" {
                assert_eq!(
                    value["$serde_json::private::RawValue"],
                    "[[[ordinary string]]]"
                );
            } else {
                assert_eq!(value["hello"], "ordinary DATA");
            }
            if case == "initial_hello_value_callback_refused" {
                return Err(ProviderError::Conflict("actual Hello Value callback"));
            }
            if case == "initial_hello_value_loan_expired" {
                std::thread::sleep(Duration::from_secs(5));
            }
            Ok(())
        });
        assert_eq!(
            result.is_ok(),
            !matches!(
                case,
                "initial_hello_value_callback_refused" | "initial_hello_value_loan_expired"
            )
        );
        assert!(std::ptr::eq(
            owner.hello_value.value_fixture_data().unwrap(),
            actual
        ));
    } else {
        assert!(owner.with_hello_value_data(|_| Ok(())).is_err());
        assert_eq!(
            owner.hello_value.value_fixture_data().is_some(),
            matches!(
                case,
                "initial_hello_value_finish_refused" | "initial_hello_value_finish_expired"
            )
        );
    }
    assert!(owner.decode_hello_value_data(&admission).is_err());
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(owner.bodies.each_ref().map(|body| body.as_ptr()), pointers);
    assert!(owner.inputs.is_empty_data());
    let mut queued = [0; 14];
    let (_, count) = rustix::net::recv(
        rustix::stdio::stderr(),
        &mut queued[..],
        rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
    )
    .unwrap();
    if case == "initial_hello_value_unchecked_literal" {
        assert_eq!(&queued[..4], (body_data(case).len() as u32).to_be_bytes());
    } else {
        assert_eq!(&queued[..count], b"literal suffix");
    }
}

#[test]
fn original_strict_hello_value_preserves_parser_failures_and_terminal_custody() {
    assert!(
        OriginalImport18RawBootstrap::hello_value_loan_counter_scratch_data::<usize>()
            > size_of::<usize>()
    );
    for case in [
        "initial_hello_value_complete",
        "initial_hello_value_reactive",
        "initial_hello_value_depth64",
        "initial_hello_value_raw_value_key",
        "initial_hello_value_unchecked_literal",
        "initial_hello_value_before_expired",
        "initial_hello_value_quote_refused",
        "initial_hello_value_quote_expired",
        "initial_hello_value_construct_refused",
        "initial_hello_value_construct_expired",
        "initial_hello_value_finish_refused",
        "initial_hello_value_finish_expired",
        "initial_hello_value_callback_refused",
        "initial_hello_value_loan_expired",
        "initial_hello_value_duplicate",
        "initial_hello_value_unicode",
        "initial_hello_value_nonfinite",
        "initial_hello_value_malformed",
        "initial_hello_value_depth65",
    ] {
        flight(case);
    }
}
