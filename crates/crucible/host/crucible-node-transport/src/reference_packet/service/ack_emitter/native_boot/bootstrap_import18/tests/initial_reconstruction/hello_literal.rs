//! Exercises independently admitted public literal reads on an inherited socket.

use super::super::super::hello_literal::OriginalImport18HelloLiteralAdmission;
use super::*;
use std::cell::Cell;

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    before: usize,
    row: Cell<Option<[usize; 3]>>,
}

impl OriginalImport18HelloLiteralAdmission for Admission<'_> {
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert_eq!(original.hello_literal_row, Some(row));
        assert!(row.into_iter().all(|axis| axis > 0));
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        assert!(original.hello_literal.is_none());
        self.row.set(Some(row));
        if self.case == "initial_hello_literal_construct_refused" {
            return Err(ProviderError::Conflict("original literal admission"));
        }
        if self.case == "initial_hello_literal_construct_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }

    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        actual: usize,
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(2), 1);
        assert_eq!(original.hello_literal_backing_data().unwrap(), actual);
        assert!(actual <= self.row.get().unwrap()[0]);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + actual
        );
        if self.case == "initial_hello_literal_finish_refused" {
            return Err(ProviderError::Conflict("original literal terminal"));
        }
        if self.case == "initial_hello_literal_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn construct_for_value(owner: &mut OriginalImport18RawBootstrap) {
    super::hello_exchange::construct_for_literal(owner);
    let admission = Admission {
        case: "initial_hello_literal_complete",
        calls: Cell::new(0),
        before: owner.retained_requested_bytes().unwrap(),
        row: Cell::new(None),
    };
    owner.receive_hello_literal_data(&admission).unwrap();
    assert!(owner.hello_literal_complete);
    assert_eq!(admission.calls.get(), 2);
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    if case != "initial_hello_literal_unchecked_exchange" {
        super::hello_exchange::construct_for_literal(owner);
    }
    let before = owner.retained_requested_bytes().unwrap();
    let pointers = owner.bodies.each_ref().map(|body| body.as_ptr());
    let admission = Admission {
        case,
        calls: Cell::new(0),
        before,
        row: Cell::new(None),
    };
    if case == "initial_hello_literal_before_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    let outcome = owner.receive_hello_literal_data(&admission);
    let complete = matches!(
        case,
        "initial_hello_literal_complete"
            | "initial_hello_literal_reactive"
            | "initial_hello_literal_callback_refused"
            | "initial_hello_literal_loan_expired"
    );
    assert_eq!(outcome.is_ok(), complete, "{case}: {outcome:?}");
    assert!(owner.hello_literal_started);
    assert_eq!(owner.hello_literal_complete, complete);
    assert_eq!(
        admission.calls.get(),
        match case {
            "initial_hello_literal_unchecked_exchange" | "initial_hello_literal_before_expired" =>
                0,
            "initial_hello_literal_construct_refused" => 1,
            _ => 2,
        }
    );
    let retained = owner.retained_requested_bytes().unwrap();
    if complete {
        let mut pointer = None;
        let outcome = owner.with_hello_literal_data(|body| {
            assert_eq!(body, b"{unparsed public Hello DATA");
            pointer = Some(body.as_ptr());
            if case == "initial_hello_literal_callback_refused" {
                return Err(ProviderError::Conflict("original literal callback"));
            }
            if case == "initial_hello_literal_loan_expired" {
                std::thread::sleep(Duration::from_secs(5));
            }
            Ok(body.len())
        });
        assert!(pointer.is_some());
        assert_eq!(
            outcome.is_ok(),
            matches!(
                case,
                "initial_hello_literal_complete" | "initial_hello_literal_reactive"
            )
        );
        if outcome.is_ok() {
            owner
                .with_hello_literal_data(|body| {
                    assert_eq!(Some(body.as_ptr()), pointer);
                    Ok(())
                })
                .unwrap();
        }
    } else {
        assert!(owner.with_hello_literal_data(|_| Ok(())).is_err());
    }
    let actual = owner.hello_literal_backing_data().unwrap();
    assert_eq!(
        actual,
        match case {
            "initial_hello_literal_unchecked_exchange"
            | "initial_hello_literal_before_expired"
            | "initial_hello_literal_construct_refused"
            | "initial_hello_literal_construct_expired"
            | "initial_hello_literal_zero"
            | "initial_hello_literal_oversized"
            | "initial_hello_literal_partial_header" => 0,
            "initial_hello_literal_partial_body" | "initial_hello_literal_timeout" => 64,
            _ => b"{unparsed public Hello DATA".len(),
        }
    );
    if actual > 0 {
        let literal_pointer = owner.hello_literal.as_ref().unwrap() as *const _;
        assert!(owner.receive_hello_literal_data(&admission).is_err());
        assert_eq!(
            owner.hello_literal.as_ref().unwrap() as *const _,
            literal_pointer
        );
    } else {
        assert!(owner.receive_hello_literal_data(&admission).is_err());
    }
    if matches!(
        case,
        "initial_hello_literal_unchecked_exchange"
            | "initial_hello_literal_before_expired"
            | "initial_hello_literal_construct_refused"
            | "initial_hello_literal_construct_expired"
    ) {
        let mut queued = [0; 4];
        let (_, count) = rustix::net::recv(
            rustix::stdio::stderr(),
            &mut queued[..],
            rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
        )
        .unwrap();
        assert_eq!(count, 4);
        assert_eq!(
            queued,
            (b"{unparsed public Hello DATA".len() as u32).to_be_bytes()
        );
    }
    if complete
        || matches!(
            case,
            "initial_hello_literal_finish_refused" | "initial_hello_literal_finish_expired"
        )
    {
        let mut queued = [0; 14];
        let (_, count) = rustix::net::recv(
            rustix::stdio::stderr(),
            &mut queued[..],
            rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
        )
        .unwrap();
        assert_eq!(&queued[..count], b"literal suffix");
    }
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(owner.bodies.each_ref().map(|body| body.as_ptr()), pointers);
    assert!(owner.inputs.is_empty_data());
}

#[test]
fn original_public_hello_literal_read_retains_partial_banks_and_once_custody() {
    assert!(
        OriginalImport18RawBootstrap::hello_literal_loan_counter_scratch_data::<usize>()
            > size_of::<usize>()
    );
    for case in [
        "initial_hello_literal_complete",
        "initial_hello_literal_reactive",
        "initial_hello_literal_unchecked_exchange",
        "initial_hello_literal_before_expired",
        "initial_hello_literal_construct_refused",
        "initial_hello_literal_construct_expired",
        "initial_hello_literal_finish_refused",
        "initial_hello_literal_finish_expired",
        "initial_hello_literal_callback_refused",
        "initial_hello_literal_loan_expired",
        "initial_hello_literal_zero",
        "initial_hello_literal_oversized",
        "initial_hello_literal_partial_header",
        "initial_hello_literal_partial_body",
        "initial_hello_literal_timeout",
    ] {
        flight(case);
    }
}
