//! Exercises original public channel/journal transfer under the same raw custody.

use super::super::super::hello_exchange::OriginalImport18HelloExchangeAdmission;
use super::*;
use std::cell::Cell;

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    before: usize,
    moved: usize,
    row: Cell<Option<[usize; 3]>>,
}

impl OriginalImport18HelloExchangeAdmission for Admission<'_> {
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert_eq!(original.hello_exchange_row, Some(row));
        assert!(row.into_iter().all(|axis| axis > 0));
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        self.row.set(Some(row));
        if self.case == "initial_hello_exchange_construct_refused" {
            return Err(ProviderError::Conflict("actual original framing admission"));
        }
        if self.case == "initial_hello_exchange_construct_expired" {
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
        assert_eq!(original.hello_exchange_backing_data().unwrap(), actual);
        let moved = if original.public_channel.is_none() {
            self.moved
        } else {
            0
        };
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before - moved + actual
        );
        assert!(actual <= self.moved + self.row.get().unwrap()[0]);
        if self.case == "initial_hello_exchange_finish_refused" {
            return Err(ProviderError::Conflict("actual original framing terminal"));
        }
        if self.case == "initial_hello_exchange_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    if case != "initial_hello_exchange_unchecked_channel" {
        super::public_channel::construct_for_exchange(owner);
    }
    let descriptor = owner
        .public_channel
        .as_ref()
        .unwrap()
        .descriptor_data()
        .unwrap();
    let before = owner.retained_requested_bytes().unwrap();
    let pointers = owner.bodies.each_ref().map(|body| body.as_ptr());
    let admission = Admission {
        case,
        calls: Cell::new(0),
        before,
        moved: owner.public_channel_backing_data().unwrap(),
        row: Cell::new(None),
    };
    if case == "initial_hello_exchange_before_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    let outcome = owner.construct_hello_exchange_data(&admission);
    let complete = matches!(
        case,
        "initial_hello_exchange_complete"
            | "initial_hello_exchange_reactive"
            | "initial_hello_exchange_callback_refused"
            | "initial_hello_exchange_loan_expired"
    );
    assert_eq!(outcome.is_ok(), complete, "{case}: {outcome:?}");
    assert_eq!(owner.hello_exchange_complete, complete);
    assert!(owner.hello_exchange_started);
    assert_eq!(
        admission.calls.get(),
        match case {
            "initial_hello_exchange_unchecked_channel"
            | "initial_hello_exchange_before_expired" => 0,
            "initial_hello_exchange_construct_refused" => 1,
            _ => 2,
        }
    );
    let retained = owner.retained_requested_bytes().unwrap();
    if complete {
        let mut original = None;
        let result = owner.with_hello_exchange_data(|exchange| {
            original = Some(
                exchange
                    as *const crate::native_hello::OriginalNativeHelloExchange<
                        crate::client::OriginalNativePublicBirthChannel,
                    >,
            );
            assert_eq!(
                exchange.original_stream_data().descriptor_data().unwrap(),
                descriptor
            );
            if case == "initial_hello_exchange_callback_refused" {
                return Err(ProviderError::Conflict("original framing callback"));
            }
            if case == "initial_hello_exchange_loan_expired" {
                std::thread::sleep(Duration::from_secs(5));
            }
            Ok(())
        });
        assert!(original.is_some());
        assert_eq!(
            result.is_ok(),
            matches!(
                case,
                "initial_hello_exchange_complete" | "initial_hello_exchange_reactive"
            )
        );
        if result.is_ok() {
            owner
                .with_hello_exchange_data(|exchange| {
                    assert!(std::ptr::eq(original.unwrap(), exchange));
                    Ok(())
                })
                .unwrap();
        }
    } else {
        assert!(owner.with_hello_exchange_data(|_| Ok(())).is_err());
    }
    if matches!(
        case,
        "initial_hello_exchange_finish_refused" | "initial_hello_exchange_finish_expired"
    ) || complete
    {
        assert!(owner.public_channel.is_none());
        owner
            .hello_exchange
            .as_ref()
            .unwrap()
            .with_exchange_data(|exchange| {
                assert_eq!(
                    exchange.original_stream_data().descriptor_data().unwrap(),
                    descriptor
                );
                Ok(())
            })
            .unwrap();
        assert!(owner.with_hello_frames_data(|_| Ok(())).is_err());
        assert_eq!(
            owner.hello_exchange_backing_data().unwrap(),
            admission.moved
        );
    } else {
        assert!(owner.public_channel.is_some());
        assert_eq!(
            owner
                .public_channel
                .as_ref()
                .unwrap()
                .descriptor_data()
                .unwrap(),
            descriptor
        );
        assert_eq!(owner.hello_exchange_backing_data().unwrap(), 0);
    }
    let mut bytes = [0; 64];
    let (_, count) = rustix::net::recv(
        rustix::stdio::stderr(),
        &mut bytes[..],
        rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
    )
    .unwrap();
    assert_eq!(&bytes[..count], b"unconsumed public Hello DATA");
    assert!(owner.construct_hello_exchange_data(&admission).is_err());
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(owner.bodies.each_ref().map(|body| body.as_ptr()), pointers);
    assert!(owner.inputs.is_empty_data());
}

#[test]
fn original_hello_framing_moves_its_actual_socket_and_journal_without_public_io() {
    assert!(
        OriginalImport18RawBootstrap::hello_exchange_loan_counter_scratch_data::<usize>()
            > size_of::<usize>()
    );
    for case in [
        "initial_hello_exchange_complete",
        "initial_hello_exchange_reactive",
        "initial_hello_exchange_unchecked_channel",
        "initial_hello_exchange_before_expired",
        "initial_hello_exchange_construct_refused",
        "initial_hello_exchange_construct_expired",
        "initial_hello_exchange_finish_refused",
        "initial_hello_exchange_finish_expired",
        "initial_hello_exchange_callback_refused",
        "initial_hello_exchange_loan_expired",
    ] {
        flight(case);
    }
}
