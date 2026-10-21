//! Exercises original descriptor custody and immutable physical cut binding.

use super::super::super::public_channel::OriginalImport18PublicChannelAdmission;
use super::*;
use std::{cell::Cell, os::fd::AsRawFd};

pub(in super::super) fn retain_before_read(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    if matches!(
        case,
        "initial_hello_channel_missing" | "initial_hello_channel_late_descriptor"
    ) {
        return;
    }
    let mut incoming = Some(if case == "initial_hello_channel_wrong_peer" {
        UnixStream::pair().unwrap().0
    } else {
        UnixStream::from(rustix::io::dup(rustix::stdio::stderr()).unwrap())
    });
    let descriptor = incoming.as_ref().unwrap().as_raw_fd();
    let before = owner.retained_requested_bytes().unwrap();
    owner.retain_public_channel_data(&mut incoming).unwrap();
    assert!(incoming.is_none());
    let public = owner.public_channel.as_ref().unwrap();
    assert_eq!(public.descriptor_data().unwrap(), descriptor);
    assert_eq!(public.retained_backing_data().unwrap(), 0);
    assert_eq!(owner.retained_requested_bytes().unwrap(), before);
    if case == "initial_hello_channel_occupied" {
        let mut other = Some(UnixStream::pair().unwrap().0);
        let other_descriptor = other.as_ref().unwrap().as_raw_fd();
        assert!(owner.retain_public_channel_data(&mut other).is_err());
        assert_eq!(other.as_ref().unwrap().as_raw_fd(), other_descriptor);
        assert_eq!(
            owner
                .public_channel
                .as_ref()
                .unwrap()
                .descriptor_data()
                .unwrap(),
            descriptor
        );
    }
}

struct Admission<'a> {
    case: &'a str,
    calls: Cell<usize>,
    before: usize,
    row: Cell<Option<[usize; 3]>>,
}

impl OriginalImport18PublicChannelAdmission for Admission<'_> {
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError> {
        assert_eq!(self.calls.replace(1), 0);
        assert_eq!(original.public_channel_row, Some(row));
        assert!(row.into_iter().all(|axis| axis > 0));
        assert_eq!(original.retained_requested_bytes().unwrap(), self.before);
        self.row.set(Some(row));
        if self.case == "initial_hello_channel_construct_refused" {
            return Err(ProviderError::ResourceExhausted(
                "original public channel admission",
            ));
        }
        if self.case == "initial_hello_channel_construct_expired" {
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
        assert_eq!(original.public_channel_backing_data().unwrap(), actual);
        assert!(actual <= self.row.get().unwrap()[0]);
        assert_eq!(
            original.retained_requested_bytes().unwrap(),
            self.before + actual
        );
        if self.case == "initial_hello_channel_finish_refused" {
            return Err(ProviderError::Conflict("original public channel terminal"));
        }
        if self.case == "initial_hello_channel_finish_expired" {
            std::thread::sleep(Duration::from_secs(5));
        }
        Ok(())
    }
}

pub(super) fn construct_for_exchange(owner: &mut OriginalImport18RawBootstrap) {
    super::hello_frames::construct_for_channel(owner);
    let admission = Admission {
        case: "initial_hello_channel_complete",
        calls: Cell::new(0),
        before: owner.retained_requested_bytes().unwrap(),
        row: Cell::new(None),
    };
    owner.construct_public_channel_data(&admission).unwrap();
    assert!(owner.public_channel_complete);
    assert_eq!(admission.calls.get(), 2);
}

pub(super) fn assert_child(case: &str, owner: &mut OriginalImport18RawBootstrap) {
    if case != "initial_hello_channel_unchecked_frames" {
        super::hello_frames::construct_for_channel(owner);
    }
    if case == "initial_hello_channel_before_expired" {
        owner.cut = OperationalDeadline::expired_fixture();
    }
    if case == "initial_hello_channel_late_descriptor" {
        let mut incoming = Some(UnixStream::from(
            rustix::io::dup(rustix::stdio::stderr()).unwrap(),
        ));
        let descriptor = incoming.as_ref().unwrap().as_raw_fd();
        assert!(owner.retain_public_channel_data(&mut incoming).is_err());
        assert_eq!(incoming.as_ref().unwrap().as_raw_fd(), descriptor);
        assert!(owner.public_channel.is_none());
    }
    let descriptor = owner
        .public_channel
        .as_ref()
        .map(|public| public.descriptor_data().unwrap());
    let pointers = owner.bodies.each_ref().map(|body| body.as_ptr());
    let admission = Admission {
        case,
        calls: Cell::new(0),
        before: owner.retained_requested_bytes().unwrap(),
        row: Cell::new(None),
    };
    let outcome = owner.construct_public_channel_data(&admission);
    let complete = matches!(
        case,
        "initial_hello_channel_complete"
            | "initial_hello_channel_reactive"
            | "initial_hello_channel_occupied"
            | "initial_hello_channel_loan_expired"
    );
    assert_eq!(outcome.is_ok(), complete, "{case}: {outcome:?}");
    assert_eq!(owner.public_channel_complete, complete);
    assert!(owner.public_channel_started);
    assert_eq!(
        admission.calls.get(),
        match case {
            "initial_hello_channel_unchecked_frames"
            | "initial_hello_channel_missing"
            | "initial_hello_channel_late_descriptor"
            | "initial_hello_channel_before_expired" => 0,
            "initial_hello_channel_construct_refused" => 1,
            _ => 2,
        }
    );
    assert_eq!(
        owner
            .public_channel
            .as_ref()
            .map(|public| public.descriptor_data().unwrap()),
        descriptor
    );
    let retained = owner.retained_requested_bytes().unwrap();
    if complete {
        owner.authenticate_public_channel_data().unwrap();
        if case == "initial_hello_channel_loan_expired" {
            std::thread::sleep(Duration::from_secs(5));
            assert!(owner.authenticate_public_channel_data().is_err());
        }
    } else {
        assert!(owner.authenticate_public_channel_data().is_err());
    }
    if matches!(
        case,
        "initial_hello_channel_finish_refused" | "initial_hello_channel_finish_expired"
    ) || complete
    {
        assert_eq!(
            owner.public_channel_backing_data().unwrap(),
            admission.row.get().unwrap()[0]
        );
    } else {
        assert_eq!(owner.public_channel_backing_data().unwrap(), 0);
    }
    if !matches!(
        case,
        "initial_hello_channel_wrong_peer"
            | "initial_hello_channel_missing"
            | "initial_hello_channel_late_descriptor"
    ) {
        let mut bytes = [0; 64];
        let (_, count) = rustix::net::recv(
            rustix::stdio::stderr(),
            &mut bytes[..],
            rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
        )
        .unwrap();
        assert_eq!(&bytes[..count], b"unconsumed public Hello DATA");
    }
    assert!(owner.construct_public_channel_data(&admission).is_err());
    assert_eq!(owner.retained_requested_bytes().unwrap(), retained);
    assert_eq!(owner.bodies.each_ref().map(|body| body.as_ptr()), pointers);
    assert!(owner.inputs.is_empty_data());
}

#[test]
fn actual_public_channel_retains_descriptor_cut_and_allocations_after_every_outcome() {
    for case in [
        "initial_hello_channel_complete",
        "initial_hello_channel_reactive",
        "initial_hello_channel_occupied",
        "initial_hello_channel_unchecked_frames",
        "initial_hello_channel_missing",
        "initial_hello_channel_late_descriptor",
        "initial_hello_channel_before_expired",
        "initial_hello_channel_construct_refused",
        "initial_hello_channel_construct_expired",
        "initial_hello_channel_finish_refused",
        "initial_hello_channel_finish_expired",
        "initial_hello_channel_wrong_peer",
        "initial_hello_channel_loan_expired",
    ] {
        flight(case);
    }
}
