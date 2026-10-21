//! Retains the physical import18 channel and its three unchanged raw bodies.
//!
//! ```text
//! inherited socket -> prefix256 -> recipe bytes -> selected9 bytes -> boot18 bytes -> EOF
//! ```
//!
//! This receiver owns partial bytes and one nonrenewing operational cut. Its
//! independently calculated raw-storage floor precedes body allocation. Its
//! typed DATA transition independently checks complete raw/parser storage before
//! decoding. Separate Source checks and exact initial DATA reconstruction share
//! that same custody and cut. It creates no Initial, Recipe, model or readiness grant;
//! those require their separate complete constructors and original custody.

use crate::ProviderError;
use crate::operational_time::OperationalDeadline;
use crate::reference_packet::service::complete_restore::import18::hello::{
    PacketNativeImport18HelloDeclarationData, PacketNativeImport18HelloSelectionData,
};
use crate::reference_packet::service::complete_restore::import18::{
    InitialConstructionData, NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES, OriginalImport18DecodedBodies,
    PacketNativeImport18PrivatePrefixData, decode_native_import18_private_prefix_data,
    initial_construction_counter_scratch_data,
    native_import18_private_prefix_construction_transient_data,
    native_import18_private_prefix_counter_scratch_data, private_body_decode_counter_scratch_data,
    private_body_owner_counter_scratch_data,
};
use std::{mem::size_of, os::unix::net::UnixStream, thread::ThreadId, time::Duration};

#[path = "bootstrap_import18/receiving_banks.rs"]
mod receiving_banks;

#[path = "bootstrap_import18/decoding.rs"]
mod decoding;

#[path = "bootstrap_import18/source_authentication.rs"]
mod source_authentication;

#[path = "bootstrap_import18/initial_reconstruction.rs"]
mod initial_reconstruction;

#[path = "bootstrap_import18/completed_inputs.rs"]
mod completed_inputs;

#[path = "bootstrap_import18/native_framing.rs"]
mod native_framing;

#[path = "bootstrap_import18/normalization.rs"]
mod normalization;

#[path = "bootstrap_import18/selection.rs"]
mod selection;
pub(in crate::reference_packet::service) use selection::{
    construction_data as selection_construction_data,
    counter_scratch_data as selection_counter_scratch_data,
};

#[path = "bootstrap_import18/hello_request.rs"]
mod hello_request;
pub(in crate::reference_packet::service) use hello_request::{
    construction_bound_data as hello_request_construction_bound_data,
    counter_scratch_data as hello_request_counter_scratch_data,
};

#[path = "bootstrap_import18/hello_registrar.rs"]
mod hello_registrar;

#[path = "bootstrap_import18/hello_value.rs"]
mod hello_value;
pub(in crate::reference_packet::service) use hello_value::{
    construction_bound_data as hello_value_construction_bound_data,
    counter_scratch_data as hello_value_counter_scratch_data,
};

#[path = "bootstrap_import18/hello_literal.rs"]
mod hello_literal;
pub(in crate::reference_packet::service) use hello_literal::{
    construction_data as hello_literal_construction_data,
    counter_scratch_data as hello_literal_counter_scratch_data,
};

#[path = "bootstrap_import18/hello_exchange.rs"]
mod hello_exchange;
pub(in crate::reference_packet::service) use hello_exchange::{
    construction_data as hello_exchange_construction_data,
    counter_scratch_data as hello_exchange_counter_scratch_data,
};

#[path = "bootstrap_import18/public_channel.rs"]
mod public_channel;
pub(in crate::reference_packet::service) use public_channel::{
    construction_data as public_channel_construction_data,
    counter_scratch_data as public_channel_counter_scratch_data,
};

#[path = "bootstrap_import18/hello_frames.rs"]
mod hello_frames;
pub(in crate::reference_packet::service) use hello_frames::{
    construction_data as hello_frames_construction_data,
    counter_scratch_data as hello_frames_counter_scratch_data,
};

#[path = "bootstrap_import18/hello_selection.rs"]
mod hello_selection;
pub(in crate::reference_packet::service) use hello_selection::{
    construction_data as hello_selection_construction_data,
    counter_scratch_data as hello_selection_counter_scratch_data,
};

#[path = "bootstrap_import18/controller_measurement.rs"]
mod controller_measurement;

pub(in crate::reference_packet::service) use controller_measurement::construction_data as controller_measurement_construction_data;
use receiving_banks::OriginalImport18ReceivingBanks;

/// Restricts the three raw inputs independently of their announced allocation.
#[derive(Clone, Copy)]
pub(super) struct Import18RawBootstrapBounds {
    pub(super) bodies: [usize; 3],
    pub(super) complete_private_bytes: usize,
    pub(super) requested_peak: usize,
}

/// Retains raw channel custody without converting an announcement into funding.
pub(super) struct OriginalImport18RawBootstrap {
    process: u32,
    thread: ThreadId,
    cut: OperationalDeadline,
    stream: UnixStream,
    bounds: Import18RawBootstrapBounds,
    prefix: [u8; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES],
    prefix_received: usize,
    header: Option<PacketNativeImport18PrivatePrefixData>,
    bodies: [Vec<u8>; 3],
    inputs: OriginalImport18ReceivingBanks,
    parsed: OriginalImport18DecodedBodies,
    selection_construction_row: Option<[usize; 3]>,
    selection_started: bool,
    selection_authenticated: bool,
    hello_declaration: Option<PacketNativeImport18HelloDeclarationData>,
    hello_selection: Option<PacketNativeImport18HelloSelectionData>,
    hello_construction_row: Option<[usize; 3]>,
    hello_started: bool,
    hello_complete: bool,
    hello_frames: Option<crate::native_hello::OriginalNativeHelloReservation>,
    hello_frames_row: Option<[usize; 3]>,
    hello_frames_started: bool,
    hello_frames_complete: bool,
    public_channel: Option<crate::client::OriginalNativePublicBirthChannel>,
    public_channel_row: Option<[usize; 3]>,
    public_channel_started: bool,
    public_channel_complete: bool,
    hello_exchange: Option<
        crate::native_hello::RetainedOriginalNativeHelloExchange<
            crate::client::OriginalNativePublicBirthChannel,
        >,
    >,
    hello_value: hello_value::Attempt,
    hello_request: hello_request::Attempt,
    hello_literal: Option<crate::native_hello::OriginalNativeHelloLiteral>,
    hello_literal_row: Option<[usize; 3]>,
    hello_literal_started: bool,
    hello_literal_complete: bool,
    hello_exchange_row: Option<[usize; 3]>,
    hello_exchange_started: bool,
    hello_exchange_complete: bool,
    decoding_row: Option<[usize; 3]>,
    decode_started: bool,
    decoded: bool,
    source_authentication_row: Option<[usize; 3]>,
    source_authentication_started: bool,
    source_authenticated: bool,
    initial_construction: Option<InitialConstructionData>,
    initial_reconstruction_row: Option<[usize; 3]>,
    initial_reconstruction_started: bool,
    initial_reconstructed: bool,
    received: [usize; 3],
    tail: [u8; 1],
    tail_received: usize,
    closed: bool,
    started: bool,
    complete: bool,
}

impl OriginalImport18RawBootstrap {
    /// Retains the real inherited descriptor before any credential check or read.
    pub(super) fn retain(
        stream: UnixStream,
        bounds: Import18RawBootstrapBounds,
    ) -> Result<Self, ProviderError> {
        let cut = OperationalDeadline::after(Duration::from_secs(5)).ok_or_else(refused)?;
        Ok(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            cut,
            stream,
            bounds,
            prefix: [0; NATIVE_IMPORT18_PRIVATE_PREFIX_BYTES],
            prefix_received: 0,
            header: None,
            bodies: std::array::from_fn(|_| Vec::new()),
            inputs: OriginalImport18ReceivingBanks::empty(),
            parsed: OriginalImport18DecodedBodies::empty(),
            selection_construction_row: None,
            selection_started: false,
            selection_authenticated: false,
            hello_declaration: None,
            hello_selection: None,
            hello_construction_row: None,
            hello_started: false,
            hello_complete: false,
            hello_frames: None,
            hello_frames_row: None,
            hello_frames_started: false,
            hello_frames_complete: false,
            public_channel: None,
            public_channel_row: None,
            public_channel_started: false,
            public_channel_complete: false,
            hello_exchange: None,
            hello_value: hello_value::Attempt::empty_data(),
            hello_request: hello_request::Attempt::empty_data(),
            hello_literal: None,
            hello_literal_row: None,
            hello_literal_started: false,
            hello_literal_complete: false,
            hello_exchange_row: None,
            hello_exchange_started: false,
            hello_exchange_complete: false,
            decoding_row: None,
            decode_started: false,
            decoded: false,
            source_authentication_row: None,
            source_authentication_started: false,
            source_authenticated: false,
            initial_construction: None,
            initial_reconstruction_row: None,
            initial_reconstruction_started: false,
            initial_reconstructed: false,
            received: [0; 3],
            tail: [0; 1],
            tail_received: 0,
            closed: false,
            started: false,
            complete: false,
        })
    }

    /// Spends the read once and retains all partial allocations after refusal.
    pub(super) fn receive(&mut self) -> Result<(), ProviderError> {
        if self.started {
            return Err(refused());
        }
        self.started = true;
        self.authenticate_channel()?;
        receive_into(
            &self.stream,
            self.cut,
            &mut self.prefix,
            &mut self.prefix_received,
        )?;
        self.header = Some(decode_native_import18_private_prefix_data(
            &self.prefix,
            self.bounds.bodies,
            self.bounds.complete_private_bytes,
        )?);

        let header = self.header.as_ref().ok_or_else(refused)?;
        let lengths = header.body_lengths_data()?;
        let actual = raw_storage_floor(lengths)?;
        let announced = header.initial_funding_data()?;
        let allowed = [
            announced.retained_requested_bytes.get(),
            announced.maximum_simultaneous_transient_bytes.get(),
            announced.declared_counter_scratch_bytes.get(),
        ];
        let mut peak = 0usize;
        for (requested, allowance) in actual.into_iter().zip(allowed) {
            peak = peak.checked_add(requested).ok_or_else(exhausted)?;
            if u64::try_from(requested).map_err(|_| exhausted())? > allowance {
                return Err(exhausted());
            }
        }
        if peak > self.bounds.requested_peak {
            return Err(exhausted());
        }
        self.authenticate_channel()?;

        // Reserve directly into the retained owner. Failed or rounded-up
        // allocations stay here; no temporary Vec can hide that population.
        for (bank, length) in self.bodies.iter_mut().zip(lengths) {
            bank.try_reserve_exact(length).map_err(|_| exhausted())?;
            if bank.capacity() != length {
                return Err(exhausted());
            }
            bank.resize(length, 0);
        }
        self.authenticate_channel()?;
        for index in 0..self.bodies.len() {
            receive_into(
                &self.stream,
                self.cut,
                &mut self.bodies[index],
                &mut self.received[index],
            )?;
            self.authenticate_channel()?;
        }
        self.authenticate_bodies()?;
        // The inherited channel carries only this private sequence. Public
        // Hello and subsequent requests use their separately owned CNP socket.
        // Retain an unexpected suffix byte before refusing it; an open writer
        // cannot turn a complete body prefix into a completed occurrence.
        receive_end(
            &self.stream,
            self.cut,
            &mut self.tail,
            &mut self.tail_received,
            &mut self.closed,
        )?;
        self.authenticate_channel()?;
        self.complete = true;
        Ok(())
    }

    /// Lends only fully received, current, raw-hash-matched bodies as DATA.
    pub(super) fn bodies_data(&self) -> Result<[&[u8]; 3], ProviderError> {
        if !self.complete || !self.closed || self.tail_received != 0 {
            return Err(refused());
        }
        self.authenticate_channel()?;
        self.authenticate_bodies()?;
        self.authenticate_channel()?;
        Ok(self.bodies.each_ref().map(Vec::as_slice))
    }

    /// Counts actual capacities even after a partial or failed read.
    pub(super) fn retained_requested_bytes(&self) -> Result<usize, ProviderError> {
        self.authenticate_origin()?;
        let retained = self
            .bodies
            .iter()
            .try_fold(size_of::<Self>(), |sum, bank| {
                sum.checked_add(bank.capacity()).ok_or_else(exhausted)
            })?;
        let input_backing = self.inputs.retained_backing_data()?;
        let typed_backing = self.parsed.retained_backing_data()?;
        let hello_backing = self.hello_selection_backing_data()?;
        let hello_frames_backing = self.hello_frames_backing_data()?;
        let public_channel_backing = self.public_channel_backing_data()?;
        let hello_exchange_backing = self.hello_exchange_backing_data()?;
        let hello_literal_backing = self.hello_literal_backing_data()?;
        let hello_value_backing = self.hello_value.retained_backing_data()?;
        let hello_request_backing = self.hello_request.retained_backing_data()?;
        retained
            .checked_add(hello_request_backing)
            .and_then(|n| n.checked_add(hello_value_backing))
            .and_then(|n| n.checked_add(hello_literal_backing))
            .and_then(|n| n.checked_add(input_backing))
            .and_then(|n| n.checked_add(typed_backing))
            .and_then(|n| n.checked_add(hello_backing))
            .and_then(|n| n.checked_add(hello_frames_backing))
            .and_then(|n| n.checked_add(public_channel_backing))
            .and_then(|n| n.checked_add(hello_exchange_backing))
            .ok_or_else(exhausted)
    }

    fn authenticate_origin(&self) -> Result<(), ProviderError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_channel(&self) -> Result<(), ProviderError> {
        self.authenticate_origin()?;
        if self.cut.is_expired() {
            return Err(refused());
        }
        let peer =
            rustix::net::sockopt::socket_peercred(&self.stream).map_err(std::io::Error::from)?;
        if Some(peer.pid) != rustix::process::getppid() || peer.uid != rustix::process::geteuid() {
            return Err(refused());
        }
        Ok(())
    }

    fn authenticate_bodies(&self) -> Result<(), ProviderError> {
        let header = self.header.as_ref().ok_or_else(refused)?;
        let lengths = header.body_lengths_data()?;
        for (index, length) in lengths.into_iter().enumerate() {
            if self.received[index] != length || self.bodies[index].len() != length {
                return Err(refused());
            }
        }
        let [recipe, launch, boot] = self.bodies.each_ref();
        header.authenticate_body_slices_data(recipe, launch, boot)
    }
}

/// Calculates only this physical raw receiver's actual userspace construction.
///
/// The independent initial construction projection combines this physical row
/// with prospective typed decoders, Source checks and overlapping outputs.
/// A genuine complete recipe and parent custody still precede opaque Initial.
/// No caller-supplied row enters this calculation.
pub(in crate::reference_packet::service) fn raw_storage_floor(
    lengths: [usize; 3],
) -> Result<[usize; 3], ProviderError> {
    let retained = lengths
        .into_iter()
        .try_fold(size_of::<OriginalImport18RawBootstrap>(), |sum, length| {
            sum.checked_add(length).ok_or_else(exhausted)
        })?;
    let transient = native_import18_private_prefix_construction_transient_data()
        + size_of::<Option<PacketNativeImport18PrivatePrefixData>>()
        + size_of::<OriginalImport18RawBootstrap>()
        + size_of::<Result<OriginalImport18RawBootstrap, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + OriginalImport18ReceivingBanks::construction_transient_data()
        + size_of::<OriginalImport18DecodedBodies>()
        + size_of::<hello_value::Attempt>()
        + size_of::<hello_request::Attempt>()
        + crate::client::OriginalNativePublicBirthChannel::retention_construction_transient_data();
    let scratch = native_import18_private_prefix_counter_scratch_data()
        + OriginalImport18ReceivingBanks::counter_scratch_data()
        + private_body_decode_counter_scratch_data()
        + private_body_owner_counter_scratch_data()
        + crate::client::OriginalNativePublicBirthChannel::retention_counter_scratch_data()
        + decoding::counter_scratch_data()
        + source_authentication::counter_scratch_data()
        + initial_construction_counter_scratch_data()
        + initial_reconstruction::counter_scratch_data()
        + size_of::<&OriginalImport18RawBootstrap>()
        + size_of::<&mut OriginalImport18RawBootstrap>()
        + size_of::<&UnixStream>()
        + size_of::<Import18RawBootstrapBounds>()
        + size_of::<OperationalDeadline>()
        + size_of::<rustix::net::UCred>()
        + size_of::<Result<rustix::net::UCred, rustix::io::Errno>>()
        + size_of::<Result<rustix::net::UCred, std::io::Error>>()
        + size_of::<Option<rustix::process::Pid>>()
        + size_of::<rustix::process::Uid>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<[u64; 3]>()
        + size_of::<std::iter::Zip<std::array::IntoIter<usize, 3>, std::array::IntoIter<u64, 3>>>()
        + size_of::<
            std::iter::Zip<std::slice::IterMut<'static, Vec<u8>>, std::array::IntoIter<usize, 3>>,
        >()
        + size_of::<std::iter::Enumerate<std::array::IntoIter<usize, 3>>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<&mut Vec<u8>>()
        + size_of::<&mut [u8]>()
        + size_of::<&mut usize>()
        + size_of::<&mut [u8; 1]>()
        + size_of::<&mut bool>()
        + size_of::<usize>() * 4
        + size_of::<Option<usize>>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Result<(usize, usize), rustix::io::Errno>>()
        + size_of::<Result<(), ProviderError>>() * 3;
    Ok([retained, transient, scratch])
}

fn receive_into(
    stream: &UnixStream,
    cut: OperationalDeadline,
    bytes: &mut [u8],
    received: &mut usize,
) -> Result<(), ProviderError> {
    while *received < bytes.len() {
        if cut.is_expired() {
            return Err(refused());
        }
        match rustix::net::recv(
            stream,
            &mut bytes[*received..],
            rustix::net::RecvFlags::DONTWAIT,
        ) {
            Ok((_, 0)) => return Err(ProviderError::Frame("import18 private body incomplete")),
            Ok((_, count)) => *received += count,
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => std::thread::yield_now(),
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
    }
    Ok(())
}

fn receive_end(
    stream: &UnixStream,
    cut: OperationalDeadline,
    tail: &mut [u8; 1],
    received: &mut usize,
    closed: &mut bool,
) -> Result<(), ProviderError> {
    loop {
        if cut.is_expired() {
            return Err(refused());
        }
        match rustix::net::recv(stream, &mut tail[..], rustix::net::RecvFlags::DONTWAIT) {
            Ok((_, 0)) => {
                *closed = true;
                return Ok(());
            }
            Ok((_, count)) => {
                *received = count;
                return Err(ProviderError::Frame("import18 private suffix"));
            }
            Err(error) if error == rustix::io::Errno::INTR => {}
            Err(error) if error == rustix::io::Errno::AGAIN => std::thread::yield_now(),
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original import18 raw bootstrap unavailable")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 raw bootstrap storage")
}

#[cfg(test)]
#[path = "bootstrap_import18/tests.rs"]
mod tests;
