//! Authenticates the separate startup16 inherited channel before owned decoding.
//!
//! Prefix16 authenticates admission, count and two finite rows. Archive model
//! DATA is not present on this channel: its exact eight-field recount is sealed
//! only from the real restoration inputs. Neither phase enables suffix actions.

use crate::reference_packet::service::{
    PacketNative5SourceLaunch, PacketSourceService, native_startup::*,
};
use crate::{
    ProviderError,
    client::OriginalNative5BirthCut,
    transport::{FrameReader, original_frames::OriginalFrameReservation},
};
use crucible_node_format::ContractError;
use std::{
    cell::RefCell, io::Write, mem::size_of, os::fd::AsFd, path::Path, rc::Rc, time::Duration,
};

/// Retains one actual inherited prefix and its nonrenewing initial deadline.
pub(super) struct OriginalRestoredSuffixBootstrap {
    creator: u32,
    thread: std::thread::ThreadId,
    pub(super) preamble: [u8; ORIGINAL_NATIVE_RESTORED_SUFFIX_PREAMBLE_BYTES],
    pub(super) data: PacketNativeSuffixPreambleData,
    pub(super) original_cut: crate::operational_time::OperationalDeadline,
    issued: bool,
    pub(super) failed: bool,
}

struct SuffixBootstrap {
    reader: Option<FrameReader<super::owned_read::OriginalPrivateBootstrapStream<std::io::Stdin>>>,
    literals: Option<Rc<RefCell<OriginalFrameReservation>>>,
    launch_value: Option<serde_json::Value>,
    launch7: Vec<u8>,
    launch6: Vec<u8>,
    launch: Option<PacketNative5SourceLaunch>,
    purpose: Option<PacketNativeInvocationPurposeData>,
    boot_value: Option<serde_json::Value>,
    boot: Option<Rc<RefCell<super::boot::NativeAckBoot>>>,
    startup: OriginalRestoredSuffixBootstrap,
}

impl OriginalRestoredSuffixBootstrap {
    fn read<S: AsFd>(stream: &S) -> Result<Self, ProviderError> {
        let original_cut =
            crate::operational_time::OperationalDeadline::after(Duration::from_secs(5))
                .ok_or_else(refused)?;
        let peer = rustix::net::sockopt::socket_peercred(stream).map_err(std::io::Error::from)?;
        let parent = rustix::process::getppid().ok_or_else(refused)?;
        if peer.pid != parent || peer.uid != rustix::process::geteuid() {
            return Err(refused());
        }
        let mut preamble = [0; ORIGINAL_NATIVE_RESTORED_SUFFIX_PREAMBLE_BYTES];
        let mut received = 0;
        while received < preamble.len() {
            if original_cut.is_expired() {
                return Err(refused());
            }
            match rustix::net::recv(
                stream,
                &mut preamble[received..],
                rustix::net::RecvFlags::DONTWAIT,
            ) {
                Ok((_, 0)) => return Err(ProviderError::Frame("suffix16 prefix incomplete")),
                Ok((_, count)) => received += count,
                Err(error) if error == rustix::io::Errno::INTR => {}
                Err(error) if error == rustix::io::Errno::AGAIN => std::thread::yield_now(),
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
        }
        let data = decode_original_native_suffix_preamble_data(&preamble)?;
        authenticate_original_native_suffix_preamble_data(&preamble, &preamble[328..360])?;
        if data.invocation.controller_pid != u64::from(peer.pid.as_raw_nonzero().get() as u32)
            || data.invocation.controller_uid != u64::from(peer.uid.as_raw())
            || data.invocation.birth_id
                != blake3::derive_key(
                    "source-owned.packet-canonical-ack-birth/5",
                    &preamble[328..360],
                )
        {
            return Err(refused());
        }
        let initial = original_native_private_bootstrap_floor_data()?
            .checked_add(original_restored_suffix_bootstrap_header_data())
            .ok_or_else(exhausted)?;
        if data
            .invocation
            .private_bootstrap
            .retained_requested_bytes
            .get()
            < u64::try_from(initial).map_err(|_| exhausted())?
        {
            return Err(exhausted());
        }
        let scratch = original_native_birth_startup_counter_scratch_data()
            .checked_add(original_native_suffix_counter_scratch_data())
            .ok_or_else(exhausted)?;
        if u64::try_from(scratch).map_err(|_| exhausted())?
            > data
                .invocation
                .private_bootstrap
                .declared_counter_scratch_bytes
                .get()
        {
            return Err(exhausted());
        }
        let incoming = crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data((data.invocation.launch_bytes as usize).max(data.invocation.maximum_boot_bytes as usize))?;
        if u64::try_from(incoming.canonical_pass_requested_bytes()?).map_err(|_| exhausted())?
            > data
                .invocation
                .private_bootstrap
                .maximum_simultaneous_transient_bytes
                .get()
        {
            return Err(exhausted());
        }
        let owner = Self {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            preamble,
            data,
            original_cut,
            issued: false,
            failed: false,
        };
        owner.ensure_current()?;
        Ok(owner)
    }

    pub(super) fn ensure_current(&self) -> Result<(), ProviderError> {
        if self.failed {
            return Err(refused());
        }
        self.ensure_cut()
    }

    fn ensure_cut(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || self.original_cut.is_expired()
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn begin_claim(
        &mut self,
        key: &[u8],
        birth: &[u8],
        raw7: &[u8],
    ) -> Result<(), ProviderError> {
        self.ensure_current()?;
        if std::mem::replace(&mut self.issued, true) {
            return Err(refused());
        }
        self.failed = true;
        authenticate_original_native_suffix_preamble_data(&self.preamble, key)?;
        if birth != self.data.invocation.birth_id
            || raw7.len() != self.data.invocation.launch_bytes as usize
            || blake3::hash(raw7).as_bytes() != &self.data.invocation.launch_digest
        {
            return Err(refused());
        }
        self.ensure_cut()
    }

    pub(super) fn complete_claim(&mut self) -> Result<(), ProviderError> {
        self.ensure_cut()?;
        if !self.issued || !self.failed {
            return Err(refused());
        }
        self.failed = false;
        Ok(())
    }
}

pub(in crate::reference_packet::service) fn accept(
    socket: &Path,
) -> Result<PacketSourceService, ProviderError> {
    let startup = OriginalRestoredSuffixBootstrap::read(&rustix::stdio::stdin())?;
    // The fixed genuine owner exists before any bank/reader/Value can fail.
    let mut owner = SuffixBootstrap {
        reader: None,
        literals: None,
        launch_value: None,
        launch7: Vec::new(),
        launch6: Vec::new(),
        launch: None,
        purpose: None,
        boot_value: None,
        boot: None,
        startup,
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.prepare(socket)));
    match result {
        Ok(Ok(mut service)) => {
            service._private_bootstrap = Some(Box::new(owner));
            Ok(service)
        }
        failure => {
            owner.startup.failed = true;
            loop {
                std::hint::black_box((&owner, &failure));
                std::thread::park();
            }
        }
    }
}

impl SuffixBootstrap {
    fn prepare(&mut self, socket: &Path) -> Result<PacketSourceService, ProviderError> {
        self.startup.ensure_current()?;

        // The literal owner is retained before reader or parser construction.
        let bank = Rc::new(RefCell::new(OriginalFrameReservation::reserve(
            1024 * 1024 + 512 * 1024 + 8,
            2,
        )?));
        self.literals = Some(Rc::clone(&bank));
        let cut = OriginalNative5BirthCut::from_original_preparser_cut(self.startup.original_cut)?;
        let stream = super::owned_read::OriginalPrivateBootstrapStream {
            original: std::io::stdin(),
            cut: Some(cut),
        };
        let maximum = (self.startup.data.invocation.launch_bytes as usize)
            .max(self.startup.data.invocation.maximum_boot_bytes as usize);
        let mut reader = FrameReader::with_limits(stream, maximum, 64)?;
        reader.install_originals(bank);
        self.reader = Some(reader);
        let budget = OriginalNativeFramePreflight::private(
            &self.startup.data.invocation.private_bootstrap,
            0,
        );
        self.launch_value = Some(
            self.reader
                .as_mut()
                .ok_or_else(refused)?
                .read_original_native_preflight(maximum, &budget)?
                .ok_or_else(refused)?
                .value,
        );
        self.startup.ensure_current()?;

        self.launch7 = crucible_node_format::canonical::canonical_json(
            self.launch_value.as_ref().ok_or_else(refused)?,
        )?;
        if self.launch7.len() != self.startup.data.invocation.launch_bytes as usize
            || blake3::hash(&self.launch7).as_bytes() != &self.startup.data.invocation.launch_digest
        {
            return Err(refused());
        }

        // The exact wrapper contributes no replacement identity for launch5.
        let value = self.launch_value.as_ref().ok_or_else(refused)?;
        let fields = value.as_object().ok_or_else(refused)?;
        if fields.len() != 4
            || fields
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                != Some(7)
        {
            return Err(refused());
        }
        let purpose = PacketNativeInvocationPurposeData::from_original_value_data(
            fields.get("invocation").ok_or_else(refused)?,
        )?;
        if purpose.is_original_execution_data() {
            return Err(refused());
        }
        let reservation: PacketRestoredSuffixReservationData =
            serde::Deserialize::deserialize(fields.get("suffix_reservation").ok_or_else(refused)?)
                .map_err(crucible_node_format::ContractError::from)?;
        if reservation != self.startup.data.suffix_reservation {
            return Err(refused());
        }
        self.purpose = Some(purpose);
        self.launch = Some(
            serde::Deserialize::deserialize(fields.get("launch").ok_or_else(refused)?)
                .map_err(crucible_node_format::ContractError::from)?,
        );

        // Existing Source15/Boot7 code keeps its genuine canonical6 identity.
        let nested = nested_launch5(&self.launch7)?;
        let identity6 = original_native_invocation_launch_identity_data(&purpose, nested)?;
        self.launch6
            .try_reserve_exact(identity6.encoded_bytes)
            .map_err(|_| exhausted())?;
        write_original_native_invocation_launch_data(
            &purpose,
            nested,
            &mut Limited {
                bank: &mut self.launch6,
                maximum: identity6.encoded_bytes,
            },
        )?;
        if self.launch6.len() != identity6.encoded_bytes
            || blake3::hash(&self.launch6).as_bytes() != &identity6.raw_digest
        {
            return Err(refused());
        }

        let launch = self.launch.as_ref().ok_or_else(refused)?;
        purpose.authenticate_target_data(launch)?;
        let peer = rustix::net::sockopt::socket_peercred(
            &self
                .reader
                .as_mut()
                .ok_or_else(refused)?
                .stream_mut()
                .original,
        )
        .map_err(std::io::Error::from)?;
        if peer.pid.as_raw_nonzero().get() as u64 != launch.controller_pid.get()
            || u64::from(peer.uid.as_raw()) != launch.controller_uid.get()
        {
            return Err(refused());
        }

        // Typed launch and both raw identities stay live during boot decoding.
        let carry = original_private_launch_backing_data(launch)?
            .checked_add(self.launch7.capacity())
            .and_then(|n| n.checked_add(self.launch6.capacity()))
            .ok_or_else(exhausted)?;
        let budget = OriginalNativeFramePreflight::private(
            &self.startup.data.invocation.private_bootstrap,
            carry,
        );
        self.boot_value = Some(
            self.reader
                .as_mut()
                .ok_or_else(refused)?
                .read_original_native_preflight(
                    self.startup.data.invocation.maximum_boot_bytes as usize,
                    &budget,
                )?
                .ok_or_else(refused)?
                .value,
        );
        self.startup.ensure_current()?;
        super::boot::NativeAckBoot::prepare_original_restored_suffix_into(
            self.boot_value.as_ref().ok_or_else(refused)?,
            launch,
            &self.launch7,
            self.launch6.clone(),
            purpose,
            &mut self.startup,
            &mut self.boot,
        )?;

        launch.validate()?;
        if super::bootstrap::admitted::measure_original_controller_executable(
            launch.controller_pid,
        )? != launch.controller_executable
        {
            return Err(refused());
        }
        self.startup.ensure_current()?;
        let reader = self.reader.as_mut().ok_or_else(refused)?;
        reader
            .stream_mut()
            .cut
            .as_ref()
            .ok_or_else(refused)?
            .ensure_current()?;
        let cut = reader.stream_mut().cut.take().ok_or_else(refused)?;
        let launch = self.launch.take().ok_or_else(refused)?;
        let boot = Rc::clone(self.boot.as_ref().ok_or_else(refused)?);
        super::super::super::server::accept_complete_with_boot(
            socket,
            launch,
            cut,
            boot,
            Rc::clone(self.literals.as_ref().ok_or_else(refused)?),
        )
    }
}

struct Limited<'a> {
    bank: &'a mut Vec<u8>,
    maximum: usize,
}
impl Write for Limited<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .bank
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= self.maximum && *n <= self.bank.capacity())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
        self.bank.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn nested_launch5(raw: &[u8]) -> Result<&[u8], ProviderError> {
    let mut fields = crate::protocol_snapshot::owned11::OriginalOwned11Fields::object(raw)?;
    fields.named("invocation")?;
    let nested = fields.named("launch")?;
    if fields.named("schema_version")? != b"7" {
        return Err(refused());
    }
    fields.named("suffix_reservation")?;
    fields.finish()?;
    Ok(nested)
}

/// Returns the complete fixed private reader/partial-owner root.
pub(crate) const fn original_restored_suffix_bootstrap_header_data() -> usize {
    size_of::<SuffixBootstrap>()
}

/// Names explicit prefix, reader, parser, returned and error views before decoding.
pub(crate) fn original_restored_suffix_bootstrap_counter_scratch_data() -> usize {
    type Reader = FrameReader<super::owned_read::OriginalPrivateBootstrapStream<std::io::Stdin>>;

    let reader_views = size_of::<Option<&mut Reader>>()
        + size_of::<Option<&OriginalNative5BirthCut>>()
        + size_of::<Option<OriginalNative5BirthCut>>()
        + size_of::<Option<&Rc<RefCell<super::boot::NativeAckBoot>>>>()
        + size_of::<Result<crate::transport::RetainedFrame, ProviderError>>()
        + size_of::<Result<rustix::process::Pid, ProviderError>>();
    let typed_views = size_of::<Option<&serde_json::Map<String, serde_json::Value>>>()
        + size_of::<Option<&PacketNative5SourceLaunch>>()
        + size_of::<Option<PacketNative5SourceLaunch>>()
        + size_of::<&mut Vec<u8>>()
        + size_of::<&mut crate::protocol_snapshot::owned11::OriginalOwned11Fields<'static>>();
    let owner_and_decode_views = size_of::<OriginalRestoredSuffixBootstrap>()
        + size_of::<Result<OriginalRestoredSuffixBootstrap, ProviderError>>()
        + size_of::<[u8; 392]>()
        + size_of::<usize>() * 4
        + size_of::<PacketNativeSuffixPreambleData>()
        + size_of::<Result<PacketNativeSuffixPreambleData, ProviderError>>()
        + size_of::<crate::operational_time::OperationalDeadline>()
        + size_of::<Option<crate::operational_time::OperationalDeadline>>()
        + size_of::<&[u8]>() * 2
        + size_of::<Result<&[u8], ProviderError>>()
        + size_of::<PacketNativeInvocationPurposeData>()
        + size_of::<Option<PacketNativeInvocationPurposeData>>()
        + size_of::<PacketRestoredSuffixReservationData>()
        + size_of::<Result<PacketRestoredSuffixReservationData, crucible_node_format::ContractError>>(
        )
        + size_of::<Result<PacketRestoredSuffixReservationData, serde_json::Error>>()
        + size_of::<Result<PacketNative5SourceLaunch, crucible_node_format::ContractError>>();

    let bootstrap_and_peer_views =
        size_of::<Result<PacketNative5SourceLaunch, serde_json::Error>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<u64, std::num::TryFromIntError>>()
            + size_of::<Option<usize>>()
            + size_of::<Limited<'static>>()
            + size_of::<&OriginalRestoredSuffixBootstrap>()
            + size_of::<&mut OriginalRestoredSuffixBootstrap>()
            + size_of::<&SuffixBootstrap>()
            + size_of::<&mut SuffixBootstrap>()
            + size_of::<&Path>()
            + size_of::<std::io::Stdin>()
            + size_of::<rustix::net::UCred>()
            + size_of::<Result<rustix::net::UCred, rustix::io::Errno>>()
            + size_of::<Result<rustix::net::UCred, std::io::Error>>()
            + size_of::<rustix::process::Pid>()
            + size_of::<Option<rustix::process::Pid>>();

    let frame_and_literal_views = size_of::<Result<(usize, usize), rustix::io::Errno>>()
        + size_of::<(usize, usize)>()
        + size_of::<
            crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
        >()
        + size_of::<
            Result<
                crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData,
                ProviderError,
            >,
        >()
        + size_of::<super::owned_read::OriginalPrivateBootstrapStream<std::io::Stdin>>()
        + size_of::<FrameReader<super::owned_read::OriginalPrivateBootstrapStream<std::io::Stdin>>>(
        )
        + size_of::<
            Result<
                FrameReader<super::owned_read::OriginalPrivateBootstrapStream<std::io::Stdin>>,
                ProviderError,
            >,
        >()
        + size_of::<crate::transport::RetainedFrame>()
        + size_of::<Option<crate::transport::RetainedFrame>>()
        + size_of::<Result<Option<crate::transport::RetainedFrame>, ProviderError>>()
        + size_of::<
            &mut FrameReader<super::owned_read::OriginalPrivateBootstrapStream<std::io::Stdin>>,
        >()
        + size_of::<
            Result<
                &mut FrameReader<super::owned_read::OriginalPrivateBootstrapStream<std::io::Stdin>>,
                ProviderError,
            >,
        >()
        + size_of::<OriginalFrameReservation>()
        + size_of::<Result<OriginalFrameReservation, ProviderError>>()
        + size_of::<Rc<RefCell<OriginalFrameReservation>>>()
        + size_of::<&Rc<RefCell<OriginalFrameReservation>>>()
        + size_of::<Result<&Rc<RefCell<OriginalFrameReservation>>, ProviderError>>();

    let decoded_and_returned_views = size_of::<OriginalNative5BirthCut>()
        + size_of::<Result<OriginalNative5BirthCut, ProviderError>>()
        + size_of::<&OriginalNative5BirthCut>()
        + size_of::<Result<&OriginalNative5BirthCut, ProviderError>>()
        + size_of::<&serde_json::Value>() * 3
        + size_of::<Option<&serde_json::Value>>()
        + size_of::<Result<&serde_json::Value, ProviderError>>()
        + size_of::<&serde_json::Map<String, serde_json::Value>>()
        + size_of::<Result<&serde_json::Map<String, serde_json::Value>, ProviderError>>()
        + size_of::<Option<&str>>()
        + size_of::<Option<u64>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<Result<&PacketNative5SourceLaunch, ProviderError>>()
        + size_of::<PacketNativeSuffixLaunchIdentityData>()
        + size_of::<PacketNativeInvocationLaunchIdentityData>()
        + size_of::<Result<PacketNativeInvocationLaunchIdentityData, ProviderError>>()
        + size_of::<OriginalNativeFramePreflight<'static>>() * 2
        + size_of::<crate::protocol_snapshot::owned11::OriginalOwned11Fields<'static>>()
        + size_of::<Result<crate::protocol_snapshot::owned11::OriginalOwned11Fields<'static>, ProviderError>>()
        + size_of::<Vec<u8>>()
        + size_of::<Result<Vec<u8>, ContractError>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Result<(), ProviderError>>()
        + crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
        + size_of::<Result<PacketNativeInvocationPurposeData, ProviderError>>()
        + size_of::<Result<PacketSourceService, ProviderError>>()
        + size_of::<Result<Result<PacketSourceService, ProviderError>, Box<dyn std::any::Any + Send>>>()
        + size_of::<Box<SuffixBootstrap>>()
        + size_of::<Rc<RefCell<super::boot::NativeAckBoot>>>()
        + size_of::<&Rc<RefCell<super::boot::NativeAckBoot>>>()
        + size_of::<Result<&Rc<RefCell<super::boot::NativeAckBoot>>, ProviderError>>()
        + size_of::<Result<crucible_node_format::ContentRef, ProviderError>>()
        + size_of::<PacketNative5SourceLaunch>()
        + size_of::<Result<PacketNative5SourceLaunch, ProviderError>>()
        + size_of::<std::io::Result<usize>>()
        + size_of::<std::io::Result<()>>();

    reader_views
        + typed_views
        + owner_and_decode_views
        + bootstrap_and_peer_views
        + frame_and_literal_views
        + decoded_and_returned_views
}

fn refused() -> ProviderError {
    ProviderError::Correlation("restored suffix16 original bootstrap differs")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("restored suffix16 bootstrap window")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_launch_requires_exact_separate_seven_wrapper() {
        let original = br#"{"invocation":{},"launch":{"schema_version":5},"schema_version":7,"suffix_reservation":{}}"#;
        assert_eq!(
            nested_launch5(original).unwrap(),
            br#"{"schema_version":5}"#
        );
        for foreign in [
            br#"{"invocation":{},"launch":{},"schema_version":6,"suffix_reservation":{}}"#.as_slice(),
            br#"{"invocation":{},"launch":{},"schema_version":7,"suffix_reservation":{},"unknown":0}"#,
            br#"{"invocation":{},"launch":{},"launch":{},"schema_version":7,"suffix_reservation":{}}"#,
        ] {
            assert!(nested_launch5(foreign).is_err());
        }
    }

    #[test]
    fn inherited_prefix_refuses_same_process_peer_before_read() {
        let (receiver, _sender) = std::os::unix::net::UnixStream::pair().unwrap();
        // A local pair is not the inherited parent channel. No prefix bytes,
        // scope, native owner or positive claim are manufactured by this test.
        assert!(OriginalRestoredSuffixBootstrap::read(&receiver).is_err());
    }

    #[test]
    fn bounded_derived_launch_writer_keeps_partial_on_one_short() {
        let mut exact = Vec::with_capacity(4);
        Limited {
            bank: &mut exact,
            maximum: 4,
        }
        .write_all(b"test")
        .unwrap();
        assert_eq!(exact, b"test");

        let mut partial = Vec::with_capacity(4);
        let mut writer = Limited {
            bank: &mut partial,
            maximum: 3,
        };
        writer.write_all(b"te").unwrap();
        assert!(writer.write_all(b"st").is_err());
        assert_eq!(partial, b"te");
    }
}
