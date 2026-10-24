//! Retains the actual inherited prefix17 before parsing or native allocation.
//!
//! The sole constructor reads the real inherited socket, authenticates its
//! parent credentials and complete new MAC, and preserves a nonrenewing cut.
//! A decoded advertisement cannot construct this private one-shot owner. The
//! caller retains it on every later error, including a failed native install.

use super::restored_settled::OriginalRestoredSettledCaptureInputsData;
use crate::ProviderError;
use crate::reference_packet::service::native_startup::*;
use crate::reference_packet::service::native_startup::{
    ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES, PacketNativeSettledPreambleData,
    PacketRestoredSettledNativeCarrierData, authenticate_original_native_settled_preamble_data,
    decode_original_native_settled_preamble_data,
    original_native_birth_startup_counter_scratch_data,
    original_native_private_bootstrap_floor_data,
};
use crate::reference_packet::service::{PacketNative5SourceLaunch, PacketSourceService};
use crate::{
    client::OriginalNative5BirthCut,
    transport::{FrameReader, original_frames::OriginalFrameReservation},
};
use std::{cell::RefCell, io::Write, path::Path, rc::Rc};
use std::{mem::size_of, os::fd::AsFd, time::Duration};

/// Groups the original inputs for retaining one prefix17 boot.
///
/// This record carries the same owned nested launch and borrowed authenticated
/// inputs. It supplies no bootstrap permission or independently usable owner.
pub(super) struct OriginalRestoredSettledBootInputsData<'a> {
    /// Borrows the actual private boot value already retained by the reader.
    pub(super) value: &'a serde_json::Value,
    /// Borrows the actual decoded Source launch.
    pub(super) launch: &'a PacketNative5SourceLaunch,
    /// Borrows the complete original wrapper8 bytes.
    pub(super) raw8: &'a [u8],
    /// Borrows the original nested suffix7 bytes.
    pub(super) raw7: &'a [u8],
    /// Moves the same independently retained nested invocation6 bytes.
    pub(super) original6: Vec<u8>,
    /// Carries the original invocation purpose without issuing authority.
    pub(super) purpose: PacketNativeInvocationPurposeData,
    /// Borrows the complete decoded existing allocation rows.
    pub(super) existing_rows: &'a PacketRestoredSettledNativeExistingRowsData,
}

/// Owns one genuine prefix17 occurrence, rather than a portable bootstrap DTO.
pub(super) struct OriginalRestoredSettledBootstrap {
    creator: u32,
    thread: std::thread::ThreadId,
    preamble: [u8; ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES],
    pub(super) data: PacketNativeSettledPreambleData,
    pub(super) original_cut: crate::operational_time::OperationalDeadline,
    issued: bool,
    failed: bool,
}

impl OriginalRestoredSettledBootstrap {
    /// Reads the real inherited private socket before any owned frame parser.
    pub(super) fn read<S: AsFd>(stream: &S) -> Result<Self, ProviderError> {
        let original_cut =
            crate::operational_time::OperationalDeadline::after(Duration::from_secs(5))
                .ok_or_else(refused)?;
        let peer = rustix::net::sockopt::socket_peercred(stream).map_err(std::io::Error::from)?;
        let parent = rustix::process::getppid().ok_or_else(refused)?;
        if peer.pid != parent || peer.uid != rustix::process::geteuid() {
            return Err(refused());
        }

        let mut preamble = [0; ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES];
        let mut received = 0usize;
        while received < preamble.len() {
            if original_cut.is_expired() {
                return Err(refused());
            }
            match rustix::net::recv(
                stream,
                &mut preamble[received..],
                rustix::net::RecvFlags::DONTWAIT,
            ) {
                Ok((_, 0)) => return Err(ProviderError::Frame("settled17 prefix incomplete")),
                Ok((_, count)) => received += count,
                Err(error) if error == rustix::io::Errno::INTR => {}
                Err(error) if error == rustix::io::Errno::AGAIN => std::thread::yield_now(),
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
        }

        // This key is part of this actual inherited parent channel. It is not
        // an old16 MAC reconstructed from a new17 advertisement.
        let key = &preamble[504..536];
        authenticate_original_native_settled_preamble_data(&preamble, key)?;
        let data = decode_original_native_settled_preamble_data(&preamble)?;
        let invocation = &data.suffix.invocation;
        if invocation.controller_pid != u64::from(peer.pid.as_raw_nonzero().get() as u32)
            || invocation.controller_uid != u64::from(peer.uid.as_raw())
            || invocation.birth_id
                != blake3::derive_key("source-owned.packet-canonical-ack-birth/5", key)
        {
            return Err(refused());
        }

        // These are only the fixed pre-parser costs. The complete reader,
        // retained launch/boot and native graph rows are checked by install.
        let fixed = original_native_private_bootstrap_floor_data()?
            .checked_add(size_of::<Self>())
            .ok_or_else(refused)?;
        let scratch = original_native_birth_startup_counter_scratch_data()
            .checked_add(Self::counter_scratch_data())
            .ok_or_else(refused)?;
        if u64::try_from(fixed).map_err(|_| refused())?
            > invocation.private_bootstrap.retained_requested_bytes.get()
            || u64::try_from(scratch).map_err(|_| refused())?
                > invocation
                    .private_bootstrap
                    .declared_counter_scratch_bytes
                    .get()
        {
            return Err(refused());
        }

        // The first private Value/canonical pass happens before the full
        // constructor recount. Authenticate its independent transient axis now,
        // just as for the existing suffix parser; retained/scratch credit does
        // not pay this separate peak.
        let incoming = crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(
            (invocation.launch_bytes as usize).max(invocation.maximum_boot_bytes as usize),
        )?;
        if u64::try_from(incoming.canonical_pass_requested_bytes()?).map_err(|_| refused())?
            > invocation
                .private_bootstrap
                .maximum_simultaneous_transient_bytes
                .get()
        {
            return Err(refused());
        }

        Ok(Self {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            preamble,
            data,
            original_cut,
            issued: false,
            failed: false,
        })
    }

    pub(super) const fn preamble_data(
        &self,
    ) -> &[u8; ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES] {
        &self.preamble
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

    pub(super) fn ensure_current(&self) -> Result<(), ProviderError> {
        self.ensure_cut()?;
        if self.failed {
            return Err(refused());
        }
        Ok(())
    }

    /// Spends this occurrence before comparing the actual retained boot bodies.
    pub(super) fn begin_claim(
        &mut self,
        key: &[u8],
        birth: &[u8],
        raw8: &[u8],
        existing_rows: &PacketRestoredSettledNativeExistingRowsData,
    ) -> Result<PacketRestoredSettledNativeCarrierData, ProviderError> {
        self.ensure_current()?;
        if std::mem::replace(&mut self.issued, true) {
            self.failed = true;
            return Err(refused());
        }
        self.failed = true;

        authenticate_original_native_settled_preamble_data(&self.preamble, key)?;
        let invocation = &self.data.suffix.invocation;
        if birth != invocation.birth_id
            || u64::try_from(raw8.len()).map_err(|_| refused())?
                != u64::from(invocation.launch_bytes)
            || blake3::hash(raw8).as_bytes() != &invocation.launch_digest
        {
            return Err(refused());
        }

        // This fixed scalar DTO is decoded from the SAME MAC-bound raw8,
        // never reconstructed by subtracting final advertised native credit.
        let mut fields = crate::protocol_snapshot::owned11::typed::Fields::object(raw8)?;
        fields.named("capture_reservation")?;
        let stored: PacketRestoredSettledNativeExistingRowsData =
            serde_json::from_slice(fields.named("existing_rows")?)
                .map_err(crucible_node_format::ContractError::from)?;
        fields.named("schema_version")?;
        fields.named("suffix")?;
        fields.finish()?;
        stored.validate_data()?;
        if &stored != existing_rows {
            return Err(refused());
        }

        self.ensure_cut()?;
        Ok(self.data.capture)
    }

    /// Closes install only after the same Boot has retained its real reserve.
    pub(super) fn complete_claim(&mut self) -> Result<(), ProviderError> {
        self.ensure_cut()?;
        if !self.issued || !self.failed {
            return Err(refused());
        }
        self.failed = false;
        Ok(())
    }

    pub(super) fn interrupt(&mut self) {
        self.failed = true;
    }

    pub(crate) const fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<[u8; ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES]>()
            + size_of::<PacketNativeSettledPreambleData>()
            + size_of::<Result<PacketNativeSettledPreambleData, ProviderError>>()
            + size_of::<PacketRestoredSettledNativeCarrierData>()
            + size_of::<Result<PacketRestoredSettledNativeCarrierData, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<u64, std::num::TryFromIntError>>()
            + size_of::<usize>() * 2
            + size_of::<[u8; 32]>()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("settled17 inherited bootstrap unavailable or spent")
}

/// Reports the retained inherited prefix owner before frame decoding starts.
///
/// The complete accept frame/Value/partial capsule is a separate native holder
/// construction term; this value names the exact fixed reader prerequisite.
pub(crate) const fn original_restored_settled_bootstrap_header_data() -> usize {
    size_of::<OriginalRestoredSettledBootstrap>()
}

/// Reports defining fixed prefix authentication and once-claim views.
pub(crate) fn original_restored_settled_bootstrap_counter_scratch_data() -> usize {
    // Both call boundaries retain their own input headers. The existing native
    // construction quote includes this fixed scratch before owner admission;
    // the owned launch backing remains separately priced by its original row.
    2 * size_of::<OriginalRestoredSettledBootInputsData<'static>>()
        + 2 * size_of::<OriginalRestoredSettledCaptureInputsData<'static>>()
        + size_of::<usize>()
        + OriginalRestoredSettledBootstrap::counter_scratch_data()
        + super::bootstrap_suffix::original_restored_suffix_bootstrap_counter_scratch_data()
        + size_of::<SettledBootstrap>()
        + size_of::<PacketNative8RestoredSettledLaunch>()
        + size_of::<Option<PacketNative8RestoredSettledLaunch>>()
        + size_of::<&PacketNative8RestoredSettledLaunch>()
        + size_of::<&mut PacketNative8RestoredSettledLaunch>()
        + size_of::<Result<&PacketRestoredSettledNativeCarrierData, ProviderError>>()
        + size_of::<Result<PacketNativeInvocationPurposeData, ProviderError>>()
        + size_of::<Result<PacketRestoredSuffixReservationData, ProviderError>>()
        + size_of::<Limited<'static>>()
        + size_of::<Result<(), std::io::Error>>()
}

struct SettledBootstrap {
    reader: Option<FrameReader<super::owned_read::OriginalPrivateBootstrapStream<std::io::Stdin>>>,
    literals: Option<Rc<RefCell<OriginalFrameReservation>>>,
    launch_value: Option<serde_json::Value>,
    launch8: Vec<u8>,
    launch7: Vec<u8>,
    launch6: Vec<u8>,
    decoded: Option<PacketNative8RestoredSettledLaunch>,
    launch: Option<PacketNative5SourceLaunch>,
    boot_value: Option<serde_json::Value>,
    boot: Option<Rc<RefCell<super::boot::NativeAckBoot>>>,
    startup: OriginalRestoredSettledBootstrap,
}

/// Accepts only the separately selected genuine inherited prefix17 path.
pub(in crate::reference_packet::service) fn accept(
    socket: &Path,
) -> Result<PacketSourceService, ProviderError> {
    let startup = OriginalRestoredSettledBootstrap::read(&rustix::stdio::stdin())?;
    let mut owner = SettledBootstrap {
        reader: None,
        literals: None,
        launch_value: None,
        launch8: Vec::new(),
        launch7: Vec::new(),
        launch6: Vec::new(),
        decoded: None,
        launch: None,
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
            owner.startup.interrupt();
            loop {
                std::hint::black_box((&owner, &failure));
                std::thread::park();
            }
        }
    }
}

impl SettledBootstrap {
    fn prepare(&mut self, socket: &Path) -> Result<PacketSourceService, ProviderError> {
        self.startup.ensure_current()?;
        let expected = self.startup.data.suffix.invocation;
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
        let maximum = (expected.launch_bytes as usize).max(expected.maximum_boot_bytes as usize);
        let mut reader = FrameReader::with_limits(stream, maximum, 64)?;
        reader.install_originals(bank);
        self.reader = Some(reader);

        let budget = OriginalNativeFramePreflight::private(&expected.private_bootstrap, 0);
        self.launch_value = Some(
            self.reader
                .as_mut()
                .ok_or_else(refused)?
                .read_original_native_preflight(maximum, &budget)?
                .ok_or_else(refused)?
                .value,
        );
        self.startup.ensure_current()?;
        self.launch8 = crucible_node_format::canonical::canonical_json(
            self.launch_value.as_ref().ok_or_else(refused)?,
        )?;
        if self.launch8.len() != expected.launch_bytes as usize
            || blake3::hash(&self.launch8).as_bytes() != &expected.launch_digest
        {
            return Err(refused());
        }

        PacketNative8RestoredSettledLaunch::decode_original_value_into(
            self.launch_value.as_ref().ok_or_else(refused)?,
            &mut self.decoded,
        )?;
        let decoded = self.decoded.as_ref().ok_or_else(refused)?;
        if decoded.capture_reservation_data()? != &self.startup.data.capture
            || decoded.suffix_reservation_data()? != self.startup.data.suffix.suffix_reservation
        {
            return Err(refused());
        }

        let purpose = decoded.invocation_data()?;
        let mut fields =
            crate::protocol_snapshot::owned11::OriginalOwned11Fields::object(&self.launch8)?;
        fields.named("capture_reservation")?;
        // Match actual four-field wrapper8, with the same old-row snapshot
        // retained by its typed owner and rechecked by the private once-claim.
        fields.named("existing_rows")?;
        if fields.named("schema_version")? != b"8" {
            return Err(refused());
        }
        let raw7 = fields.named("suffix")?;
        fields.finish()?;

        self.launch7
            .try_reserve_exact(raw7.len())
            .map_err(|_| refused())?;
        self.launch7.extend_from_slice(raw7);

        let nested = super::bootstrap_suffix::nested_launch5(&self.launch7)?;
        let identity6 = original_native_invocation_launch_identity_data(&purpose, nested)?;
        self.launch6
            .try_reserve_exact(identity6.encoded_bytes)
            .map_err(|_| refused())?;
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

        let launch = decoded.suffix_data()?.launch_data();
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
        let carry = original_private_launch_backing_data(launch)?
            .checked_add(self.launch8.capacity())
            .and_then(|bytes| bytes.checked_add(self.launch7.capacity()))
            .and_then(|bytes| bytes.checked_add(self.launch6.capacity()))
            .ok_or_else(refused)?;

        let budget = OriginalNativeFramePreflight::private(&expected.private_bootstrap, carry);
        self.boot_value = Some(
            self.reader
                .as_mut()
                .ok_or_else(refused)?
                .read_original_native_preflight(expected.maximum_boot_bytes as usize, &budget)?
                .ok_or_else(refused)?
                .value,
        );
        self.startup.ensure_current()?;
        super::boot::NativeAckBoot::prepare_original_restored_settled_into(
            OriginalRestoredSettledBootInputsData {
                value: self.boot_value.as_ref().ok_or_else(refused)?,
                launch,
                raw8: &self.launch8,
                raw7: &self.launch7,
                original6: self.launch6.clone(),
                purpose,
                existing_rows: decoded.existing_rows_data()?,
            },
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
        self.decoded
            .as_mut()
            .ok_or_else(refused)?
            .take_launch_into(&mut self.launch)?;
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
        self.bank
            .len()
            .checked_add(bytes.len())
            .filter(|end| *end <= self.maximum && *end <= self.bank.capacity())
            .ok_or_else(|| std::io::Error::other("settled17 nested launch bank"))?;
        self.bank.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Reports the actual retained reader/raw/typed/error capsule before accept.
pub(crate) const fn original_restored_settled_bootstrap_accept_header_data() -> usize {
    size_of::<SettledBootstrap>()
}

/// Lends only the actual successful concrete prefix17 capsule from this service.
///
/// The caller has authenticated the current Connection native admission first.
/// This does not consume old16 bootstrap or reconstruct an issuer from a DTO.
pub(in crate::reference_packet::service) fn borrow_current_settled_bootstrap_data<'a>(
    retained: &'a dyn std::any::Any,
    actual_boot: &'a Rc<RefCell<super::boot::NativeAckBoot>>,
) -> Result<SettledBootstrapHistory17<'a>, ProviderError> {
    let owner = retained
        .downcast_ref::<SettledBootstrap>()
        .ok_or_else(refused)?;
    authenticate_settled_bootstrap_history(owner, actual_boot)?;
    let literals = owner
        .literals
        .as_ref()
        .ok_or_else(refused)?
        .try_borrow()
        .map_err(|_| refused())?;
    let facts = owner
        .reader
        .as_ref()
        .ok_or_else(refused)?
        .original_owned11_facts(owner.literals.as_ref().ok_or_else(refused)?)?;
    Ok(SettledBootstrapHistory17 {
        owner,
        actual_boot,
        literals,
        facts,
    })
}

fn authenticate_settled_bootstrap_history(
    owner: &SettledBootstrap,
    actual_boot: &Rc<RefCell<super::boot::NativeAckBoot>>,
) -> Result<(), ProviderError> {
    if owner.startup.creator != std::process::id()
        || owner.startup.thread != std::thread::current().id()
        || !owner.startup.issued
        || owner.startup.failed
        || owner.launch.is_some()
        || owner
            .boot
            .as_ref()
            .is_none_or(|boot| !Rc::ptr_eq(boot, actual_boot))
        || owner.launch_value.is_none()
        || owner.boot_value.is_none()
    {
        return Err(refused());
    }

    let decoded = owner.decoded.as_ref().ok_or_else(refused)?;
    decoded.invocation_data()?;
    decoded.existing_rows_data()?;
    decoded.capture_reservation_data()?;

    // Successful transfer empties the actual typed launch once. Other failed
    // parser stages cannot pass the complete fixed getters above.
    if decoded.suffix_data().is_ok() {
        return Err(refused());
    }
    let reader = owner.reader.as_ref().ok_or_else(refused)?;
    if reader.stream_ref().cut.is_some() {
        return Err(refused());
    }
    let facts = reader.original_owned11_facts(owner.literals.as_ref().ok_or_else(refused)?)?;
    if facts.failed
        || facts.last_original_slot != Some(1)
        || owner.launch8.len() != owner.startup.data.suffix.invocation.launch_bytes as usize
        || blake3::hash(&owner.launch8).as_bytes()
            != &owner.startup.data.suffix.invocation.launch_digest
    {
        return Err(refused());
    }

    let frames = owner
        .literals
        .as_ref()
        .ok_or_else(refused)?
        .try_borrow()
        .map_err(|_| refused())?;
    if frames.frames().count() != 2
        || frames.frames().any(|frame| {
            frame.direction != crate::transport::original_frames::FrameDirection::Incoming
                || !frame.complete
                || frame.transferred != frame.bytes.len()
        })
    {
        return Err(refused());
    }

    // An unrecorded private suffix remains a real obligation. Require genuine
    // channel closure, matching the original immutable bootstrap history rule.
    let mut probe = [0u8; 1];
    match rustix::net::recv(
        &reader.stream_ref().original,
        &mut probe,
        rustix::net::RecvFlags::DONTWAIT | rustix::net::RecvFlags::PEEK,
    ) {
        Ok((_, 0)) => Ok(()),
        Ok(_) => Err(refused()),
        Err(error) if error == rustix::io::Errno::AGAIN => Err(refused()),
        Err(error) => Err(std::io::Error::from(error).into()),
    }
}

pub(in crate::reference_packet::service) struct SettledBootstrapHistory17<'a> {
    owner: &'a SettledBootstrap,
    actual_boot: &'a Rc<RefCell<super::boot::NativeAckBoot>>,
    literals: std::cell::Ref<'a, OriginalFrameReservation>,
    facts: crate::transport::OriginalFrameReaderFacts,
}

impl serde::Serialize for SettledBootstrapHistory17<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes;
        use serde::ser::SerializeStruct;
        authenticate_settled_bootstrap_history(self.owner, self.actual_boot)
            .map_err(serde::ser::Error::custom)?;
        let SettledBootstrap {
            reader: _,
            literals: _,
            launch_value,
            launch8,
            launch7,
            launch6,
            decoded,
            launch: _,
            boot_value,
            boot: _,
            startup,
        } = self.owner;
        let decoded = decoded
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("typed bootstrap8 absent"))?;
        let mut fields = serializer.serialize_struct("NativeCurrentBootstrap17", 15)?;
        fields.serialize_field("schema", "source-private.native-current-bootstrap/17")?;
        fields.serialize_field("reader", &self.facts)?;
        fields.serialize_field(
            "private_frames",
            &self.literals.protocol_view_with_encoding(true),
        )?;
        fields.serialize_field("launch_value", launch_value)?;
        fields.serialize_field(
            "launch8",
            &(BorrowedCompactBytes::new(launch8), launch8.capacity()),
        )?;
        fields.serialize_field(
            "launch7",
            &(BorrowedCompactBytes::new(launch7), launch7.capacity()),
        )?;
        fields.serialize_field(
            "launch6",
            &(BorrowedCompactBytes::new(launch6), launch6.capacity()),
        )?;
        fields.serialize_field(
            "typed_fixed",
            &(
                decoded
                    .invocation_data()
                    .map_err(serde::ser::Error::custom)?,
                decoded
                    .suffix_reservation_data()
                    .map_err(serde::ser::Error::custom)?,
                decoded
                    .existing_rows_data()
                    .map_err(serde::ser::Error::custom)?,
                decoded
                    .capture_reservation_data()
                    .map_err(serde::ser::Error::custom)?,
            ),
        )?;
        fields.serialize_field("launch_transferred", &true)?;
        fields.serialize_field("boot_value", boot_value)?;
        fields.serialize_field("boot_role", "native-boot")?;
        fields.serialize_field("prefix", &BorrowedCompactBytes::new(&startup.preamble))?;
        fields.serialize_field("issued", &startup.issued)?;
        fields.serialize_field("failed", &startup.failed)?;
        fields.serialize_field(
            "original_cut_role",
            "genuine-original-birth-cut-transferred-history-only",
        )?;
        fields.end()
    }
}

#[path = "bootstrap_settled/settled17.rs"]
mod settled17;
pub(crate) use settled17::{
    CurrentBootstrap17GroupIds, HistoricalCurrentBootstrap17,
    read_current_native17_bootstrap_fields_data,
};

pub(crate) use settled17::{
    BorrowedBootstrap17LineageData, borrow_current_bootstrap17_lineage_data,
};
