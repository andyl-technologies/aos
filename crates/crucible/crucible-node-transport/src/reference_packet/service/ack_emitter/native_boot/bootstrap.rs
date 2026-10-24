//! Retains the actual inherited private channel until native birth completes.

use super::owned_read::OriginalPrivateBootstrapInput;
use crate::reference_packet::service::{PacketNative5SourceLaunch, PacketSourceService};
use crate::transport::original_frames::OriginalFrameReservation;
use crate::{ProviderError, client::OriginalNative5BirthCut, transport::FrameReader};
use serde::Deserialize;
use std::{cell::RefCell, os::fd::AsFd, path::Path, rc::Rc, time::Duration};

#[path = "bootstrap_admitted.rs"]
pub(super) mod admitted;
#[path = "bootstrap_owned11.rs"]
mod owned11;

pub(crate) use owned11::OriginalNativeBootstrapOwned11;

#[cfg(test)]
#[path = "bootstrap_body_tests.rs"]
mod body_tests;

struct Bootstrap<S> {
    reader: FrameReader<super::owned_read::OriginalPrivateBootstrapStream<S>>,
    literals: Rc<RefCell<OriginalFrameReservation>>,
    launch_value: Option<serde_json::Value>,
    launch_bytes: Vec<u8>,
    launch: Option<PacketNative5SourceLaunch>,
    boot_value: Option<serde_json::Value>,
    boot: Option<Rc<RefCell<super::boot::NativeAckBoot>>>,
    startup_attempt: Option<super::boot::OriginalNativeStartupBootAttempt>,
    startup: Option<admitted::OriginalNativeStartupBootstrap>,
}

pub(in crate::reference_packet::service) fn accept(
    socket: &Path,
    stdin: std::io::Stdin,
) -> Result<PacketSourceService, ProviderError> {
    let cut = OriginalNative5BirthCut::start(Duration::from_secs(5))?;
    let bank = Rc::new(RefCell::new(OriginalFrameReservation::reserve(
        1024 * 1024 + 512 * 1024 + 8,
        2,
    )?));
    let stream = super::owned_read::OriginalPrivateBootstrapStream {
        original: OriginalPrivateBootstrapInput::Legacy(stdin),
        cut: Some(cut),
    };
    let mut reader = FrameReader::with_limits(stream, 1024 * 1024, 64)?;
    reader.install_originals(Rc::clone(&bank));
    let mut owner = Bootstrap {
        reader,
        literals: bank,
        launch_value: None,
        launch_bytes: Vec::new(),
        launch: None,
        boot_value: None,
        boot: None,
        startup_attempt: None,
        startup: None,
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.prepare(socket)));
    match result {
        Ok(Ok(mut service)) => {
            service._private_bootstrap = Some(Box::new(owner));
            Ok(service)
        }
        failure => loop {
            std::hint::black_box((&owner, &failure));
            std::thread::park();
        },
    }
}

// This distinct entry consumes the fixed origin prefix before allocating a
// reader, literal bank or typed launch. Old boot5 entry behavior is preserved.
pub(in crate::reference_packet::service) fn accept_admitted(
    socket: &Path,
) -> Result<PacketSourceService, ProviderError> {
    // Retain the same safe fd0 borrow through prefix admission and frame reads;
    // no standard-library buffered stdin owner is constructed on this path.
    let stdin = rustix::stdio::stdin();
    let startup = admitted::OriginalNativeStartupBootstrap::read_original(&stdin)?;
    let cut = OriginalNative5BirthCut::from_original_preparser_cut(startup.original_cut)?;
    let bank = Rc::new(RefCell::new(OriginalFrameReservation::reserve(
        1024 * 1024 + 512 * 1024 + 8,
        2,
    )?));
    let stream = super::owned_read::OriginalPrivateBootstrapStream {
        original: OriginalPrivateBootstrapInput::Inherited(stdin),
        cut: Some(cut),
    };
    let mut reader = FrameReader::with_limits(
        stream,
        startup.maximum_launch_bytes.max(startup.maximum_boot_bytes),
        64,
    )?;
    reader.install_originals(Rc::clone(&bank));
    let mut owner = Bootstrap {
        reader,
        literals: bank,
        launch_value: None,
        launch_bytes: Vec::new(),
        launch: None,
        boot_value: None,
        boot: None,
        startup_attempt: None,
        startup: Some(startup),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.prepare(socket)));
    match result {
        Ok(Ok(mut service)) => {
            service._private_bootstrap = Some(Box::new(owner));
            Ok(service)
        }
        failure => {
            if let Some(startup) = owner.startup.as_mut() {
                startup.failed = true;
            }
            loop {
                std::hint::black_box((&owner, &failure));
                std::thread::park();
            }
        }
    }
}

// Distinct selected entry; the legacy admitted entry still reads prefix14 only.
pub(in crate::reference_packet::service) fn accept_invocation(
    socket: &Path,
) -> Result<PacketSourceService, ProviderError> {
    // Retain the same safe fd0 borrow through prefix admission and frame reads;
    // no standard-library buffered stdin owner is constructed on this path.
    let stdin = rustix::stdio::stdin();
    let startup = admitted::OriginalNativeStartupBootstrap::read_invocation(&stdin)?;
    let cut = OriginalNative5BirthCut::from_original_preparser_cut(startup.original_cut)?;
    let bank = Rc::new(RefCell::new(OriginalFrameReservation::reserve(
        1024 * 1024 + 512 * 1024 + 8,
        2,
    )?));
    let stream = super::owned_read::OriginalPrivateBootstrapStream {
        original: OriginalPrivateBootstrapInput::Inherited(stdin),
        cut: Some(cut),
    };
    let mut reader = FrameReader::with_limits(
        stream,
        startup.maximum_launch_bytes.max(startup.maximum_boot_bytes),
        64,
    )?;
    reader.install_originals(Rc::clone(&bank));
    let mut owner = Bootstrap {
        reader,
        literals: bank,
        launch_value: None,
        launch_bytes: Vec::new(),
        launch: None,
        boot_value: None,
        boot: None,
        startup_attempt: None,
        startup: Some(startup),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| owner.prepare(socket)));
    match result {
        Ok(Ok(mut service)) => {
            service._private_bootstrap = Some(Box::new(owner));
            Ok(service)
        }
        failure => {
            if let Some(startup) = owner.startup.as_mut() {
                startup.failed = true;
            }
            loop {
                std::hint::black_box((&owner, &failure));
                std::thread::park();
            }
        }
    }
}

impl<S: AsFd> Bootstrap<S> {
    fn prepare(&mut self, socket: &Path) -> Result<PacketSourceService, ProviderError> {
        let pre_dom_selected = self
            .startup
            .as_ref()
            .map(|startup| {
                startup
                    .has_invocation_prefix()
                    .map(|invocation| !invocation)
            })
            .transpose()?
            .unwrap_or(false);
        self.launch_value = Some(
            if let Some(startup) = self.startup.as_ref().filter(|_| pre_dom_selected) {
                startup.ensure_original()?;
                let budget = crate::reference_packet::service::native_startup::OriginalNativeFramePreflight::private(
                    &startup.private_bootstrap,
                    0,
                );
                let frame = self.reader.read_original_native_preflight(
                    startup.maximum_launch_bytes.max(startup.maximum_boot_bytes),
                    &budget,
                )?;
                frame.map(|frame| frame.value)
            } else {
                self.reader.read()?
            }
            .ok_or(ProviderError::Frame("native private launch absent"))?,
        );
        // A completed Value belongs to this same bootstrap before the next
        // fallible cut check. Expiry retains it alongside its literal journal.
        if let Some(startup) = self.startup.as_ref().filter(|_| pre_dom_selected) {
            startup.ensure_original()?;
        }
        self.launch_bytes = crucible_node_format::canonical::canonical_json(
            self.launch_value
                .as_ref()
                .ok_or(ProviderError::Frame("native launch slot absent"))?,
        )?;
        self.launch = Some(if let Some(startup) = self.startup.as_ref() {
            startup.ensure_original()?;
            let digest = if startup.has_invocation_prefix()? {
                startup.invocation_data()?.launch_digest
            } else {
                startup.data()?.launch_digest
            };
            if self.launch_bytes.len() != startup.maximum_launch_bytes
                || blake3::hash(&self.launch_bytes).as_bytes() != &digest
            {
                return Err(ProviderError::Correlation(
                    "native startup launch literal differs",
                ));
            }
            // Full policy validation constructs schema owners. It follows the
            // actual native row recount, rather than running in the pre-parser.
            let value = self
                .launch_value
                .as_ref()
                .ok_or(ProviderError::Frame("native startup launch value absent"))?;
            let value = if startup.has_invocation_prefix()? {
                let fields = value.as_object().ok_or(ProviderError::Correlation(
                    "native invocation launch object",
                ))?;
                if fields.len() != 3
                    || fields
                        .get("schema_version")
                        .and_then(serde_json::Value::as_u64)
                        != Some(6)
                    || !fields.contains_key("invocation")
                {
                    return Err(ProviderError::Correlation(
                        "native invocation launch closed class",
                    ));
                }
                fields.get("launch").ok_or(ProviderError::Correlation(
                    "native invocation nested launch",
                ))?
            } else {
                value
            };
            PacketNative5SourceLaunch::deserialize(value)
                .map_err(crucible_node_format::ContractError::from)?
        } else {
            PacketNative5SourceLaunch::decode(&self.launch_bytes, 1024 * 1024)?
        });
        let launch = self
            .launch
            .as_ref()
            .ok_or(ProviderError::Frame("native selected launch absent"))?;
        if launch.ack_emitter_selection
            != Some(super::super::PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
        {
            return Err(ProviderError::Correlation(
                "native selected boot requires ACK mechanism",
            ));
        }
        let peer = rustix::net::sockopt::socket_peercred(&self.reader.stream_mut().original)
            .map_err(std::io::Error::from)?;
        if peer.pid.as_raw_nonzero().get() as u64 != launch.controller_pid.get()
            || u64::from(peer.uid.as_raw()) != launch.controller_uid.get()
        {
            return Err(ProviderError::Correlation("native inherited peer identity"));
        }
        if self.startup.is_none() {
            let exe = std::path::Path::new("/proc")
                .join(launch.controller_pid.get().to_string())
                .join("exe");
            if crate::conformance::measure_executable(&exe)? != launch.controller_executable {
                return Err(ProviderError::Correlation(
                    "native inherited peer executable",
                ));
            }
        }
        if let Some(startup) = self.startup.as_mut()
            && startup.has_invocation_prefix()?
        {
            startup.admit_invocation_boot_parser_data(launch)?;
        }
        self.boot_value = Some(
            if let Some(startup) = self.startup.as_ref().filter(|_| pre_dom_selected) {
                startup.ensure_original()?;
                // The clone passed into NativeAckBoot is independent from the
                // original growable canonical bank already funded in privateR.
                let carry = crate::reference_packet::service::native_startup::original_private_launch_backing_data(launch)?
                    .checked_add(self.launch_bytes.len())
                    .ok_or(ProviderError::ResourceExhausted("native private carried launch"))?;
                let budget = crate::reference_packet::service::native_startup::OriginalNativeFramePreflight::private(
                    &startup.private_bootstrap,
                    carry,
                );
                self.reader.read_original_native_preflight(startup.maximum_boot_bytes, &budget)?
            } else {
                self.reader.read_retained_with_maximum_bytes(self.startup.as_ref().map_or(512 * 1024, |startup| startup.maximum_boot_bytes))?
            }
            .ok_or(ProviderError::Frame("native private boot absent"))?
            .value,
        );
        // Keep the complete second Value on expiry before any boot DTO or
        // Source/registration preparation borrows it.
        if let Some(startup) = self.startup.as_ref().filter(|_| pre_dom_selected) {
            startup.ensure_original()?;
        }
        let boot_value = self
            .boot_value
            .as_ref()
            .ok_or(ProviderError::Frame("native boot slot absent"))?;
        if let Some(startup) = self.startup.as_mut() {
            let literals = self
                .literals
                .try_borrow()
                .map_err(|_| ProviderError::Conflict("native original boot literals borrowed"))?;
            // This fresh two-slot bank contains launch then boot. FrameReader
            // checked the framing length before marking this second slot complete.
            let frame = literals
                .frame(1)
                .ok_or(ProviderError::Frame("native original boot literal absent"))?;
            if frame.direction != crate::transport::original_frames::FrameDirection::Incoming
                || !frame.complete
                || frame.transferred != frame.bytes.len()
            {
                return Err(ProviderError::Frame(
                    "native original boot literal incomplete",
                ));
            }
            let body = frame
                .bytes
                .get(4..)
                .ok_or(ProviderError::Frame("native original boot body absent"))?;
            let boot_value = super::boot::OriginalNativeBootValue {
                value: boot_value,
                body,
            };
            if startup.has_invocation_prefix()? {
                let purpose = crate::reference_packet::service::native_startup::PacketNativeInvocationPurposeData::from_original_value_data(
                    self.launch_value.as_ref()
                        .and_then(|value| value.get("invocation"))
                        .ok_or(ProviderError::Correlation("native invocation purpose absent"))?,
                )?;
                purpose.authenticate_target_data(launch)?;
                super::boot::NativeAckBoot::prepare_original_invocation_into(
                    boot_value,
                    launch,
                    self.launch_bytes.clone(),
                    purpose,
                    startup,
                    &mut self.startup_attempt,
                    &mut self.boot,
                )?;
            } else {
                super::boot::NativeAckBoot::prepare_original_startup_into(
                    boot_value,
                    launch,
                    self.launch_bytes.clone(),
                    startup,
                    &mut self.startup_attempt,
                    &mut self.boot,
                )?;
            }
            launch.validate()?;
            if admitted::measure_original_controller_executable(launch.controller_pid)?
                != launch.controller_executable
            {
                startup.failed = true;
                return Err(ProviderError::Correlation(
                    "native startup controller executable differs",
                ));
            }
            startup.ensure_original()?;
        } else {
            super::boot::NativeAckBoot::prepare_into(
                boot_value,
                launch,
                self.launch_bytes.clone(),
                &mut self.boot,
            )?;
        }
        self.reader
            .stream_mut()
            .cut
            .as_ref()
            .ok_or(ProviderError::Correlation("native original cut absent"))?
            .ensure_current()?;
        let stream = self.reader.stream_mut();
        // Move the original cut only after every borrowed private-channel check.
        // The socket/literals remain in this holder through service preparation.
        let cut = stream.cut.take().ok_or(ProviderError::Correlation(
            "native original cut transferred",
        ))?;
        let launch = self
            .launch
            .take()
            .ok_or(ProviderError::Frame("native launch transferred"))?;
        let boot = self
            .boot
            .as_ref()
            .ok_or(ProviderError::Frame("native boot transferred"))?
            .clone();
        super::super::super::server::accept_complete_with_boot(
            socket,
            launch,
            cut,
            boot,
            Rc::clone(&self.literals),
        )
    }
}

pub(crate) const fn original_native_private_bootstrap_layout() -> usize {
    // Preserve the legacy layout floor while independently counting the actual
    // closed input enum in every selected Bootstrap owner.
    let original = std::mem::size_of::<Bootstrap<std::io::Stdin>>();
    let current = std::mem::size_of::<Bootstrap<OriginalPrivateBootstrapInput>>();
    if current > original {
        current
    } else {
        original
    }
}
