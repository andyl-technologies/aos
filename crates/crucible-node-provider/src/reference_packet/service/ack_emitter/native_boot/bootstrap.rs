//! Retains the actual inherited private channel until native birth completes.

use crate::reference_packet::service::{PacketNative5SourceLaunch, PacketSourceService};
use crate::transport::original_frames::OriginalFrameReservation;
use crate::{ProviderError, client::OriginalNative5BirthCut, transport::FrameReader};
use std::{cell::RefCell, os::fd::AsFd, path::Path, rc::Rc, time::Duration};

#[path = "bootstrap_owned11.rs"]
mod owned11;

pub(crate) use owned11::OriginalNativeBootstrapOwned11;

struct Bootstrap<S> {
    reader: FrameReader<super::owned_read::OriginalPrivateBootstrapStream<S>>,
    literals: Rc<RefCell<OriginalFrameReservation>>,
    launch_value: Option<serde_json::Value>,
    launch_bytes: Vec<u8>,
    launch: Option<PacketNative5SourceLaunch>,
    boot_value: Option<serde_json::Value>,
    boot: Option<Rc<RefCell<super::boot::NativeAckBoot>>>,
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
        original: stdin,
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

impl<S: AsFd> Bootstrap<S> {
    fn prepare(&mut self, socket: &Path) -> Result<PacketSourceService, ProviderError> {
        self.launch_value = Some(
            self.reader
                .read()?
                .ok_or(ProviderError::Frame("native private launch absent"))?,
        );
        self.launch_bytes = crucible_node_contract::canonical::canonical_json(
            self.launch_value
                .as_ref()
                .ok_or(ProviderError::Frame("native launch slot absent"))?,
        )?;
        self.launch = Some(PacketNative5SourceLaunch::decode(
            &self.launch_bytes,
            1024 * 1024,
        )?);
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
        let exe = std::path::Path::new("/proc")
            .join(launch.controller_pid.get().to_string())
            .join("exe");
        if crate::conformance::measure_executable(&exe)? != launch.controller_executable {
            return Err(ProviderError::Correlation(
                "native inherited peer executable",
            ));
        }
        self.boot_value = Some(
            self.reader
                .read_retained_with_maximum_bytes(512 * 1024)?
                .ok_or(ProviderError::Frame("native private boot absent"))?
                .value,
        );
        super::boot::NativeAckBoot::prepare_into(
            self.boot_value
                .as_ref()
                .ok_or(ProviderError::Frame("native boot slot absent"))?,
            launch,
            self.launch_bytes.clone(),
            &mut self.boot,
        )?;
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
    std::mem::size_of::<Bootstrap<std::io::Stdin>>()
}
