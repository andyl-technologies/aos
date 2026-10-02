//! Manual, independently approved Initialize/one-Recover coordinator.
//!
//! Externally resident startup and ten fixed phase reservoirs outlive this
//! attempt. The native original job owns approval, whole history, time and
//! strict Pending/Terminal/Current persistence. The actual selected supervisor
//! owns each child and received record through errors and caught unwind.
//! Callbacks use only the shared nonblocking transport; full measurements,
//! native durability and post-nondumpable observations occur outside them.
//! This offline effect does not publish runtime credentials, seed a session
//! floor, authorize Resolve or establish descendant/TPM-RM Drain.

use std::io;
use std::os::fd::{AsFd as _, OwnedFd};

use aos_sandbox::journal::{
    NixOfflineHelperLaunchV5, NixOfflineNativeJobErrorV5, NixOfflineNativeJobV5,
};
use aos_sandbox::normal_root::OfflineNixHardwareOriginV5;
use aos_sandbox_linux::process::{FixedNixOfflineSessionOwnerV1, FixedProcessCaptureV1};
use aos_sandbox_linux::seqpacket::{NixOfflineSeqpacketPairV5, ReceivedRecord};
use zeroize::Zeroizing;

use crate::tpm_nv_custody::physical::{NixOfflineExchangeErrorV5, NixOfflineExchangeV5};

type Run<'resources> = FixedNixOfflineSessionOwnerV1<
    'resources,
    'resources,
    ReceivedRecord,
    NixOfflineExchangeErrorV5,
>;

struct PhaseResourcesV5 {
    launch: NixOfflineHelperLaunchV5,
    pair: NixOfflineSeqpacketPairV5,
    capture: FixedProcessCaptureV1,
    endpoint: Option<OwnedFd>,
    control: Option<OwnedFd>,
    nonce: Zeroizing<Vec<u8>>,
    hello: [u8; 232],
    request: Vec<u8>,
}

/// Retains ten fixed mechanical phase reservoirs outside their borrowing runs.
///
/// Construction acquires no protected descriptor or authority. The actual
/// coordinator alone fills these private slots from its genuine native job.
/// Keep this owner resident until explicit exit on failure or caught unwind.
pub struct NixOfflineHardwareResourcesV5 {
    phases: [PhaseResourcesV5; 10],
}

impl NixOfflineHardwareResourcesV5 {
    /// Creates bounded empty slots without any child/device/contact effect.
    #[must_use]
    pub fn new() -> Self {
        Self {
            phases: std::array::from_fn(|_| PhaseResourcesV5 {
                launch: NixOfflineHelperLaunchV5::new(),
                pair: NixOfflineSeqpacketPairV5::new(),
                capture: FixedProcessCaptureV1::new(),
                endpoint: None,
                control: None,
                nonce: Zeroizing::new(Vec::new()),
                hello: [0; 232],
                request: Vec::new(),
            }),
        }
    }
}

impl Default for NixOfflineHardwareResourcesV5 {
    fn default() -> Self {
        Self::new()
    }
}

/// Separates resident original causes from closed outward refusal markers.
#[derive(Debug, thiserror::Error)]
pub enum NixOfflineHardwareErrorV5 {
    /// The genuine native owner retains the original typed cause and debt.
    #[error("offline native job is fenced")]
    Native,
    /// The externally resident pair owns its first acquisition/admission cause.
    #[error("offline original helper pair is fenced")]
    Pair,
    /// The actual run owns its original process/exchange/cleanup cause.
    #[error("offline original helper run is fenced")]
    Process,
    /// A new allocation or control duplicate failed before child execution.
    #[error("offline original coordinator I/O failed")]
    Io(#[from] io::Error),
    /// The sole kernel entropy engine failed before contact admission.
    #[error("offline contact entropy failed")]
    Entropy(#[source] crate::BrokerSessionSecurityError),
    /// The actual transport refused its single ACK-to-RESULT phase handoff.
    #[error("offline original exchange phase differs")]
    Exchange,
    /// A fixed, already native-prepared mechanical handoff was refused.
    #[error("offline native launch handoff failed")]
    Launch(#[source] NixOfflineNativeJobErrorV5),
    /// A second, missing or interrupted attempt remains closed.
    #[error("offline hardware attempt is fenced")]
    Fenced,
}

/// Owns one genuine offline effect while borrowing externally resident resources.
///
/// The original native job is not a caller DTO. No helper path, hierarchy key,
/// profile, time or operation factory exists. Returned runs are parked before
/// every preparation/exchange call and never cloned. No implicit rollback,
/// hot effect retry, third attempt or runtime-floor activation is provided.
pub struct NixOfflineHardwareAttemptV5<'startup, 'resources> {
    native: NixOfflineNativeJobV5<'startup>,
    resources: Option<&'resources mut NixOfflineHardwareResourcesV5>,
    runs: Vec<Run<'resources>>,
    attempted: bool,
    first_failure: Option<NixOfflineHardwareErrorV5>,
    terminal_failure: Option<NixOfflineNativeJobErrorV5>,
    exchange_failure: Option<NixOfflineExchangeErrorV5>,
}

impl<'startup, 'resources> NixOfflineHardwareAttemptV5<'startup, 'resources> {
    /// Parks the actual startup loan and external fixed reservoirs without I/O.
    #[must_use]
    pub fn new(
        origin: OfflineNixHardwareOriginV5<'startup>,
        resources: &'resources mut NixOfflineHardwareResourcesV5,
    ) -> Self {
        Self {
            native: NixOfflineNativeJobV5::new(origin),
            resources: Some(resources),
            runs: Vec::new(),
            attempted: false,
            first_failure: None,
            terminal_failure: None,
            exchange_failure: None,
        }
    }

    /// Executes the one already selected, independently approved hardware job.
    ///
    /// # Errors
    /// Retains the first actual native, transport or process failure; its owner
    /// and every returned prefix remain resident. Caught unwind cannot retry.
    /// Application cutoffs bound admitted crossings, not blocking kernel/TSS
    /// calls, internal allocation, late wait completion or whole-tree Drain.
    ///
    /// # Panics
    /// Propagates an underlying unwind with this attempt already fenced. The
    /// installed caller keeps it and the external resources resident until exit.
    pub fn execute_once(&mut self) -> Result<(), &NixOfflineHardwareErrorV5> {
        if self.attempted {
            return Err(self.first_failure.get_or_insert(NixOfflineHardwareErrorV5::Fenced));
        }
        self.attempted = true;
        match self.execute_inner() {
            Ok(()) => Ok(()),
            Err(error) => Err(self.first_failure.get_or_insert(error)),
        }
    }

    /// Borrows the first outward cause without releasing any original owner.
    pub fn failure(&self) -> Option<&NixOfflineHardwareErrorV5> {
        self.first_failure.as_ref()
    }

    /// Borrows the actual native cause, including an original negative RESULT.
    pub fn native_failure(&self) -> Option<&NixOfflineNativeJobErrorV5> {
        self.native.failure()
    }

    /// Borrows an actual terminal-ACK failure without replacing the native cause.
    pub fn terminal_failure(&self) -> Option<&NixOfflineNativeJobErrorV5> {
        self.terminal_failure.as_ref()
    }

    fn execute_inner(&mut self) -> Result<(), NixOfflineHardwareErrorV5> {
        use NixOfflineHardwareErrorV5 as Error;

        self.runs.try_reserve_exact(10).map_err(io::Error::other)?;
        let resources = self.resources.take().ok_or(Error::Fenced)?;
        for phase in &mut resources.phases {
            phase.nonce.try_reserve_exact(32).map_err(io::Error::other)?;
            phase.nonce.resize(32, 0);
            phase.request.try_reserve_exact(2360).map_err(io::Error::other)?;
        }

        self.native.admit_original().map_err(|_| Error::Native)?;
        self.native.persist_admission().map_err(|_| Error::Native)?;

        for phase in resources.phases.iter_mut() {
            crate::entropy::fill_retained_nonzero(&mut phase.nonce).map_err(Error::Entropy)?;
            let nonce = phase.nonce.as_slice().try_into().map_err(|_| Error::Fenced)?;
            self.native.begin_contact(nonce).map_err(|_| Error::Native)?;
            self.native.prepare_launch(&mut phase.launch).map_err(|_| Error::Native)?;
            let contact = self.native.contact().map_err(Error::Launch)?;
            let slot = contact.coordinates().1;
            phase.hello.copy_from_slice(contact.hello());
            phase.request.extend_from_slice(contact.request());

            phase.pair.prepare().map_err(|_| Error::Pair)?;
            phase.endpoint = Some(phase.pair.take_child_endpoint().map_err(|_| Error::Pair)?);
            let socket = phase.pair.socket().map_err(|_| Error::Pair)?;
            phase.control = Some(
                rustix::io::fcntl_dupfd_cloexec(
                    socket.as_fd().map_err(|_| Error::Pair)?,
                    3,
                )
                .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?,
            );
            let control = phase.control.as_ref().ok_or(Error::Fenced)?.as_fd();
            let (run, locks) = phase.launch.retain_run(
                control,
                &mut phase.endpoint,
                &mut phase.capture,
            )
            .map_err(Error::Launch)?;

            // Park the complete actual run before any exec or exchange check.
            self.runs.push(run);
            let run = self.runs.last_mut().ok_or(Error::Fenced)?;
            let mut exchange = NixOfflineExchangeV5::new(
                socket,
                &phase.hello,
                &phase.request,
                locks,
            );

            run.prepare_live_child(&mut exchange).map_err(|_| Error::Process)?;
            self.native
                .observe_helper_before_hello(&run.child().map_err(|_| Error::Process)?)
                .map_err(|_| Error::Native)?;
            if run.run_to_reply(&mut exchange).map_err(|_| Error::Process)?.is_none() {
                return Err(Error::Process);
            }
            {
                let (child, acknowledgment) = run.reply_and_child().map_err(|_| Error::Process)?;
                self.native
                    .authorize_acknowledgment(exchange.socket(), acknowledgment, &child)
                    .map_err(|_| Error::Native)?;
            }

            run.resume_after_acknowledgment().map_err(|_| Error::Process)?;
            if let Err(error) = exchange.select_result_phase() {
                self.exchange_failure.get_or_insert(error);
                return Err(Error::Exchange);
            }
            if run.run_to_reply(&mut exchange).map_err(|_| Error::Process)?.is_none() {
                return Err(Error::Process);
            }
            let settled;
            {
                let (child, result) = run.reply_and_child().map_err(|_| Error::Process)?;
                settled = self.native.settle_contact(exchange.socket(), result, &child).is_ok();
                if let Err(error) = self.native.acknowledge_terminal(
                    exchange.socket(), result, &child,
                ) {
                    self.terminal_failure.get_or_insert(error);
                }
            }

            // The native first cause takes precedence over late ACK/wait causes.
            // The actual run still retains its first process failure and all
            // returned records. The same original P bounds this final wait.
            let finished = run.finish_same_child(&mut exchange).is_ok();
            if !settled || self.terminal_failure.is_some() {
                return Err(Error::Native);
            }
            if !finished {
                return Err(Error::Process);
            }
            self.native.retire_contact(run).map_err(|_| Error::Native)?;
            if slot == 10 {
                self.native.finish_job().map_err(|_| Error::Native)?;
                return Ok(());
            }
        }
        Err(Error::Fenced)
    }
}
