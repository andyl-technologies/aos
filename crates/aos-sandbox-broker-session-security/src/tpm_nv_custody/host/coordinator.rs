//! Owns the selected publisher's original signing and durable canary attempt.
//!
//! The private seed reservoir is constructed only beside genuine Core Origins.
//! Returned fixed ancestry/leaf descriptions and partial zeroizing reads stay
//! resident before metadata, name, decoder or postcheck failure. Core's same
//! credential engine supplies the closed protected-file UNIT comparison; no
//! key, preimage callback, descriptor role or signing authority is exported.
//!
//! ```text
//! /run/credentials/aos-sandbox-runtime-publisher.service/
//!     runtime-deployment-signing-seed-v1:32
//! ```

use std::error::Error;
use std::fs::File;
use std::os::fd::{AsFd as _, OwnedFd};

use aos_sandbox::{RuntimeDeploymentComparisonErrorV1, RuntimeDeploymentComparisonOriginsV1};
use aos_sandbox_linux::protected_file::{
    ExactReadFailure, open_nofollow_child, read_exact_positioned_retaining_cause,
};
use ed25519_dalek::SigningKey;
use rustix::fs::{Mode, OFlags};
use zeroize::Zeroizing;
use ed25519_dalek::Signer as _;
use sha2::{Digest as _, Sha256};

use aos_sandbox_linux::seqpacket::{
    RetainedSeqpacketAdmissionErrorV1, RetainedSeqpacketReceiveErrorV1, SeqpacketError,
};
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use aos_sandbox_protocol::runtime_deployment::canary::{
    ASSOCIATION_SIGNATURE_DOMAIN_V2, CURRENT_SIGNATURE_DOMAIN_V2,
    CanaryAssociationFieldsV2, CanaryAssociationV2, CanaryCurrentFieldsV2, CanaryCurrentV2,
    CanaryPublisherRequestV3, REPLY_BYTES_V2, REQUEST_BYTES_V3, association_transaction_v2,
};

const SIGNING_ROLE_V2: &str = "runtime-deployment-signing-seed-v1";
const SIGNING_ANCESTRY_V2: [&str; 3] = [
    "run", "credentials", "aos-sandbox-runtime-publisher.service",
];

// Core constructs this owning window only after authenticating the same request
// record and full job. Consuming its record loan ends that borrow before any
// whole-transport mutation; no sibling can fabricate or renew the window.
pub(in crate::tpm_nv_custody) use aos_sandbox::{
    RuntimeDeploymentOriginalWindowV3 as CanaryAuthenticatedRequestV3,
    RuntimeDeploymentOriginalClockCauseV3 as CanaryClockCauseV2,
};
use aos_sandbox::observe_original_runtime_deployment_clock_v3
    as original_clock_pair_v2;

#[derive(Debug, thiserror::Error)]
enum CanarySigningCauseV2 {
    #[error("selected signing original native observation failed")]
    Descriptor(#[from] rustix::io::Errno),
    #[error("selected signing original read failed")]
    Read(#[from] ExactReadFailure),
    #[error("selected signing original protected comparison failed")]
    Origins(#[from] RuntimeDeploymentComparisonErrorV1),
    #[error("selected signing original is incomplete, changed or fenced")]
    Changed,
}

/// Reports the authentic closed attempt cause and separate later observations.
///
/// Diagnostic aliases expose no retry, signer, key or original positive owner.
/// Rich native errors can retain their inherited screened partial descriptors.
/// Whole invocation custody ends only after the called terminal pass and then
/// ordinary scope Drop; this error does not promise continued custody or Drain.
#[derive(Debug)]
pub struct RuntimeDeploymentCanaryRunErrorV2 {
    first: CanaryPublisherCauseV2,
    later: [Option<CanaryPublisherCauseV2>; 16],
}

impl std::fmt::Display for RuntimeDeploymentCanaryRunErrorV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("selected runtime deployment canary attempt refused")
    }
}

impl Error for RuntimeDeploymentCanaryRunErrorV2 {
    fn source(&self) -> Option<&(dyn Error + 'static)> { Some(&self.first) }
}

#[derive(Debug, thiserror::Error)]
enum CanaryPublisherCauseV2 {
    #[error("original selected startup refused")]
    Startup(#[from] aos_sandbox::RuntimeDeploymentStartupErrorV1),
    #[error("original selected admission refused")]
    Admission(#[from] aos_sandbox::RuntimeDeploymentCanaryFailureV2),
    #[error("original selected Core comparison refused")]
    Comparison(#[from] RuntimeDeploymentComparisonErrorV1),
    #[error("original selected socket admission refused")]
    Accept(#[from] RetainedSeqpacketAdmissionErrorV1),
    #[error("original selected receive refused with retained custody")]
    Receive(#[from] RetainedSeqpacketReceiveErrorV1),
    #[error("original selected transport refused")]
    Transport(#[from] SeqpacketError),
    #[error("original selected received subject refused")]
    Subject(#[from] aos_sandbox_linux::seqpacket::RecordBindingError),
    #[error("original selected descriptor operation refused")]
    Descriptor(#[from] rustix::io::Errno),
    #[error("original selected protocol DATA refused")]
    Wire(#[from] aos_sandbox_protocol::runtime_deployment::DeploymentWireErrorV1),
    #[error("original selected signing refused")]
    Signing(#[from] CanarySigningDiagnosticV2),
    #[error("original selected physical action refused")]
    Physical(#[from] super::physical::CanaryPhysicalErrorV2),
    #[error("original selected physical preparation refused")]
    PhysicalPreparation(#[from] super::physical::PhysicalTpmFailureV1),
    #[error("original selected native owner refused")]
    Journal(#[from] super::HostOwnedJournalErrorV1),
    #[error("original selected journal admission refused")]
    JournalAdmission(#[from] super::journal::CanaryJournalAdmissionDiagnosticV2),
    #[error("original selected clock refused")]
    Clock(#[from] CanaryClockCauseV2),
    #[error("selected attempt has no authenticated original clock window")]
    AbsentWindow,
    #[error("selected attempt is incomplete or differs")]
    Changed,
    #[error("selected attempt was interrupted")]
    Unwind,
}

/// One terminal pass, with concrete bounded debt rather than an error pool.
struct CanaryPublisherLedgerV2 {
    first: Option<CanaryPublisherCauseV2>,
    later: [Option<CanaryPublisherCauseV2>; 16],
    count: usize,
    terminal: bool,
}

impl CanaryPublisherLedgerV2 {
    fn new() -> Self {
        Self {
            first: None,
            later: std::array::from_fn(|_| None),
            count: 0,
            terminal: false
        }
    }

    fn retain(&mut self, result: Result<(), CanaryPublisherCauseV2>) {
        if let Err(cause) = result {
            if self.first.is_none() {
                self.first = Some(cause);
            } else {
                let slot = self.later.get_mut(self.count).unwrap_or_else(|| std::process::abort());
                if slot.is_some() {
                    std::process::abort();
                }
                *slot = Some(cause);
                self.count += 1;
            }
        }
    }

    fn finish(self) -> Result<(), RuntimeDeploymentCanaryRunErrorV2> {
        match self.first {
            Some(first) => Err(RuntimeDeploymentCanaryRunErrorV2 {
                first,
                later: self.later
            }),
            None => Ok(()),
        }
    }
}

/// Parks native returned Results before classification or any owner bookend.
struct CanaryPublisherTransportV2 {
    accepted: Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
    received: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    shutdown_alias: Option<OwnedFd>,
    shutdown: Option<Result<(), rustix::io::Errno>>,
    receive_attempted: bool,
    failed: bool,
    ended: bool,
}

impl CanaryPublisherTransportV2 {
    fn new() -> Self {
        Self {
            accepted: None,
            received: None,
            shutdown_alias: None,
            shutdown: None,
            receive_attempted: false,
            failed: false,
            ended: false,
        }
    }

    fn accept(
        &mut self,
        startup: &aos_sandbox::ProductionRuntimeDeploymentStartupV1,
        listener: &mut aos_sandbox_linux::seqpacket::RecordSubjectListener
    ) -> Result<(), CanaryPublisherCauseV2> {
        if self.accepted.is_some() || self.failed || self.ended {
            return Err(CanaryPublisherCauseV2::Changed);
        }

        startup.require_canary_listener_v2(listener)?;
        self.accepted = Some(listener.accept_descriptor_subject_retaining());
        if let Some(Err(_)) = self.accepted.as_ref() {
            // Only the returned Err moves. The attempt tag stays irreversible;
            // successful originals never leave their resident native Result.
            self.failed = true;
            return match self.accepted.take() {
                Some(Err(cause)) => Err(cause.into()),
                _ => std::process::abort(),
            };
        }
        let socket = self.accepted.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CanaryPublisherCauseV2::Changed)?;
        // One safe alias of the SAME OFD is solely a negative shutdown handle.
        // Park it before any peer/packet check can fence the public as_fd loan.
        self.shutdown_alias = Some(rustix::io::dup(socket.as_fd()?)?);

        startup.require_canary_listener_v2(listener)?;
        Ok(())
    }

    fn receive(&mut self) -> Result<(), CanaryPublisherCauseV2> {
        if self.receive_attempted || self.failed || self.ended {
            return Err(CanaryPublisherCauseV2::Changed);
        }

        self.receive_attempted = true;
        let socket = self.accepted.as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(CanaryPublisherCauseV2::Changed)?;
        socket.provision_packet_capacity(REPLY_BYTES_V2)?;
        self.received = Some(socket.receive_optional_descriptor_reply_retaining(REQUEST_BYTES_V3));
        if let Some(Err(_)) = self.received.as_ref() {
            self.failed = true;
            return match self.received.take() {
                Some(Err(cause)) => Err(cause.into()),
                _ => std::process::abort(),
            };
        }
        Ok(())
    }

    fn originals(&mut self) -> Result<(&mut DescriptorSubjectSocket, &ReceivedDescriptorRecord), CanaryPublisherCauseV2> {
        let socket = self.accepted.as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(CanaryPublisherCauseV2::Changed)?;
        let record = self.received.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CanaryPublisherCauseV2::Changed)?;
        Ok((socket, record))
    }

    fn terminal_observations(&mut self, ledger: &mut CanaryPublisherLedgerV2) {
        if let Some(Ok(socket)) = self.accepted.as_mut() {
            ledger.retain(socket.as_fd().map(|_| ()).map_err(Into::into));
            if let Some(Ok(record)) = self.received.as_ref() {
                ledger.retain(socket.validate_received_origin_retaining(record).map_err(Into::into));
            }
        }
    }

    fn end(&mut self, ledger: &mut CanaryPublisherLedgerV2) {
        if self.ended {
            return;
        }
        self.ended = true;
        if let Some(alias) = self.shutdown_alias.as_ref() {
            self.shutdown = Some(rustix::net::shutdown(alias, rustix::net::Shutdown::Both));
            if let Some(Err(_)) = self.shutdown.as_ref() {
                match self.shutdown.take() {
                    Some(Err(cause)) => ledger.retain(Err(cause.into())),
                    _ => std::process::abort(),
                }
            }
        } else if let Some(Ok(socket)) = self.accepted.as_mut() {
            socket.close();
        }
    }
}

impl Drop for CanaryPublisherTransportV2 {
    fn drop(&mut self) {
        // Scope this fence to this endpoint's fields. Nested physical/receive
        // destructors retain their own documented order and failure limits.
        if !self.ended {
            if let Some(alias) = self.shutdown_alias.as_ref() {
                self.shutdown = Some(rustix::net::shutdown(alias, rustix::net::Shutdown::Both));
            } else if let Some(Ok(socket)) = self.accepted.as_mut() {
                socket.close();
            }
            self.ended = true;
        }
    }
}


#[derive(Clone, Debug)]
struct CanarySigningDiagnosticV2 {
    cause: std::sync::Arc<Option<CanarySigningCauseV2>>,
}

impl std::fmt::Display for CanarySigningDiagnosticV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("selected signing original is permanently fenced")
    }
}

impl Error for CanarySigningDiagnosticV2 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause.as_ref().as_ref().map(|cause| cause as &(dyn Error + 'static))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SigningPhaseV2 {
    Empty,
    Capturing,
    Ready,
    Comparing,
    Failed,
}

/// Keeps the extra original seed OFD distinct from Core's five input originals.
///
/// The component can hold four initial ancestry Files, one initial leaf, four
/// named-comparison ancestors and one comparison leaf. Two fixed zeroizing
/// buffers and the private Dalek key are additional residents. This inventory
/// is not a physical-memory, whole-invocation funding or Drain proof.
struct CanarySigningOriginalV2<'origin, 'startup> {
    origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    ancestors: [Option<File>; 4],
    leaf: Option<File>,
    named_ancestors: [Option<File>; 4],
    named_leaf: Option<File>,
    seed: Zeroizing<[u8; 32]>,
    readback: Zeroizing<[u8; 32]>,
    key: Option<SigningKey>,
    phase: SigningPhaseV2,
    first_failure: std::sync::Arc<Option<CanarySigningCauseV2>>,
    post_debt: [Option<CanarySigningCauseV2>; 16],
    debt_count: usize,
}

impl<'origin, 'startup> CanarySigningOriginalV2<'origin, 'startup> {
    fn new(origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>) -> Self {
        Self {
            origins,
            ancestors: std::array::from_fn(|_| None),
            leaf: None,
            named_ancestors: std::array::from_fn(|_| None),
            named_leaf: None,
            seed: Zeroizing::new([0; 32]),
            readback: Zeroizing::new([0; 32]),
            key: None,
            phase: SigningPhaseV2::Empty,
            first_failure: std::sync::Arc::new(None),
            post_debt: std::array::from_fn(|_| None),
            debt_count: 0,
        }
    }

    /// Arms before the first open; a returned failure never extracts custody.
    fn capture_once(&mut self) -> Result<(), CanarySigningDiagnosticV2> {
        if self.first_failure.is_some() {
            return Err(self.diagnostic());
        }
        self.require_vacant_failure();
        let result = if self.phase != SigningPhaseV2::Empty || self.first_failure.is_some() {
            Err(CanarySigningCauseV2::Changed)
        } else {
            self.phase = SigningPhaseV2::Capturing;
            self.capture_inner()
        };
        self.finish_original_action(result)
    }

    /// Preserves failed named opens/readback until deliberate invocation end.
    fn recheck(&mut self) -> Result<(), CanarySigningDiagnosticV2> {
        if self.first_failure.is_some() {
            return Err(self.diagnostic());
        }
        self.require_vacant_failure();
        let result = if self.phase != SigningPhaseV2::Ready || self.first_failure.is_some()
            || self.named_leaf.is_some() || self.named_ancestors.iter().any(Option::is_some)
            || self.debt_count > self.post_debt.len() - 2
        {
            Err(CanarySigningCauseV2::Changed)
        } else {
            self.phase = SigningPhaseV2::Comparing;
            self.recheck_inner()
        };
        self.finish_original_action(result)
    }

    fn capture_inner(&mut self) -> Result<(), CanarySigningCauseV2> {
        self.origins.recheck()?;
        if self.origins.canary_purpose_v2().is_none() || self.leaf.is_some()
            || self.key.is_some() || self.ancestors.iter().any(Option::is_some)
        {
            return Err(CanarySigningCauseV2::Changed);
        }
        open_signing_ancestry_v2(&mut self.ancestors)?;
        let directory = self.ancestors[3].as_ref().ok_or(CanarySigningCauseV2::Changed)?;
        self.leaf = Some(File::from(open_nofollow_child(directory, SIGNING_ROLE_V2)?));
        let leaf = self.leaf.as_ref().ok_or(CanarySigningCauseV2::Changed)?;

        // The Core RefCell loan ends inside this UNIT comparator. The actual
        // returned seed File remains here before the first secret read.
        self.origins.compare_canary_signing_original_v2(directory, leaf)?;
        read_exact_positioned_retaining_cause(leaf, &mut self.seed[..])?;
        self.key = Some(SigningKey::from_bytes(&self.seed));
        if *self.seed == [0; 32]
            || self.key.as_ref().ok_or(CanarySigningCauseV2::Changed)?
                .verifying_key().to_bytes() != self.origins.genesis_claims().signer
        {
            return Err(CanarySigningCauseV2::Changed);
        }
        self.origins.compare_canary_signing_original_v2(directory, leaf)?;
        self.origins.recheck()?;
        Ok(())
    }

    fn recheck_inner(&mut self) -> Result<(), CanarySigningCauseV2> {
        self.compare_originals()?;
        open_signing_ancestry_v2(&mut self.named_ancestors)?;
        for (original, named) in self.ancestors.iter().zip(&self.named_ancestors) {
            let original = original.as_ref().ok_or(CanarySigningCauseV2::Changed)?;
            let named = named.as_ref().ok_or(CanarySigningCauseV2::Changed)?;
            let before = rustix::fs::fstat(original)?;
            let after = rustix::fs::fstat(named)?;
            if before.st_dev != after.st_dev || before.st_ino != after.st_ino {
                return Err(CanarySigningCauseV2::Changed);
            }
        }
        let directory = self.named_ancestors[3].as_ref()
            .ok_or(CanarySigningCauseV2::Changed)?;
        self.named_leaf = Some(File::from(open_nofollow_child(directory, SIGNING_ROLE_V2)?));
        let leaf = self.named_leaf.as_ref().ok_or(CanarySigningCauseV2::Changed)?;
        self.origins.compare_canary_signing_original_v2(directory, leaf)?;
        read_exact_positioned_retaining_cause(leaf, &mut self.readback[..])?;
        if self.readback != self.seed {
            return Err(CanarySigningCauseV2::Changed);
        }
        self.compare_originals()?;
        Ok(())
    }

    fn compare_originals(&self) -> Result<(), CanarySigningCauseV2> {
        let directory = self.ancestors[3].as_ref().ok_or(CanarySigningCauseV2::Changed)?;
        let leaf = self.leaf.as_ref().ok_or(CanarySigningCauseV2::Changed)?;
        self.origins.compare_canary_signing_original_v2(directory, leaf)?;
        if self.key.as_ref().ok_or(CanarySigningCauseV2::Changed)?
            .verifying_key().to_bytes() != self.origins.genesis_claims().signer
        {
            return Err(CanarySigningCauseV2::Changed);
        }
        Ok(())
    }

    fn finish_original_action(
        &mut self,
        result: Result<(), CanarySigningCauseV2>,
    ) -> Result<(), CanarySigningDiagnosticV2> {
        // Park the chronological action/read error before either independent
        // post. A later refusal is separate debt, never a replacement cause.
        if let Err(error) = result {
            self.phase = SigningPhaseV2::Failed;
            self.park_first(error);
        }
        let origins = self.origins.recheck().map_err(CanarySigningCauseV2::from);
        self.retain_post(origins);
        if self.leaf.is_some() && self.ancestors[3].is_some() {
            let original = self.compare_originals();
            self.retain_post(original);
        }

        if self.first_failure.is_some() {
            self.phase = SigningPhaseV2::Failed;
            return Err(self.diagnostic());
        }

        // No fallible bookend follows this success-only comparison release.
        // A failure or unwind above keeps every returned comparison File.
        self.named_leaf = None;
        for ancestor in &mut self.named_ancestors {
            *ancestor = None;
        }
        self.readback.fill(0);
        self.phase = SigningPhaseV2::Ready;
        Ok(())
    }

    fn retain_post(&mut self, result: Result<(), CanarySigningCauseV2>) {
        if let Err(error) = result {
            self.phase = SigningPhaseV2::Failed;
            if self.first_failure.is_none() {
                self.park_first(error);
            } else if let Some(slot) = self.post_debt.get_mut(self.debt_count) {
                *slot = Some(error);
                self.debt_count += 1;
            } else {
                // Capacity is checked before either original observation and
                // failure forbids another crossing. An internal invariant
                // violation must not drop this cause or any original owner.
                std::process::abort();
            }
        }
    }

    fn require_vacant_failure(&mut self) {
        if self.first_failure.is_some() || std::sync::Arc::get_mut(&mut self.first_failure).is_none() {
            std::process::abort();
        }
    }

    fn park_first(&mut self, cause: CanarySigningCauseV2) {
        let slot = std::sync::Arc::get_mut(&mut self.first_failure)
            .unwrap_or_else(|| std::process::abort());
        if slot.is_some() {
            std::process::abort();
        }
        *slot = Some(cause);
    }

    fn diagnostic(&self) -> CanarySigningDiagnosticV2 {
        if self.first_failure.is_none() {
            std::process::abort();
        }
        CanarySigningDiagnosticV2 { cause: std::sync::Arc::clone(&self.first_failure) }
    }
}

/// Opens only the compiled ancestry, parking each returned File before fstat.
fn open_signing_ancestry_v2(
    slots: &mut [Option<File>; 4],
) -> Result<(), CanarySigningCauseV2> {
    if slots.iter().any(Option::is_some) {
        return Err(CanarySigningCauseV2::Changed);
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    slots[0] = Some(File::from(rustix::fs::open("/", flags, Mode::empty())?));
    for index in 0..4 {
        let directory = slots[index].as_ref().ok_or(CanarySigningCauseV2::Changed)?;
        let stat = rustix::fs::fstat(directory)?;
        if stat.st_uid != 0 || stat.st_gid != 0 || stat.st_mode & 0o022 != 0 {
            return Err(CanarySigningCauseV2::Changed);
        }
        if index < SIGNING_ANCESTRY_V2.len() {
            let opened = rustix::fs::openat(
                directory, SIGNING_ANCESTRY_V2[index], flags, Mode::empty(),
            )?;
            slots[index + 1] = Some(File::from(opened));
        }
    }
    Ok(())
}

/// Runs one genuine selected association attempt on the original startup parts.
///
/// The mode, roles, full job and existing writers are authenticated by their
/// same retained owners. Missing independent provisioning is refused, never
/// installed here. Success is one association/current reply, not public runtime
/// admission, generation-zero initialization, Root ACK, full funding or Drain.
///
/// # Errors
/// Returns the authentic first admission, transport, native, physical, signing
/// or clock cause after the one terminal pass and original endpoint fence.
/// Later observation/shutdown failures remain separate bounded debt. A caught
/// unwind is terminal; no owner is reopened, renewed, readmitted or retried.
pub fn run_runtime_deployment_canary_once_v2(
    parts: &mut aos_sandbox::ProductionRuntimeDeploymentStartupPartsV1,
) -> Result<(), RuntimeDeploymentCanaryRunErrorV2> {
    let mut ledger = CanaryPublisherLedgerV2::new();
    let mut transport = CanaryPublisherTransportV2::new();
    let mut admission = aos_sandbox::RuntimeDeploymentComparisonOriginsV1::capture_canary_v2(&parts.startup);
    let admitted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| admission.admit_once()));
    ledger.retain(match admitted {
        Ok(result) => result.map_err(Into::into),
        Err(_) => Err(CanaryPublisherCauseV2::Unwind),
    });
    if ledger.first.is_some() {
        finish_terminal_v2(&parts.startup, None, None, &mut transport, &mut ledger, None);
        return ledger.finish();
    }
    let origins = admission.origins().unwrap_or_else(|| std::process::abort());

    // Empty typed destinations are allocated before their component effects.
    // The same original credential component remains inside admitted Origins.
    let mut signing = CanarySigningOriginalV2::new(origins);
    let delegate = origins.capture_storage_delegate_v2();
    let mut delegate = match delegate {
        Ok(delegate) => delegate,
        Err(cause) => {
            ledger.retain(Err(cause.into()));
            finish_terminal_v2(&parts.startup, Some(origins), None, &mut transport, &mut ledger, None);
            return ledger.finish();
        }
    };
    let mut journals = super::journal::HostCanaryJournalAdmissionV2::new(origins);
    let mut original = None;

    // Park the sole decode in Core at the old upper-decode frontier, then end
    // this mutable transport catch before authenticating the same request.
    let prefix = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        signing.capture_once()?;
        transport.accept(&parts.startup, &mut parts.listener)?;
        transport.receive()?;
        {
            let (_, record) = transport.originals()?;
            delegate.prepare_original_request_once(record)?;
        }
        Ok::<(), CanaryPublisherCauseV2>(())
    }));
    ledger.retain(match prefix {
        Ok(result) => result,
        Err(_) => Err(CanaryPublisherCauseV2::Unwind),
    });

    if ledger.first.is_none() {
        // The returned loan borrows only the immutable received record, not
        // the disjoint accepted socket or mutable delegate captured here.
        let accepted = &mut transport.accepted;
        let received = &transport.received;
        let mut captured = None;
        let prepared = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let socket = publisher_socket_v2(accepted)?;
            let record = publisher_record_v2(received)?;
            captured = Some(delegate.capture_original_request_once(socket, record));

            let loan = match captured.take() {
                Some(Ok(loan)) => loan,
                Some(Err(cause)) => return Err(cause.into()),
                None => return Err(CanaryPublisherCauseV2::Changed),
            };
            original = Some(loan.into_original_window());

            origins.recheck()?;
            journals.admit_once()?;
            Ok::<(), CanaryPublisherCauseV2>(())
        }));

        // Preserve an earlier returned result if unwind interrupted its pure
        // handoff. The actual error precedes Unwind; success keeps its window.
        if let Some(result) = captured.take() {
            match result {
                Ok(loan) => original = Some(loan.into_original_window()),
                Err(cause) => ledger.retain(Err(cause.into())),
            }
        }
        ledger.retain(match prepared {
            Ok(result) => result,
            Err(_) => Err(CanaryPublisherCauseV2::Unwind),
        });
    }

    if ledger.first.is_some() {
        if delegate.first_failure().is_none() && transport.received.as_ref().is_some_and(Result::is_ok) {
            let observed = match transport.originals() {
                Ok((socket, record)) => match original.as_ref() {
                    Some(original) => delegate.recheck_original_request(socket, record, original),
                    None => delegate.recheck(socket, record),
                }.map_err(Into::into),
                Err(cause) => Err(cause),
            };
            ledger.retain(observed);
        }
        finish_terminal_v2(&parts.startup, Some(origins), Some(&mut signing),
            &mut transport, &mut ledger, original.as_ref().map(|loan| loan.request()));
        return ledger.finish();
    }

    let original = original.unwrap_or_else(|| std::process::abort());
    let request = original.request();
    let record = publisher_record_v2(&transport.received).unwrap_or_else(|_| std::process::abort());
    let owner = match journals.owner_mut() {
        Ok(owner) => owner,
        Err(cause) => {
            ledger.retain(Err(cause.into()));
            finish_terminal_v2(&parts.startup, Some(origins), Some(&mut signing),
                &mut transport, &mut ledger, Some(request));
            return ledger.finish();
        }
    };
    let mut physical = super::physical::HostCanaryPhysicalConsumerV2::retain(owner);
    let mut association = None;
    let mut transaction = None;
    let mut association_signature = None;
    let mut current_signature = None;
    let mut current = None;
    let mut reply = [0; REPLY_BYTES_V2];

    let effected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        physical.prepare_once()?;
        delegate.recheck_original_request(publisher_socket_v2(&mut transport.accepted)?, record, &original)?;
        signing.recheck()?;
        original.require_clock()?;
        if physical.admit(&original)? != crate::tpm_nv_custody::FloorRecoveryV1::Current {
            return Err(CanaryPublisherCauseV2::Changed);
        }
        let before = physical.main_data(&original)?;
        let ordinal = before.last.as_ref().map_or(Ok(1), |last| last.fields().ordinal.checked_add(1)
            .ok_or(CanaryPublisherCauseV2::Changed))?;
        let genesis = origins.genesis_claims();
        let purpose = origins.canary_purpose_v2().ok_or(CanaryPublisherCauseV2::Changed)?;
        let mut fields = CanaryAssociationFieldsV2 {
            purpose: purpose.digest(),
            genesis: Sha256::digest(origins.signed_genesis()).into(),
            node: genesis.node,
            deployment: genesis.deployment,
            ordinal,
            attempt: [0; 16],
            boot: request.boot,
            not_before: request.not_before,
            deadline: request.deadline,
            job_digest: [0; 32],
            request_digest: [0; 32],
            storage_invocation: [0; 16],
            storage_pid: 0,
            storage_start_ticks: 0,
            storage_profile: [0; 32],
            storage_policy: [0; 32],
            storage: request.storage,
            marker_transaction: [0; 16],
            marker_digest: [0; 32],
            held_identity: [0; 32],
            previous_association: before.last.as_ref().map_or([0; 32], CanaryAssociationV2::digest),
            main_next: before.stored.current.sequence(),
            main_head: before.stored.current.head(),
            main_transaction: [0; 16],
            publisher_profile: genesis.publisher_profile,
            publisher_policy: genesis.mac_policy,
            nonce: request.nonce,
        };

        delegate.fill_original_association_data_v2(&original, &mut fields)?;
        fields.main_transaction = association_transaction_v2(fields.purpose, fields.request_digest,
            fields.storage.primary_head, fields.main_head, fields.ordinal)?;
        let body = fields.encode_body()?;
        let mut preimage = [0; ASSOCIATION_SIGNATURE_DOMAIN_V2.len() + 712];
        preimage[..ASSOCIATION_SIGNATURE_DOMAIN_V2.len()].copy_from_slice(ASSOCIATION_SIGNATURE_DOMAIN_V2);
        preimage[ASSOCIATION_SIGNATURE_DOMAIN_V2.len()..].copy_from_slice(&body);
        if association_signature.is_some() || association.is_some() || transaction.is_some() {
            return Err(CanaryPublisherCauseV2::Changed);
        }

        // Every field/codec/digest/reserve and expensive original comparison
        // precedes the final same-boot/B/D sample. Only crypto plus an infallible
        // fixed-slot park follows it. Synchronous scheduling straddles remain.
        signing.recheck()?;
        origins.recheck()?;
        delegate.recheck_original_request(publisher_socket_v2(&mut transport.accepted)?, record, &original)?;
        physical.terminal_observations(&original)?;
        let key = signing.key.as_ref().ok_or(CanaryPublisherCauseV2::Changed)?;
        original.require_clock()?;
        association_signature = Some(key.sign(&preimage).to_bytes());

        // The signature is resident before any independent post observation.
        // A post failure stops this closure, but cannot skip the other owners.
        ledger.retain(signing.recheck().map_err(Into::into));
        ledger.retain(origins.recheck().map_err(Into::into));
        let delegate_post = match publisher_socket_v2(&mut transport.accepted) {
            Ok(socket) => delegate.recheck_original_request(socket, record, &original).map_err(Into::into),
            Err(cause) => Err(cause),
        };
        ledger.retain(delegate_post);
        ledger.retain(physical.terminal_observations(&original).map_err(Into::into));
        if ledger.first.is_some() {
            return Ok(());
        }

        association = Some(CanaryAssociationV2::from_signed_parts(fields,
            association_signature.unwrap_or_else(|| std::process::abort()))?);
        let row = association.as_ref().ok_or(CanaryPublisherCauseV2::Changed)?;
        let fields = row.fields();
        let mut name = [0; 10];
        name[0] = b'c';
        name[1..9].copy_from_slice(&ordinal.to_be_bytes());
        name[9] = 1;
        transaction = Some(aos_sandbox::JournalTransaction::new(fields.main_transaction, vec![
            aos_sandbox::JournalRecord::put(aos_sandbox::RecordNamespace::HostCatalogReconciliation,
                name.to_vec(), row.bytes().to_vec()),
        ]).map_err(super::HostOwnedJournalErrorV1::from)?);
        let saved = transaction.as_ref().ok_or(CanaryPublisherCauseV2::Changed)?;

        delegate.recheck_original_request(publisher_socket_v2(&mut transport.accepted)?, record, &original)?;
        signing.recheck()?;
        let intent = physical.fund(saved, &original)?;
        delegate.recheck_original_request(publisher_socket_v2(&mut transport.accepted)?, record, &original)?;
        physical.commit(super::journal::CanaryHostNativeStepV2::Prepare, saved, &original)?;
        delegate.recheck_original_request(publisher_socket_v2(&mut transport.accepted)?, record, &original)?;
        physical.extend(saved, &original)?;
        for step in [super::journal::CanaryHostNativeStepV2::Main,
            super::journal::CanaryHostNativeStepV2::Finalize]
        {
            delegate.recheck_original_request(publisher_socket_v2(&mut transport.accepted)?, record, &original)?;
            physical.commit(step, saved, &original)?;
        }
        delegate.recheck_original_request(publisher_socket_v2(&mut transport.accepted)?, record, &original)?;
        if physical.classify(&original)? != crate::tpm_nv_custody::FloorRecoveryV1::Current {
            return Err(CanaryPublisherCauseV2::Changed);
        }
        let completed = physical.main_data(&original)?;
        if completed.stored.prepared.is_some()
            || completed.stored.current != intent.target().cut()
            || completed.last.as_ref().is_none_or(|last| last.bytes() != row.bytes())
        {
            return Err(CanaryPublisherCauseV2::Changed);
        }
        let receipt_fields = CanaryCurrentFieldsV2 {
            purpose: fields.purpose, association: row.digest(), nonce: fields.nonce,
            job_digest: fields.job_digest, node: fields.node, deployment: fields.deployment,
            attempt: fields.attempt, ordinal: fields.ordinal,
            main_next: completed.stored.current.sequence(), main_head: completed.stored.current.head(),
            fresh_nv: physical.final_nv()?, boot: fields.boot,
            not_before: fields.not_before, deadline: fields.deadline,
        };
        let receipt_body = receipt_fields.encode_body()?;
        let mut current_preimage = [0; CURRENT_SIGNATURE_DOMAIN_V2.len() + 304];
        current_preimage[..CURRENT_SIGNATURE_DOMAIN_V2.len()].copy_from_slice(CURRENT_SIGNATURE_DOMAIN_V2);
        current_preimage[CURRENT_SIGNATURE_DOMAIN_V2.len()..].copy_from_slice(&receipt_body);
        if current_signature.is_some() || current.is_some() {
            return Err(CanaryPublisherCauseV2::Changed);
        }
        signing.recheck()?;
        origins.recheck()?;
        delegate.recheck_original_request(publisher_socket_v2(&mut transport.accepted)?, record, &original)?;
        physical.terminal_observations(&original)?;
        let key = signing.key.as_ref().ok_or(CanaryPublisherCauseV2::Changed)?;
        original.require_clock()?;
        current_signature = Some(key.sign(&current_preimage).to_bytes());

        ledger.retain(signing.recheck().map_err(Into::into));
        ledger.retain(origins.recheck().map_err(Into::into));
        let delegate_post = match publisher_socket_v2(&mut transport.accepted) {
            Ok(socket) => delegate.recheck_original_request(socket, record, &original).map_err(Into::into),
            Err(cause) => Err(cause),
        };
        ledger.retain(delegate_post);
        ledger.retain(physical.terminal_observations(&original).map_err(Into::into));
        if ledger.first.is_some() {
            return Ok(());
        }
        current = Some(CanaryCurrentV2::from_signed_parts(receipt_fields,
            current_signature.unwrap_or_else(|| std::process::abort()))?);
        let receipt = current.as_ref().ok_or(CanaryPublisherCauseV2::Changed)?;
        reply[..776].copy_from_slice(row.bytes());
        reply[776..].copy_from_slice(receipt.bytes());

        signing.recheck()?;
        origins.recheck()?;
        delegate.recheck_original_request(publisher_socket_v2(&mut transport.accepted)?, record, &original)?;
        physical.terminal_observations(&original)?;
        original.require_clock()?;
        publisher_socket_v2(&mut transport.accepted)?.send_retaining(&reply)?;
        Ok::<(), CanaryPublisherCauseV2>(())
    }));
    ledger.retain(match effected {
        Ok(result) => result,
        Err(_) => Err(CanaryPublisherCauseV2::Unwind),
    });

    // The physical owner and both original writers remain resident here. A
    // failed action's same inner pass is reused, not readmitted or duplicated.
    if !matches!(ledger.first.as_ref(), Some(CanaryPublisherCauseV2::Physical(_))) {
        ledger.retain(physical.terminal_observations(&original).map_err(Into::into));
    }
    if delegate.first_failure().is_none() {
        let delegate_post = match publisher_socket_v2(&mut transport.accepted) {
            Ok(socket) => delegate.recheck_original_request(socket, record, &original).map_err(Into::into),
            Err(cause) => Err(cause),
        };
        ledger.retain(delegate_post);
    }
    finish_terminal_v2(&parts.startup, Some(origins), Some(&mut signing),
        &mut transport, &mut ledger, Some(request));
    ledger.finish()
}

fn publisher_socket_v2(
    slot: &mut Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
) -> Result<&mut DescriptorSubjectSocket, CanaryPublisherCauseV2> {
    slot.as_mut().and_then(|result| result.as_mut().ok()).ok_or(CanaryPublisherCauseV2::Changed)
}

fn publisher_record_v2(
    slot: &Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
) -> Result<&ReceivedDescriptorRecord, CanaryPublisherCauseV2> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(CanaryPublisherCauseV2::Changed)
}

/// Runs the fixed outer terminal groups once, with the genuine clock last.
fn finish_terminal_v2(
    startup: &aos_sandbox::ProductionRuntimeDeploymentStartupV1,
    origins: Option<&RuntimeDeploymentComparisonOriginsV1<'_>>,
    signing: Option<&mut CanarySigningOriginalV2<'_, '_>>,
    transport: &mut CanaryPublisherTransportV2,
    ledger: &mut CanaryPublisherLedgerV2,
    authenticated_request: Option<&CanaryPublisherRequestV3>,
) {
    if ledger.terminal {
        std::process::abort();
    }
    ledger.terminal = true;
    ledger.retain(startup.recheck().map_err(Into::into));
    if let Some(origins) = origins {
        ledger.retain(origins.recheck().map_err(Into::into));
    }
    if let Some(signing) = signing {
        if signing.first_failure.is_none() && signing.phase != SigningPhaseV2::Empty {
            ledger.retain(signing.recheck().map_err(Into::into));
        }
    }
    transport.terminal_observations(ledger);
    // This always attempts actual boot AND BOOTTIME, even after schema/owner
    // poison. Unauthenticated DATA supplies no invented original window.
    let observed = original_clock_pair_v2();
    ledger.retain(match observed {
        Err(cause) => Err(cause.into()),
        Ok((boot, now)) => match authenticated_request {
            Some(request) if boot == request.boot && now >= request.not_before && now < request.deadline => Ok(()),
            Some(_) => Err(CanaryClockCauseV2::Changed.into()),
            None => Err(CanaryPublisherCauseV2::AbsentWindow),
        },
    });
    transport.end(ledger);
}
