//! Authenticates actual positive native work before original response loss.
//!
//! The separate source-installed device writes only after consuming its first
//! original byte and holds completion on this source-owned stream. The reader
//! checks the original kernel enrollment, exact command/input/predecessor chain
//! and independent checksum before permitting the provider-only loss action.
//! It never supplies a completed window, capture or native-class certificate.

use std::{
    cell::{Cell, RefCell},
    io::Read,
    net::Shutdown,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    rc::Rc,
    time::Duration,
};

use crucible_node_contract::{Bytes, ResourceLimits, canonical};
use crucible_node_provider::{
    ProviderError,
    reference_device::{DeviceGrant, DeviceReceipt, NativeProgressRecord},
    reference_service::{InstalledContent, ReferenceProfile, ReferenceServiceBootstrap},
};
use rustix::event::{PollFd, PollFlags, poll};
use serde_json::{Value, json};

use super::{native::NativePublicEnrollment, package::InstalledPublicReferencePackage};
use crate::supervision::ProcessDeadline;

const MAXIMUM_PROGRESS_BYTES: usize = 65_536;

/// Binds the private progress candidate to its exact original host evidence.
///
/// The ordinary public launch binder deliberately refuses this separate profile.
/// This private source fixture creates only the host admission record; the
/// installation still regenerates the measured profile and authenticates every
/// original process before any execution. It issues no qualification verdict.
///
/// # Errors
/// Refuses malformed original authority, changed qualification/admission bytes,
/// invalid source binding or the private installed-content ceiling.
pub(super) fn bind_candidate(
    mut bootstrap: ReferenceServiceBootstrap,
    profile: &ReferenceProfile,
    qualification: InstalledContent,
) -> Result<
    (
        ReferenceServiceBootstrap,
        Vec<crucible_node_contract::ContentRef>,
    ),
    ProviderError,
> {
    use crucible_node_contract::{
        AdmissionRecord, ControlReceipt, ControlReceiptKind, Extensions, Id, ReceiptIssuer, U64,
        Validate,
    };

    bootstrap.validate()?;
    qualification
        .reference
        .verify(qualification.bytes.as_slice())?;
    let references = vec![qualification.reference.clone()];
    let (binding, _) = profile.bind_qualified(bootstrap.authority.clone(), &references)?;
    let admission = AdmissionRecord {
        schema_version: 1,
        realization_id: bootstrap.authority.realization_id.clone(),
        binding_hashes: vec![binding.identity()?],
        world_binding_hash: bootstrap.world_binding_hash.clone(),
        measured_artifacts: profile.implementation.artifacts.clone(),
        qualification_refs: references.clone(),
        resource_limits: bootstrap.resource_limits.clone(),
        evidence_refs: Vec::new(),
        extensions: Extensions::new(),
    };
    admission.validate()?;
    let record_ref = install_candidate_content(&mut bootstrap.installed_content, &admission)?;
    let receipt = ControlReceipt {
        schema_version: 1,
        kind: ControlReceiptKind::Admission,
        session_id: bootstrap.authority.session_id.clone(),
        incarnation_id: bootstrap.authority.incarnation_id.clone(),
        request_id: Id::new("private-admission")?,
        operation_id: None,
        owner_ids: vec![bootstrap.owner_id.clone()],
        world_generation: U64::new(0),
        record_ref,
        issuer: ReceiptIssuer::Host,
        extensions: Extensions::new(),
    };
    receipt.validate()?;
    let receipt_ref = install_candidate_content(&mut bootstrap.installed_content, &receipt)?;
    install_candidate_original(&mut bootstrap.installed_content, qualification)?;
    bootstrap.authority.host_receipt = receipt_ref.clone();
    bootstrap.admission_receipt = receipt_ref;
    bootstrap.validate()?;
    Ok((bootstrap, references))
}

fn install_candidate_content(
    contents: &mut Vec<InstalledContent>,
    value: &impl serde::Serialize,
) -> Result<crucible_node_contract::ContentRef, ProviderError> {
    let bytes = canonical::canonical_json(
        &serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?,
    )?;
    let reference = canonical::content_ref(&bytes, "application/json")?;
    install_candidate_original(
        contents,
        InstalledContent {
            reference: reference.clone(),
            bytes: Bytes::new(bytes),
        },
    )?;
    Ok(reference)
}

fn install_candidate_original(
    contents: &mut Vec<InstalledContent>,
    content: InstalledContent,
) -> Result<(), ProviderError> {
    content.reference.verify(content.bytes.as_slice())?;
    if let Some(original) = contents
        .iter()
        .find(|original| original.reference.hash == content.reference.hash)
    {
        if original.reference != content.reference || original.bytes != content.bytes {
            return Err(ProviderError::Conflict(
                "progress candidate original admission changed",
            ));
        }
        return Ok(());
    }
    if contents.len() >= 4096 {
        return Err(ProviderError::ResourceExhausted(
            "progress private installed evidence objects",
        ));
    }
    contents.push(content);
    Ok(())
}

/// Declares the source fixture before any original process is launched.
pub(super) fn fixture() -> Value {
    json!({
        "schema":"crucible.reference.native-progress-loss-fixture.v1",
        "node":"consumer","quantum":"1","consumed_prefix":"1",
        "dialect":"crucible.reference.native-progress.v1","launch_edition":5,
        "source_tuple":"independently pinned progress provider/device/closure",
        "proof":"actual native byte work before held completion; exact original Init/Ready/Stage/Activate/q0 Close+ACK",
        "input":"actual original frozen38bytes; full q1 completion remains unknown",
        "maximum_progress_bytes":MAXIMUM_PROGRESS_BYTES,"maximum_progress_records":1,
        "maximum_native_stream_wait_ns":"3000000000",
        "maximum_provider_terminal_wait_ns":"3000000000",
        "maximum_read_buffer_bytes":4096,"release":"never emitted in this loss fixture",
        "containment":"source-owned held stream shutdown after provider terminal, or on callback error/unwind; EOF exits the selected child without Completed",
        "loss":"first original CNP Begin written and fenced; positive native ledger verified before provider-only pidfd SIGKILL",
        "exclusions":["known full physical completion","reconnect","cancellation","whole-clause credit","ordinary Ready"]
    })
}

/// Keeps the separate endpoint and partial native ledger in original custody.
pub(super) struct SourceNativeProgressLoss {
    endpoint: PathBuf,
    package: Rc<InstalledPublicReferencePackage>,
    limits: ResourceLimits,
    origin: Rc<RefCell<Option<NativePublicEnrollment>>>,
    listener: RefCell<Option<UnixListener>>,
    stream: RefCell<Option<UnixStream>>,
    bytes: RefCell<Vec<u8>>,
    header: RefCell<[u8; 4]>,
    header_received: Cell<usize>,
    declared_length: Cell<Option<usize>>,
    started: Cell<bool>,
    containment_attempted: Cell<bool>,
    contained: Cell<bool>,
    stream_shutdown: Cell<bool>,
    listener_closed: Cell<bool>,
    original: RefCell<Option<Value>>,
}

impl SourceNativeProgressLoss {
    /// Reserves raw ledger credit before Child and before any native controls.
    pub(super) fn reserve(
        endpoint: PathBuf,
        package: Rc<InstalledPublicReferencePackage>,
        limits: ResourceLimits,
        origin: Rc<RefCell<Option<NativePublicEnrollment>>>,
    ) -> Result<Self, ProviderError> {
        if !endpoint.is_absolute() || endpoint.as_os_str().len() > 100 {
            return Err(refused("native progress endpoint geometry"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAXIMUM_PROGRESS_BYTES)
            .map_err(|_| ProviderError::ResourceExhausted("original native progress raw credit"))?;
        Ok(Self {
            endpoint,
            package,
            limits,
            origin,
            listener: RefCell::new(None),
            stream: RefCell::new(None),
            bytes: RefCell::new(bytes),
            header: RefCell::new([0; 4]),
            header_received: Cell::new(0),
            declared_length: Cell::new(None),
            started: Cell::new(false),
            containment_attempted: Cell::new(false),
            contained: Cell::new(false),
            stream_shutdown: Cell::new(false),
            listener_closed: Cell::new(false),
            original: RefCell::new(None),
        })
    }

    /// Returns operational endpoint data without exposing a stream or authority.
    pub(super) fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Installs the original private endpoint before its provider Child exists.
    pub(super) fn bind_before_child(&self) -> Result<(), ProviderError> {
        if self.listener.borrow().is_some() || self.started.get() {
            return Err(refused("native progress endpoint already installed"));
        }
        let listener = UnixListener::bind(&self.endpoint)?;
        listener.set_nonblocking(true)?;
        std::fs::set_permissions(&self.endpoint, std::fs::Permissions::from_mode(0o600))?;
        *self.listener.borrow_mut() = Some(listener);
        Ok(())
    }

    /// Authenticates the single actual consumed prefix without reading completion.
    ///
    /// Every failure retains the original stream and whatever original bytes
    /// were read. This method cannot re-enter to replace a failed observation.
    pub(super) fn read_positive(
        &self,
        grant: &DeviceGrant,
        input: &[u8],
        predecessor: &DeviceReceipt,
    ) -> Result<Value, ProviderError> {
        if self.started.replace(true) {
            return Err(refused(
                "original native progress attempt cannot be replaced",
            ));
        }
        let origin = self.origin.borrow();
        let origin = origin
            .as_ref()
            .ok_or(refused("original native progress enrollment absent"))?;
        origin.authenticate(&self.package, &self.limits)?;
        let companion = origin.original_companion_pid()?;
        let listener = self.listener.borrow();
        let listener = listener
            .as_ref()
            .ok_or(refused("original native progress listener absent"))?;
        let deadline = ProcessDeadline::after(Duration::from_secs(3))
            .ok_or(refused("native progress wait representation"))?;
        let timeout = rustix::time::Timespec::try_from(remaining(deadline)?)
            .map_err(|_| refused("native progress wait representation"))?;
        let mut descriptors = [PollFd::new(listener, PollFlags::IN)];
        if poll(&mut descriptors, Some(&timeout)).map_err(std::io::Error::from)? != 1 {
            return Err(refused("original native progress connection unavailable"));
        }
        let (stream, _) = listener.accept()?;
        // Retain the actual accepted stream before credential/parsing failures.
        *self.stream.borrow_mut() = Some(stream);
        let mut stream = self.stream.borrow_mut();
        let stream = stream
            .as_mut()
            .ok_or(refused("original native progress stream absent"))?;
        let credentials =
            rustix::net::sockopt::socket_peercred(&*stream).map_err(std::io::Error::from)?;
        if u32::try_from(credentials.pid.as_raw_nonzero().get()).ok() != Some(companion)
            || credentials.uid != rustix::process::getuid()
        {
            return Err(refused(
                "native progress peer differs from original companion",
            ));
        }
        let mut header = self.header.borrow_mut();
        let mut bytes = self.bytes.borrow_mut();
        read_original_frame(
            stream,
            &mut header,
            &self.header_received,
            &self.declared_length,
            &mut bytes,
            deadline,
        )?;
        let value = canonical::parse_json(&bytes, MAXIMUM_PROGRESS_BYTES)?;
        let record: NativeProgressRecord =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
        verify_original_record(&record, companion, grant, input, predecessor)?;
        // Measurement rechecks original PID/start/group/maps/limits after work.
        origin.authenticate(&self.package, &self.limits)?;
        let original = json!({
            "schema":"crucible.reference.actual-native-progress-loss.v1",
            "raw_header":Bytes::new(header.to_vec()),
            "raw_frame_body":Bytes::new(bytes.clone()),
            "raw_reference":canonical::content_ref(&bytes,"application/json")?,
            "record":record,"original_native_enrollment":origin,
            "actual_positive_native_work":true,"completion_read":false,
            "full_window_effect_knowledge":"UNKNOWN","release_sent":false
        });
        *self.original.borrow_mut() = Some(original.clone());
        Ok(original)
    }

    /// Retains planned stream containment across callback error or unwind.
    pub(super) fn contain_on_exit(&self) -> HeldProgressContainment<'_> {
        HeldProgressContainment(self)
    }

    /// Shuts down the original held stream without releasing native completion.
    ///
    /// The selected helper treats EOF as a failed latch, retaining its uncertain
    /// native command and exiting. The stream object and partial progress bytes
    /// stay owned here; no numeric process group is signaled after leader reap.
    ///
    /// # Errors
    /// Retains attempted containment and original custody if shutdown fails.
    pub(super) fn contain_held_original(&self) -> Result<(), ProviderError> {
        if self.containment_attempted.replace(true) {
            return if self.contained.get() {
                Ok(())
            } else {
                Err(refused("original progress stream containment unresolved"))
            };
        }
        // Closing the listener also refuses a queued or late original latch.
        // Accepted streams remain owned separately with their exact history.
        let listener = self.listener.borrow_mut().take();
        self.listener_closed.set(listener.is_some());
        drop(listener);
        if let Some(stream) = self.stream.borrow().as_ref() {
            stream.shutdown(Shutdown::Both)?;
            self.stream_shutdown.set(true);
        }
        self.contained.set(true);
        Ok(())
    }

    /// Retains partial/failing original observations without retrying the reader.
    pub(super) fn original(&self) -> Value {
        json!({
            "attempted":self.started.get(),"verified":self.original.borrow().as_ref(),
            "received_header":Bytes::new(self.header.borrow()[..self.header_received.get()].to_vec()),
            "declared_body_bytes":self.declared_length.get(),
            "received_bytes":Bytes::new(self.bytes.borrow().clone()),
            "containment_attempted":self.containment_attempted.get(),
            "containment_complete":self.contained.get(),
            "listener_closed":self.listener_closed.get(),
            "original_stream_shutdown":self.stream_shutdown.get(),"release_sent":false
        })
    }
}

fn read_original_frame(
    stream: &mut UnixStream,
    header: &mut [u8; 4],
    header_received: &Cell<usize>,
    declared_length: &Cell<Option<usize>>,
    bytes: &mut Vec<u8>,
    deadline: ProcessDeadline,
) -> Result<(), ProviderError> {
    while header_received.get() < header.len() {
        let count = read_original(stream, &mut header[header_received.get()..], deadline)?;
        header_received.set(header_received.get() + count);
        // Late bytes remain original custody but cannot satisfy the deadline.
        remaining(deadline)?;
    }
    let length = u32::from_be_bytes(*header) as usize;
    declared_length.set(Some(length));
    if length == 0 || length > MAXIMUM_PROGRESS_BYTES || bytes.capacity() < length {
        return Err(refused("native progress raw frame exceeds reserved credit"));
    }

    let mut buffer = [0_u8; 4096];
    while bytes.len() < length {
        let maximum = buffer.len().min(length - bytes.len());
        let count = read_original(stream, &mut buffer[..maximum], deadline)?;
        bytes.extend_from_slice(&buffer[..count]);
        remaining(deadline)?;
    }
    Ok(())
}

fn remaining(deadline: ProcessDeadline) -> Result<Duration, ProviderError> {
    let remaining = deadline.remaining();
    if remaining.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "native progress deadline expired",
        )
        .into());
    }
    Ok(remaining)
}

fn read_original(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    deadline: ProcessDeadline,
) -> Result<usize, ProviderError> {
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "original native progress frame incomplete",
                )
                .into());
            }
            Ok(count) => return Ok(count),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn verify_original_record(
    record: &NativeProgressRecord,
    companion: u32,
    grant: &DeviceGrant,
    input: &[u8],
    predecessor: &DeviceReceipt,
) -> Result<(), ProviderError> {
    let byte = input
        .first()
        .ok_or(refused("positive native progress input absent"))?;
    let expected = predecessor
        .output
        .checksum
        .get()
        .wrapping_mul(257)
        .wrapping_add(u64::from(*byte));
    if record.schema_version != 1
        || record.child_pid.get() != u64::from(companion)
        || &record.grant != grant
        || grant.quantum.get() != 1
        || record.consumed_prefix.get() != 1
        || record.checksum_before_window != predecessor.output.checksum
        || record.checksum_after_prefix.get() != expected
        || !predecessor.application_parked
        || predecessor.grant.quantum.get() != 0
        || predecessor.grant.owner_id != grant.owner_id
        || predecessor.grant.incarnation_id != grant.incarnation_id
        || predecessor.grant.generation != grant.generation
        || predecessor.output.bytes_processed.get() != 0
        || predecessor.output.checksum.get() != 0
    {
        return Err(refused(
            "original native progress grant/input/predecessor mismatch",
        ));
    }
    verify_command(
        &record.initialize_request,
        json!({"command":"initialize",
        "owner":grant.owner_id,"incarnation":grant.incarnation_id,"generation":grant.generation}),
    )?;
    verify_command(
        &record.ready_response,
        json!({"result":"ready",
        "owner":grant.owner_id,"incarnation":grant.incarnation_id,"generation":grant.generation,
        "child_pid":companion.to_string()}),
    )?;
    verify_command(
        &record.stage_request,
        json!({"command":"stage","grant":grant,"input":input}),
    )?;
    verify_command(
        &record.activate_request,
        json!({"command":"activate","window":grant.window_id}),
    )?;
    let previous = record.predecessor.0.as_ref().ok_or(refused(
        "original native progress predecessor custody missing",
    ))?;
    let window = &predecessor.grant.window_id;
    verify_command(
        &previous.stage_request,
        json!({"command":"stage","grant":predecessor.grant,"input":[]}),
    )?;
    verify_command(
        &previous.activate_request,
        json!({"command":"activate","window":window}),
    )?;
    verify_command(
        &previous.close_request,
        json!({"command":"close","window":window}),
    )?;
    verify_command(
        &previous.close_response,
        json!({"result":"closed","grant":predecessor.grant,
        "output":predecessor.output,"application_parked":true}),
    )?;
    verify_command(
        &previous.acknowledge_request,
        json!({"command":"acknowledge","window":window}),
    )?;
    verify_command(
        &previous.acknowledge_response,
        json!({"result":"acknowledged","window":window}),
    )?;
    Ok(())
}

fn verify_command(original: &Bytes, expected: Value) -> Result<(), ProviderError> {
    if original.as_slice() != canonical::canonical_json(&expected)? {
        return Err(refused("original native progress command material changed"));
    }
    Ok(())
}

fn refused(reason: &'static str) -> ProviderError {
    ProviderError::Correlation(reason)
}

/// Keeps the owning stream containment decision live throughout the loss hook.
pub(super) struct HeldProgressContainment<'a>(&'a SourceNativeProgressLoss);

impl Drop for HeldProgressContainment<'_> {
    fn drop(&mut self) {
        // Containment can fail without changing the original effect knowledge.
        // The actor and native queues retain the same stream and journals.
        let _ = self.0.contain_held_original();
    }
}

#[cfg(test)]
#[path = "source_native_progress_loss_tests.rs"]
mod tests;
