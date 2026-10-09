//! Retains the original private issuer's direct child before postchecks.
//!
//! The process-lifetime slot preserves actual non-Clone work and cleanup causes.
//! Its source backing and every covered effect still require genuine external
//! Source/preloader/control credit through owned-VM teardown. That issuer is
//! retained outside this process. The fixed parent channel is verified before
//! listener, invocation-record or child birth; absent evidence refuses.

use super::*;
use std::fmt;
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, ExitStatus};
use std::sync::Mutex;

static ISSUER: Mutex<IssuerRecord> = Mutex::new(IssuerRecord::empty());

/// Reports a private issuer refusal while its actual causes remain retained.
///
/// Formatting borrows the original non-Clone causes while holding their slot.
/// This closed handle exposes no process, resource grant or borrowed error
/// reference. It does not implement an error-chain projection across that lock.
#[derive(Debug)]
pub struct IssuerCustodyRefusal {
    _private: (),
}

impl fmt::Display for IssuerCustodyRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let owner = ISSUER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        owner.format_refusal(formatter)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IssuerState {
    Empty,
    Prepared,
    Born,
    DirectReaped,
    Quarantined,
}

struct IssuerRecord {
    interval: Option<OriginalInterval>,
    state: IssuerState,
    child: Option<Child>,
    status: Option<ExitStatus>,
    listener: Option<UnixListener>,
    policy_file: Option<File>,
    actor_file: Option<File>,
    record: Option<File>,
    peer: Option<UnixStream>,
    policy: Option<OperatorPolicy>,
    parent: Option<issuer_parent::ParentBinding>,
    birth: Option<issuer_birth::ActorBirth>,
    first_work: Option<MeasurementOriginError>,
    kill_failure: Option<std::io::Error>,
    wait_failure: Option<std::io::Error>,
    poll_failure: Option<rustix::io::Errno>,
    clock_failure: Option<OriginalClockRefusal>,
    poisoned: bool,
    reuse_refused: bool,
    // No child-local or actor bank can supply the missing external purpose.
    // A future actual issuer must retain that Source/control credit outside
    // this process through kernel and VM teardown, not serialize a Rust loan.
}

impl IssuerRecord {
    const fn empty() -> Self {
        Self {
            interval: None,
            state: IssuerState::Empty,
            child: None,
            status: None,
            listener: None,
            policy_file: None,
            actor_file: None,
            record: None,
            peer: None,
            policy: None,
            parent: None,
            birth: None,
            first_work: None,
            kill_failure: None,
            wait_failure: None,
            poll_failure: None,
            clock_failure: None,
            poisoned: false,
            reuse_refused: false,
        }
    }

    fn original(&self) -> Result<OriginalInterval, MeasurementOriginError> {
        self.interval.ok_or(MeasurementOriginError::Authentication(
            "retained issuer interval",
        ))
    }

    fn prepare(&mut self, interval: OriginalInterval) -> Result<(), MeasurementOriginError> {
        if self.state != IssuerState::Empty || self.poisoned {
            self.reuse_refused = true;
            return Err(MeasurementOriginError::Authentication(
                "occupied original issuer",
            ));
        }
        self.interval = Some(interval);
        self.state = IssuerState::Prepared;
        interval.before()?;
        Ok(())
    }

    fn retain_work(&mut self, cause: MeasurementOriginError) {
        if self.first_work.is_none() {
            self.first_work = Some(cause);
        }
    }

    fn receive_external_purpose(&mut self) -> Result<(), MeasurementOriginError> {
        // Only the trusted real PID1 entry calls this fixed transport. Credits
        // remain in the external owner through physical VM retirement.
        let interval = self.original()?;
        self.parent = Some(issuer_parent::ParentBinding::receive(interval)?);
        interval.after_io(Ok(()))
    }

    fn publish_child(&mut self, child: Child) -> Result<(), MeasurementOriginError> {
        // Vacancy is validated before spawn while this same slot lock is held.
        // Keep these stores before any clock sample or fallible postcheck.
        self.child = Some(child);
        self.state = IssuerState::Born;
        self.original()?.after_io(Ok(()))
    }

    fn spawn_prepared(&mut self, command: &mut Command) -> Result<(), MeasurementOriginError> {
        let original = self.original()?;
        if self.state != IssuerState::Prepared || self.child.is_some() {
            return Err(MeasurementOriginError::Authentication(
                "issuer child already published",
            ));
        }
        original.before()?;
        match command.spawn() {
            Ok(child) => self.publish_child(child),
            Err(error) => original.after_io(Err(error)),
        }
    }

    fn poll_child(&mut self) -> Result<Option<ExitStatus>, MeasurementOriginError> {
        let original = self.original()?;
        original.before()?;
        let child = self
            .child
            .as_mut()
            .ok_or(MeasurementOriginError::Authentication(
                "retained direct child",
            ))?;
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => return original.after_io(Err(error)),
        };
        self.publish_wait_status(status)
    }

    fn publish_wait_status(
        &mut self,
        status: Option<ExitStatus>,
    ) -> Result<Option<ExitStatus>, MeasurementOriginError> {
        if let Some(status) = status {
            self.status = Some(status);
            self.state = IssuerState::DirectReaped;
        }
        // Actual Some/status is already retained even when this check refuses.
        self.original()?.after_io(Ok(()))?;
        Ok(status)
    }

    fn record_clock(&mut self, original: OriginalInterval) -> bool {
        match original.remaining() {
            Ok(_) => true,
            Err(cause) => {
                if self.clock_failure.is_none() {
                    self.clock_failure = Some(cause);
                }
                false
            }
        }
    }

    fn cleanup_direct_child(&mut self) {
        if self.child.is_none() || self.status.is_some() {
            return;
        }
        self.state = IssuerState::Quarantined;
        let Some(original) = self.interval else {
            return;
        };
        if !self.record_clock(original) {
            return;
        }
        if let Some(child) = self.child.as_mut()
            && let Err(error) = child.kill()
            && self.kill_failure.is_none()
        {
            self.kill_failure = Some(error);
        }
        if !self.record_clock(original) {
            return;
        }
        loop {
            if !self.record_clock(original) {
                return;
            }
            let result = match self.child.as_mut() {
                Some(child) => child.try_wait(),
                None => return,
            };
            match result {
                Ok(Some(status)) => {
                    self.status = Some(status);
                    self.state = IssuerState::DirectReaped;
                    self.record_clock(original);
                    return;
                }
                Ok(None) => {}
                Err(error) => {
                    if self.wait_failure.is_none() {
                        self.wait_failure = Some(error);
                    }
                    self.record_clock(original);
                    return;
                }
            }
            if !self.record_clock(original) {
                return;
            }
            let slice = match original.remaining() {
                Ok(left) => left.min(Duration::from_millis(10)),
                Err(cause) => {
                    self.clock_failure.get_or_insert(cause);
                    return;
                }
            };
            let timeout = match rustix::event::Timespec::try_from(slice) {
                Ok(timeout) => timeout,
                Err(_) => {
                    self.clock_failure
                        .get_or_insert(OriginalClockRefusal::Overflow);
                    return;
                }
            };
            let result = rustix::event::poll(&mut [], Some(&timeout));
            if let Err(error) = result {
                self.poll_failure.get_or_insert(error);
                self.record_clock(original);
                return;
            }
            if !self.record_clock(original) {
                return;
            }
        }
    }

    fn issue_actor(&mut self) -> Result<(), MeasurementOriginError> {
        self.receive_external_purpose()?;
        let interval = self.original()?;
        interval.before()?;
        let (policy, policy_file, digest) = match load_policy() {
            Ok(value) => value,
            Err(error) => return interval.after_result(Err(error)),
        };
        self.parent
            .as_mut()
            .ok_or(MeasurementOriginError::MissingIssuerPurpose)?
            .validate_and_seal(&policy, digest, interval)?;
        self.policy = Some(policy);
        self.policy_file = Some(policy_file);
        interval.after_io(Ok(()))?;
        let policy = self
            .policy
            .as_ref()
            .ok_or(MeasurementOriginError::Contract)?;
        interval.before()?;
        interval.after_result(same_executable(
            Path::new("/proc/self/exe"),
            &policy.init_executable,
        ))?;
        interval.before()?;
        self.actor_file = Some(match immutable_file(&policy.actor_executable) {
            Ok(file) => file,
            Err(error) => return interval.after_result(Err(error)),
        });
        interval.after_io(Ok(()))?;
        interval.before()?;
        let actor = interval.after_io(
            self.actor_file
                .as_ref()
                .ok_or(MeasurementOriginError::Contract)?
                .metadata(),
        )?;
        interval.before()?;
        self.listener = Some(match UnixListener::bind(ISSUER_PATH) {
            Ok(listener) => listener,
            Err(error) => return interval.after_io(Err(error)),
        });
        interval.after_io(Ok(()))?;
        interval.after_io(
            self.listener
                .as_ref()
                .ok_or(MeasurementOriginError::Contract)?
                .set_nonblocking(true),
        )?;
        interval.before()?;
        let fd = match memfd_create(
            "crucible-original-invocation",
            MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
        ) {
            Ok(fd) => fd,
            Err(error) => return interval.after_kernel(Err(error)),
        };
        self.record = Some(File::from(fd));
        interval.after_kernel(Ok(()))?;
        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        interval.before()?;
        let mut random = interval.after_io(File::open("/dev/urandom"))?;
        interval.before()?;
        interval.after_io(random.read_exact(&mut bytes[8..24]))?;
        drop(random);
        bytes[24..56].copy_from_slice(&digest);
        for (index, value) in [
            interval.start_ns,
            interval.end_ns,
            actor.dev(),
            actor.ino(),
            policy.native_count,
            policy.actor_cpu_slots,
            policy.actor_resident_bytes,
            policy.host_backing_bytes,
            policy.host_memory_bytes,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[56 + index * 8..64 + index * 8].copy_from_slice(&value.to_le_bytes());
        }
        let record = self
            .record
            .as_mut()
            .ok_or(MeasurementOriginError::Contract)?;
        interval.before()?;
        interval.after_io(record.write_all(&bytes))?;
        interval.before()?;
        interval.after_kernel(fcntl_add_seals(record, required_seals()))?;

        // Prepare every fallible command allocation before child birth. Keep
        // Command alive through publication; no temporary destructor intervenes.
        self.birth = Some(issuer_birth::ActorBirth::verify(&policy.mode, interval)?);
        interval.after_io(Ok(()))?;
        let mut command = Command::new(
            self.birth
                .as_ref()
                .ok_or(MeasurementOriginError::Contract)?
                .program(),
        );
        command
            .env_clear()
            .env(START_ENV, interval.start_ns.to_string())
            .env(END_ENV, interval.end_ns.to_string());
        self.spawn_prepared(&mut command)?;

        loop {
            interval.before()?;
            let accepted = self
                .listener
                .as_ref()
                .ok_or(MeasurementOriginError::Contract)?
                .accept();
            match accepted {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    interval.after_io(Ok(()))?;
                    wait_ready(
                        self.listener
                            .as_ref()
                            .ok_or(MeasurementOriginError::Contract)?,
                        rustix::event::PollFlags::IN,
                        interval,
                    )?;
                }
                Err(error) => return interval.after_io(Err(error)),
                Ok((peer, _address)) => {
                    self.peer = Some(peer);
                    interval.after_io(Ok(()))?;
                    break;
                }
            }
        }
        let peer = self.peer.as_mut().ok_or(MeasurementOriginError::Contract)?;
        interval.after_io(peer.set_nonblocking(true))?;
        interval.before()?;
        let credentials = interval.after_kernel(rustix::net::sockopt::socket_peercred(&*peer))?;
        let child = self
            .child
            .as_ref()
            .ok_or(MeasurementOriginError::Contract)?;
        if credentials.pid.as_raw_nonzero().get() as u32 != child.id() || !credentials.uid.is_root()
        {
            return Err(MeasurementOriginError::Authentication(
                "actual spawned child",
            ));
        }
        self.birth
            .as_ref()
            .ok_or(MeasurementOriginError::Contract)?
            .verify_child(child, interval)?;
        let record = self
            .record
            .as_ref()
            .ok_or(MeasurementOriginError::Contract)?;
        send_record(peer, record, interval)?;
        interval.before()?;
        let metadata = interval.after_io(record.metadata())?;
        let mut expected = [0; 32];
        expected[..16].copy_from_slice(&bytes[8..24]);
        expected[16..24].copy_from_slice(&metadata.dev().to_le_bytes());
        expected[24..].copy_from_slice(&metadata.ino().to_le_bytes());
        let mut request = [0; 32];
        read_issuance(peer, &mut request, interval)?;
        if request != expected {
            return Err(MeasurementOriginError::Authentication(
                "exact original adoption",
            ));
        }
        write_issuance(peer, &[1], interval)?;
        self.parent
            .as_ref()
            .ok_or(MeasurementOriginError::MissingIssuerPurpose)?
            .send(peer, interval)?;
        loop {
            if let Some(status) = self.poll_child()? {
                return if status.success() {
                    self.parent
                        .as_mut()
                        .ok_or(MeasurementOriginError::MissingIssuerPurpose)?
                        .complete(interval)
                } else {
                    Err(MeasurementOriginError::Authentication("actor completion"))
                };
            }
            let slice = interval.before()?.min(Duration::from_millis(10));
            let timeout = rustix::event::Timespec::try_from(slice)
                .map_err(|_| MeasurementOriginError::Clock)?;
            interval.after_kernel(rustix::event::poll(&mut [], Some(&timeout)))?;
        }
    }

    fn format_refusal(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(first) = &self.first_work {
            write!(formatter, "{first}")?;
        } else if self.poisoned {
            formatter.write_str("poisoned original custody; panic payload not retained")?;
        } else {
            formatter.write_str("original custody unavailable")?;
        }
        if let Some(cause) = &self.kill_failure {
            write!(formatter, "; termination: {cause}")?;
        }
        if let Some(cause) = &self.wait_failure {
            write!(formatter, "; direct wait: {cause}")?;
        }
        if let Some(cause) = &self.poll_failure {
            write!(formatter, "; cleanup poll: {cause}")?;
        }
        if let Some(cause) = &self.clock_failure {
            write!(formatter, "; original cleanup clock: {cause}")?;
        }
        if self.reuse_refused {
            formatter.write_str("; original slot reuse refused")?;
        }
        Ok(())
    }
}

pub(super) fn run_original(interval: OriginalInterval) -> Result<(), MeasurementOriginError> {
    let mut owner = match ISSUER.lock() {
        Ok(owner) => owner,
        Err(poisoned) => {
            let mut owner = poisoned.into_inner();
            owner.poisoned = true;
            owner.state = IssuerState::Quarantined;
            return Err(MeasurementOriginError::RetainedIssuer(
                IssuerCustodyRefusal { _private: () },
            ));
        }
    };
    if owner.state != IssuerState::Empty {
        owner.reuse_refused = true;
        return Err(MeasurementOriginError::RetainedIssuer(
            IssuerCustodyRefusal { _private: () },
        ));
    }
    let result = owner.prepare(interval).and_then(|()| owner.issue_actor());
    match result {
        Ok(()) => Ok(()),
        Err(first) => {
            owner.retain_work(first);
            owner.cleanup_direct_child();
            Err(MeasurementOriginError::RetainedIssuer(
                IssuerCustodyRefusal { _private: () },
            ))
        }
    }
}

#[cfg(test)]
mod tests;
