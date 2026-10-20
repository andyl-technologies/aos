//! Retains the fixed Mount/Source PID1 launcher-image observation.
//!
//! The lower original transport is resident before AUTH. Both native image
//! messages remain owned through exact uncached unit/manager bookends. This
//! module supplies DATA and descriptor loans, never an executed-image claim,
//! a frozen PID1, a task role or Source authority. Later protected crossings
//! require their own genuine current-owner checks.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::time::Duration;

use zbus::connection::FixedLauncherImageAttemptV1;
use zbus::connection::socket::{
    LauncherImageFailureLoanV1, LauncherImageFailureUnavailableV1,
};
use zbus::zvariant::{Fd, OwnedObjectPath, OwnedValue, Type};

const OBSERVATION_SECONDS: u64 = 5;
const MAXIMUM_LOCATOR_BYTES: usize = 4096;

#[derive(Default, Eq, PartialEq)]
struct UnitReadback {
    id: String,
    active: String,
    substate: String,
    main_pid: u32,
    invocation: Vec<u8>,
    fragment: String,
    drop_ins: Vec<String>,
    transient: bool,
}

impl UnitReadback {
    fn record(&mut self, index: usize, message: &zbus::Message) -> Result<(), zbus::Error> {
        match index {
            0 => self.id = property(message)?,
            1 => self.active = property(message)?,
            2 => self.substate = property(message)?,
            3 => self.main_pid = property(message)?,
            4 => self.invocation = property(message)?,
            5 => self.fragment = property(message)?,
            6 => self.drop_ins = property(message)?,
            7 => self.transient = property(message)?,
            _ => return Err(zbus::Error::InvalidReply),
        }

        Ok(())
    }

    fn validate(&self, unit: &str) -> Result<(), zbus::Error> {
        if self.id != unit
            || self.active != "active"
            || self.substate != "running"
            || self.main_pid != std::process::id()
            || self.invocation.len() != 16
            || self.invocation.iter().all(|byte| *byte == 0)
            || self.transient
            || !self.drop_ins.is_empty()
            || self.fragment.len() > MAXIMUM_LOCATOR_BYTES
            || !canonical_fragment(&self.fragment, unit)
        {
            return Err(zbus::Error::InvalidReply);
        }

        Ok(())
    }
}

// The ordinary zvariant decoder remains the only value parser. An exact Type
// guard prevents conversions such as av -> Vec<u8> from normalizing the schema.
fn property<T>(message: &zbus::Message) -> Result<T, zbus::Error>
where
    T: TryFrom<OwnedValue> + Type,
    T::Error: Into<zbus::zvariant::Error>,
{
    let value: OwnedValue = message.body().deserialize()?;
    decode_value(value)
}

fn decode_value<T>(value: OwnedValue) -> Result<T, zbus::Error>
where
    T: TryFrom<OwnedValue> + Type,
    T::Error: Into<zbus::zvariant::Error>,
{
    if value.value_signature() != T::SIGNATURE {
        return Err(zbus::zvariant::Error::IncorrectType.into());
    }

    T::try_from(value).map_err(|error| zbus::Error::from(error.into()))
}

fn canonical_fragment(fragment: &str, unit: &str) -> bool {
    let path = std::path::Path::new(fragment);
    path.is_absolute()
        && !fragment.as_bytes().contains(&0)
        && path.file_name() == Some(std::ffi::OsStr::new(unit))
        && path.components().all(|component| {
            matches!(component, std::path::Component::RootDir | std::path::Component::Normal(_))
        })
        && !fragment.as_bytes()[1..].split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
}

enum ObservationFailure {
    Transport(zbus::Error),
    Decode(zbus::Error),
    Deadline(tokio::time::error::Elapsed),
    DeadlineBookend { deadline: tokio::time::Instant, observed: tokio::time::Instant },
    LowerEnded,
    Repeated,
}

/// Reports a permanently ended observation without copying its owning cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnUnitPid1ImageEndedV1;

impl std::fmt::Display for OwnUnitPid1ImageEndedV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("fixed PID1 launcher-image observation ended")
    }
}

impl std::error::Error for OwnUnitPid1ImageEndedV1 {}

/// Borrows the actual retained observer and lower failure slots.
///
/// The lower move-only loan makes this view neither Send nor Sync. No field
/// contains a guard borrowed from another field of the same object.
pub struct OwnUnitPid1ImageFailureV1<'owner> {
    attempt: &'owner OwnUnitPid1ImageAttemptV1,
    lower: Option<LauncherImageFailureLoanV1<'owner>>,
}

impl std::fmt::Debug for OwnUnitPid1ImageFailureV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OwnUnitPid1ImageFailureV1")
    }
}

impl OwnUnitPid1ImageFailureV1<'_> {
    /// Returns the nonobserving loan of the same actual lower failure.
    #[must_use]
    pub fn lower(&self) -> Option<&LauncherImageFailureLoanV1<'_>> {
        self.lower.as_ref()
    }

    /// Borrows the actual parser or transport status recorded by the observer.
    #[must_use]
    pub fn protocol_cause(&self) -> Option<&zbus::Error> {
        match self.attempt.first_failure.as_ref() {
            Some(ObservationFailure::Decode(cause) | ObservationFailure::Transport(cause)) => Some(cause),
            _ => None,
        }
    }

    /// Borrows the actual elapsed result, rather than synthesizing an I/O error.
    #[must_use]
    pub fn deadline_cause(&self) -> Option<&tokio::time::error::Elapsed> {
        match self.attempt.first_failure.as_ref() {
            Some(ObservationFailure::Deadline(cause)) => Some(cause),
            _ => None,
        }
    }

    /// Returns actual final-clock DATA when synchronous decoding exceeded expiry.
    #[must_use]
    pub fn deadline_bookend(&self) -> Option<(tokio::time::Instant, tokio::time::Instant)> {
        match self.attempt.first_failure.as_ref() {
            Some(ObservationFailure::DeadlineBookend { deadline, observed }) => Some((*deadline, *observed)),
            _ => None,
        }
    }
}

/// Owns one original fixed-unit launcher-image observation before its first I/O.
///
/// The only constructors choose the two installed selected purposes. There is
/// no caller connection, descriptor, PID, unit name or profile constructor.
pub struct OwnUnitPid1ImageAttemptV1 {
    transport: FixedLauncherImageAttemptV1,
    unit: &'static str,
    attempted: bool,
    completed: bool,
    first_failure: Option<ObservationFailure>,
    before: UnitReadback,
    after: UnitReadback,
}

impl std::fmt::Debug for OwnUnitPid1ImageAttemptV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("OwnUnitPid1ImageAttemptV1")
            .field("attempted", &self.attempted)
            .field("completed", &self.completed)
            .finish_non_exhaustive()
    }
}

impl OwnUnitPid1ImageAttemptV1 {
    /// Creates an inert observation for the selected Mount main process.
    #[must_use]
    pub fn mount() -> Self {
        Self::empty(FixedLauncherImageAttemptV1::mount(), "aos-sandbox-mountd.service")
    }

    /// Creates an inert observation for the selected Source main process.
    #[must_use]
    pub fn source() -> Self {
        Self::empty(FixedLauncherImageAttemptV1::source(), "aos-source-providerd.service")
    }

    fn empty(transport: FixedLauncherImageAttemptV1, unit: &'static str) -> Self {
        Self {
            transport,
            unit,
            attempted: false,
            completed: false,
            first_failure: None,
            before: UnitReadback::default(),
            after: UnitReadback::default(),
        }
    }

    /// Performs the fixed 24-request observation under one absolute deadline.
    ///
    /// # Errors
    /// Ends on transport, schema, unit, manager or deadline failure. Actual
    /// originals and the first cause remain resident; no retry or renewal occurs.
    pub async fn capture_once(&mut self) -> Result<(), OwnUnitPid1ImageEndedV1> {
        if self.attempted || self.transport.has_ended() {
            self.transport.end();
            if self.first_failure.is_none() {
                self.first_failure = Some(if self.attempted {
                    ObservationFailure::Repeated
                } else {
                    ObservationFailure::LowerEnded
                });
            }
            return Err(OwnUnitPid1ImageEndedV1);
        }
        self.attempted = true;
        let mut cancellation = self.transport.cancellation_fence();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(OBSERVATION_SECONDS);
        let result = tokio::time::timeout_at(deadline, self.capture_recipe()).await;
        let failure = match result {
            Ok(Ok(())) => {
                let observed = tokio::time::Instant::now();
                if observed <= deadline && !self.transport.has_ended() {
                    self.completed = true;
                    cancellation.complete();
                    return Ok(());
                }
                if observed > deadline {
                    ObservationFailure::DeadlineBookend { deadline, observed }
                } else {
                    ObservationFailure::LowerEnded
                }
            }
            Ok(Err(cause)) => cause,
            Err(cause) => ObservationFailure::Deadline(cause),
        };

        self.transport.end();
        if self.first_failure.is_none() {
            self.first_failure = Some(failure);
        }
        Err(OwnUnitPid1ImageEndedV1)
    }

    async fn capture_recipe(&mut self) -> Result<(), ObservationFailure> {
        self.transport.connect().await.map_err(ObservationFailure::Transport)?;
        for index in 0..24 {
            let message = self.transport.observe_next().await
                .map_err(ObservationFailure::Transport)?
                .ok_or(ObservationFailure::Decode(zbus::Error::InvalidReply))?;

            match index {
                1 | 23 => {
                    let pid: u32 = message.body().deserialize().map_err(ObservationFailure::Decode)?;
                    if pid != 1 {
                        return Err(ObservationFailure::Decode(zbus::Error::InvalidReply));
                    }
                }
                3..=10 => self.before.record(index - 3, message).map_err(ObservationFailure::Decode)?,
                12..=19 => self.after.record(index - 12, message).map_err(ObservationFailure::Decode)?,
                11 | 20 => require_native_image(message).map_err(ObservationFailure::Decode)?,
                _ => {}
            }
            if index == 10 {
                self.before.validate(self.unit).map_err(ObservationFailure::Decode)?;
            }
            if index == 19 {
                self.after.validate(self.unit).map_err(ObservationFailure::Decode)?;
                if self.before != self.after {
                    return Err(ObservationFailure::Decode(zbus::Error::InvalidReply));
                }
            }
        }

        let first_owner = self.transport.reply(0).ok_or(ObservationFailure::Decode(zbus::Error::InvalidReply))?;
        let last_owner = self.transport.reply(22).ok_or(ObservationFailure::Decode(zbus::Error::InvalidReply))?;
        let first_owner: String = first_owner.body().deserialize().map_err(ObservationFailure::Decode)?;
        let last_owner: String = last_owner.body().deserialize().map_err(ObservationFailure::Decode)?;
        let first_unit = self.transport.reply(2).ok_or(ObservationFailure::Decode(zbus::Error::InvalidReply))?;
        let last_unit = self.transport.reply(21).ok_or(ObservationFailure::Decode(zbus::Error::InvalidReply))?;
        let first_unit: OwnedObjectPath = first_unit.body().deserialize().map_err(ObservationFailure::Decode)?;
        let last_unit: OwnedObjectPath = last_unit.body().deserialize().map_err(ObservationFailure::Decode)?;
        if first_owner != last_owner || first_unit != last_unit {
            return Err(ObservationFailure::Decode(zbus::Error::InvalidReply));
        }
        for index in 2..=21 {
            let message = self.transport.reply(index).ok_or(ObservationFailure::Decode(zbus::Error::InvalidReply))?;
            if message.header().sender().map(|sender| sender.as_str()) != Some(first_owner.as_str()) {
                return Err(ObservationFailure::Decode(zbus::Error::InvalidReply));
            }
        }

        Ok(())
    }

    /// Borrows the original failure without fresh observation or retry.
    ///
    /// # Errors
    /// Refuses a locked or poisoned lower slot rather than recovering it.
    pub fn failure(&self) -> Result<Option<OwnUnitPid1ImageFailureV1<'_>>, LauncherImageFailureUnavailableV1> {
        let lower = self.transport.failure()?;
        if self.first_failure.is_none() && lower.is_none() {
            return Ok(None);
        }

        Ok(Some(OwnUnitPid1ImageFailureV1 { attempt: self, lower }))
    }

    /// Borrows original and invariant-rejection shutdown outcomes, in that order.
    ///
    /// This is nonobserving even if the receive-failure loan is unavailable.
    /// None is not successful shutdown; Ok is not acknowledgement or drain.
    #[must_use]
    pub fn shutdown_outcomes(&self) -> (
        Option<&std::io::Result<()>>,
        Option<&std::io::Result<()>>,
    ) {
        self.transport.shutdown_outcomes()
    }

    /// Ends the same original queue before any partial observation can drop.
    ///
    /// This negative-only operation neither retries nor lends a descriptor.
    pub fn end(&self) {
        self.transport.end();
    }

    /// Moves the complete original owner once without taking either descriptor.
    ///
    /// # Errors
    /// Returns this same original attempt if it has not completed or has failed.
    pub fn into_completed(self) -> Result<CompletedOwnUnitPid1ImageV1, Self> {
        if !self.completed || self.first_failure.is_some() || self.transport.has_ended() {
            return Err(self);
        }

        Ok(CompletedOwnUnitPid1ImageV1 { attempt: self })
    }
}

impl Drop for OwnUnitPid1ImageAttemptV1 {
    fn drop(&mut self) {
        self.transport.end();
    }
}

fn require_native_image(message: &zbus::Message) -> Result<(), zbus::Error> {
    if message.body().signature() != <Fd<'_> as Type>::SIGNATURE || message.data().fds().len() != 1 {
        return Err(zbus::Error::InvalidReply);
    }
    let body = message.body();
    let decoded: Fd<'_> = body.deserialize()?;
    let Some(original) = message.data().fds().first() else {
        return Err(zbus::Error::InvalidReply);
    };
    if decoded.as_raw_fd() != original.as_raw_fd() {
        return Err(zbus::Error::InvalidReply);
    }

    Ok(())
}

/// Retains both completed native image messages and their original transport.
///
/// Equality, backing immutability and executed-image measurements remain the
/// consumer's responsibility. This owner is not a Root/currentness claim.
pub struct CompletedOwnUnitPid1ImageV1 {
    attempt: OwnUnitPid1ImageAttemptV1,
}

impl std::fmt::Debug for CompletedOwnUnitPid1ImageV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CompletedOwnUnitPid1ImageV1")
    }
}

impl CompletedOwnUnitPid1ImageV1 {
    /// Borrows the first original image descriptor without duplication/adoption.
    #[must_use]
    pub fn first_image(&self) -> Option<BorrowedFd<'_>> {
        self.attempt.transport.reply(11)?.data().fds().first().map(AsFd::as_fd)
    }

    /// Borrows the second original image descriptor without duplication/adoption.
    #[must_use]
    pub fn second_image(&self) -> Option<BorrowedFd<'_>> {
        self.attempt.transport.reply(20)?.data().fds().first().map(AsFd::as_fd)
    }

    /// Returns the invocation bytes observed at both actual unit bookends.
    #[must_use]
    pub fn invocation(&self) -> &[u8] {
        &self.attempt.before.invocation
    }

    /// Borrows original and invariant-rejection shutdown outcomes, in that order.
    ///
    /// The outcomes remain separate from receive/parser failure, including after
    /// completion. None is unavailable; Ok is not acknowledgement or drain.
    #[must_use]
    pub fn shutdown_outcomes(&self) -> (
        Option<&std::io::Result<()>>,
        Option<&std::io::Result<()>>,
    ) {
        self.attempt.transport.shutdown_outcomes()
    }

    /// Permanently ends this original flight before releasing any image custody.
    pub fn end(&self) {
        self.attempt.transport.end();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ended_attempt_refuses_capture_before_runtime_or_connection() {
        struct InertWake;
        impl std::task::Wake for InertWake {
            fn wake(self: std::sync::Arc<Self>) {}
        }
        let mut attempt = OwnUnitPid1ImageAttemptV1::mount();
        attempt.end();
        let waker = std::task::Waker::from(std::sync::Arc::new(InertWake));
        let mut context = std::task::Context::from_waker(&waker);

        let mut capture = Box::pin(attempt.capture_once());
        assert!(matches!(
            std::future::Future::poll(capture.as_mut(), &mut context),
            std::task::Poll::Ready(Err(_))
        ));
        drop(capture);

        assert!(!attempt.attempted);
        assert!(attempt.transport.has_ended());
        assert!(attempt.shutdown_outcomes().0.is_none());
    }

    #[test]
    fn exact_byte_array_remains_data() {
        let value = OwnedValue::try_from(zbus::zvariant::Value::from(vec![1u8; 16])).unwrap();

        let bytes = decode_value::<Vec<u8>>(value).unwrap();

        assert_eq!(bytes, vec![1u8; 16]);
    }

    #[test]
    fn variant_elements_cannot_normalize_to_invocation_bytes() {
        let values: Vec<_> = (0..16).map(|_| zbus::zvariant::Value::new(1u8)).collect();
        let value = OwnedValue::try_from(zbus::zvariant::Value::from(values)).unwrap();

        let result = decode_value::<Vec<u8>>(value);

        assert!(matches!(result, Err(zbus::Error::Variant(zbus::zvariant::Error::IncorrectType))));
    }

    #[test]
    fn fragment_locator_rejects_lexical_dot_empty_and_sibling_components() {
        const UNIT: &str = "aos-sandbox-mountd.service";

        assert!(canonical_fragment("/usr/lib/systemd/system/aos-sandbox-mountd.service", UNIT));
        for locator in [
            "/usr/lib/./systemd/system/aos-sandbox-mountd.service",
            "/usr/lib//systemd/system/aos-sandbox-mountd.service",
            "/usr/lib/systemd/system/../aos-sandbox-mountd.service",
            "/usr/lib/systemd/system/aos-sandbox-mountd.service.other",
            "aos-sandbox-mountd.service",
        ] {
            assert!(!canonical_fragment(locator, UNIT), "{locator}");
        }
    }
}
