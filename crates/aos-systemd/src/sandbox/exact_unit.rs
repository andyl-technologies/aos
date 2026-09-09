//! Reference-held observations and exact-target stop operations.
//!
//! Host protocol 1.5 binds both transient services to one authenticated
//! launch digest retained in systemd's `Environment` property.  This module
//! is the only place that parses that manager-retained value.  It also owns
//! the `RefUnit`/`UnrefUnit` lifetime used while comparing an invocation and
//! submitting a stop job.  A terminal observation made while the reference is
//! held is deliberately intermediate: final absence must be established only
//! after `UnrefUnit`, together with exact cgroup absence.

use std::num::NonZeroU32;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::time::Duration;

use zbus::proxy::CacheProperties;
use zbus::zvariant::OwnedObjectPath;

use super::{SandboxCgroupPath, SandboxUnitName, parse_exact_cgroup, parse_invocation_id};
use crate::client::{JobResult, SystemdClient};
use crate::error::{Error, Result, is_no_such_unit};
use crate::manager_proxy::{ManagerProxy, ServiceProxy, UnitProxy};

const PAYLOAD_BINDING_PREFIX: &str = "AOS_SANDBOX_LAUNCH_BINDING=";
const GUARDIAN_BINDING_PREFIX: &str = "AOS_GUARDIAN_LAUNCH_BINDING=";
const CONNECTION_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const EXACT_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const REFERENCE_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const SYSTEM_BUS_SOCKET: &str = "/run/dbus/system_bus_socket";

/// Selects one member of the immutable-lease Guardian/payload pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExactUnitRole {
    /// The lease-enforcing companion service.
    Guardian,
    /// The sandbox nspawn supervisor service.
    Payload,
}

impl ExactUnitRole {
    fn name(self, name: &SandboxUnitName) -> &str {
        match self {
            Self::Guardian => name.guardian(),
            Self::Payload => name.as_str(),
        }
    }

    fn binding_prefix(self) -> &'static str {
        match self {
            Self::Guardian => GUARDIAN_BINDING_PREFIX,
            Self::Payload => PAYLOAD_BINDING_PREFIX,
        }
    }

    fn expected_cgroup(self, name: &SandboxUnitName) -> SandboxCgroupPath {
        match self {
            Self::Guardian => name.guardian_cgroup_path(),
            Self::Payload => name.cgroup_path(),
        }
    }
}

/// Closed projection of the manager state relevant to exact adoption and stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExactUnitState {
    /// The service is active with the service-specific `running` substate.
    ActiveRunning,
    /// The service is still activating.
    Activating,
    /// The service is inactive.
    TerminalInactive,
    /// The service is failed.
    TerminalFailed,
    /// The manager returned another state that this protocol does not adopt.
    Other,
}

impl ExactUnitState {
    fn from_manager(active: &str, sub: &str) -> Self {
        match (active, sub) {
            ("active", "running") => Self::ActiveRunning,
            ("activating", _) => Self::Activating,
            ("inactive", _) => Self::TerminalInactive,
            ("failed", _) => Self::TerminalFailed,
            _ => Self::Other,
        }
    }

    /// Returns whether systemd reports an inactive or failed terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::TerminalInactive | Self::TerminalFailed)
    }
}

/// Distinguishes a denied final effect guard from a systemd start failure.
#[derive(Debug)]
pub enum ExactStartError<E> {
    /// The caller's final authority check denied submission.
    Guard(E),
    /// Property preparation, D-Bus submission, or job completion failed.
    Systemd(Error),
}

/// Separates systemd failures from an indeterminate caller quiescence check.
#[derive(Debug)]
pub enum ExactStopError<E> {
    /// Manager transport, identity observation, job, or reference failure.
    Systemd(Error),
    /// The caller could not establish pidfd death or exact cgroup emptiness.
    Quiescence(E),
}

/// Names the immutable manager identity authorized for an exact stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactUnitTarget {
    binding: [u8; 32],
    invocation_id: [u8; 16],
}

impl ExactUnitTarget {
    /// Constructs a non-sentinel launch-binding and invocation pair.
    ///
    /// # Errors
    ///
    /// Returns an error when either identity is the all-zero sentinel.
    pub fn new(binding: [u8; 32], invocation_id: [u8; 16]) -> Result<Self> {
        if binding == [0; 32] || invocation_id == [0; 16] {
            return Err(Error::InvalidSandboxUnit(
                "exact unit target contains a zero identity".to_owned(),
            ));
        }
        Ok(Self {
            binding,
            invocation_id,
        })
    }

    /// Returns the authenticated launch binding.
    #[must_use]
    pub const fn binding(self) -> [u8; 32] {
        self.binding
    }

    /// Returns the exact systemd invocation identifier.
    #[must_use]
    pub const fn invocation_id(self) -> [u8; 16] {
        self.invocation_id
    }
}

/// One manager-sandwiched observation of a reference-held service object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactUnitObservation {
    /// Guardian or payload role used to select the unit and binding property.
    pub role: ExactUnitRole,
    /// Exact D-Bus object path held by `RefUnit` during the observation.
    pub object_path: OwnedObjectPath,
    /// Canonical, unique manager-retained launch binding, when present.
    pub binding: Option<[u8; 32]>,
    /// Current nonzero systemd invocation identifier, when present.
    pub invocation_id: Option<[u8; 16]>,
    /// Raw high-level activation state read inside the identity sandwich.
    pub active_state: String,
    /// Raw service-specific substate read inside the identity sandwich.
    pub sub_state: String,
    /// Closed manager state projection.
    pub state: ExactUnitState,
    /// Exact expected cgroup path, when systemd reports a realized cgroup.
    pub cgroup: Option<SandboxCgroupPath>,
    /// Current service leader, when systemd reports a nonzero `MainPID`.
    pub main_pid: Option<NonZeroU32>,
}

impl ExactUnitObservation {
    /// Returns whether this observation names the authorized binding and invocation.
    #[must_use]
    pub fn matches(&self, target: ExactUnitTarget) -> bool {
        self.binding == Some(target.binding) && self.invocation_id == Some(target.invocation_id)
    }

    /// Returns whether the reference-held manager object is terminal without a leader.
    ///
    /// This is not final stop evidence.  Callers must additionally establish
    /// death of every retained leader and emptiness of the pre-pinned cgroup,
    /// then wait for authoritative manager and cgroup absence after `UnrefUnit`.
    #[must_use]
    pub fn is_intermediate_terminal(&self) -> bool {
        self.state.is_terminal() && self.main_pid.is_none() && self.cgroup.is_some()
    }
}

/// Result of the manager portion of one exact-target stop operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactStopOutcome {
    /// No manager object existed before a reference could be acquired.
    MissingManagerObject,
    /// The loaded unit did not match the authorized binding and invocation.
    Foreign(ExactUnitObservation),
    /// systemd completed the submitted stop job with a non-`done` result.
    JobFailed(JobResult),
    /// The same referenced object remains nonterminal or still has a leader.
    Residual(ExactUnitObservation),
    /// The same referenced object was terminal, leaderless, pidfd-dead, and
    /// exact-cgroup-empty while `RefUnit` was still held.
    ///
    /// This is only an intermediate handoff for pidfd and cgroup checks.  The
    /// reference has been released before this value is returned, but no claim
    /// of final absence is made.
    AwaitingAbsence(ExactUnitObservation),
}

/// Fresh manager observation made without retaining a unit after `UnrefUnit`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostUnrefUnitObservation {
    /// `GetUnit` returned systemd's authoritative `NoSuchUnit` result.
    Absent,
    /// A manager object remains loaded; this is never projected as absence.
    Present(ExactUnitObservation),
}

struct UnitReference {
    name: String,
    object_path: OwnedObjectPath,
}

impl UnitReference {
    async fn release(&self, manager: &ManagerProxy<'static>) -> Result<()> {
        tokio::time::timeout(REFERENCE_OPERATION_TIMEOUT, manager.unref_unit(&self.name))
            .await
            .map_err(|_| Error::ExactUnitTimeout("UnrefUnit reply"))??;
        Ok(())
    }
}

#[cfg(unix)]
struct SocketShutdownAnchor {
    stream: UnixStream,
}

#[cfg(unix)]
impl Drop for SocketShutdownAnchor {
    fn drop(&mut self) {
        // `shutdown(2)` applies to the socket itself, including zbus's
        // duplicate descriptor, and cannot await an internal async mutex.
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

/// Owns a disposable systemd connection for one reference-sensitive operation.
///
/// Methods consume this value. Cancellation or an ambiguous `RefUnit`/
/// `UnrefUnit` reply therefore drops the complete connection, which is
/// systemd's connection-scoped fallback for releasing references. Callers must
/// not use a shared [`SystemdClient`] for exact reference lifetimes.
pub struct ExactUnitClient {
    #[cfg(unix)]
    _shutdown: SocketShutdownAnchor,
    client: SystemdClient,
}

impl ExactUnitClient {
    /// Opens a disposable system-bus connection for one exact operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the system bus or manager subscription is
    /// unavailable, or connection setup exceeds its fixed deadline.
    pub async fn connect() -> Result<Self> {
        #[cfg(unix)]
        {
            tokio::time::timeout(CONNECTION_OPERATION_TIMEOUT, async {
                let stream = tokio::net::UnixStream::connect(SYSTEM_BUS_SOCKET)
                    .await
                    .map_err(zbus::Error::from)
                    .map_err(Error::SystemdUnavailable)?;
                let stream = stream
                    .into_std()
                    .map_err(zbus::Error::from)
                    .map_err(Error::SystemdUnavailable)?;

                Self::from_unix_stream(stream).await
            })
            .await
            .map_err(|_| Error::ExactUnitTimeout("connection setup"))?
        }

        #[cfg(not(unix))]
        {
            Err(Error::InvalidSandboxUnit(
                "exact unit references require a Unix system bus".to_owned(),
            ))
        }
    }

    /// Opens a disposable peer-to-peer connection on one test-owned stream.
    ///
    /// The exact-unit test feature deliberately exposes only the stream, so
    /// the zbus connection and synchronous shutdown anchor are necessarily
    /// derived from the same socket.
    ///
    /// # Errors
    ///
    /// Returns an error when stream preparation, the peer handshake, or the
    /// manager subscription fails or exceeds its fixed deadline.
    #[cfg(all(unix, feature = "exact-unit-test-util"))]
    #[doc(hidden)]
    pub async fn from_test_peer_stream(stream: UnixStream) -> Result<Self> {
        tokio::time::timeout(CONNECTION_OPERATION_TIMEOUT, async {
            let (shutdown, stream) = prepare_unix_stream(stream)?;
            let connection = zbus::connection::Builder::unix_stream(stream)
                .p2p()
                .build()
                .await
                .map_err(Error::SystemdUnavailable)?;
            let client = SystemdClient::from_connection(connection).await?;

            Ok(Self {
                _shutdown: shutdown,
                client,
            })
        })
        .await
        .map_err(|_| Error::ExactUnitTimeout("test connection setup"))?
    }

    /// Observes one exact unit while retaining its manager object.
    ///
    /// The returned snapshot is no longer reference-held; it is evidence for
    /// a decision, not authority for a later effect.
    ///
    /// # Errors
    ///
    /// Returns an error for D-Bus failures, an object-path substitution, a
    /// malformed identity, or a manager property change during the sandwich.
    pub async fn observe_exact_unit(
        self,
        name: &SandboxUnitName,
        role: ExactUnitRole,
    ) -> Result<Option<ExactUnitObservation>> {
        let operation = async {
            match self.client.acquire_unit_reference(name, role).await {
                Ok(Some(reference)) => {
                    let observation = self.client.observe_reference(name, role, &reference).await;
                    finish_reference(&self.client.manager, &reference, observation)
                        .await
                        .map(Some)
                }
                Ok(None) => Ok(None),
                Err(error) => Err(error),
            }
        };
        let result = tokio::time::timeout(EXACT_OPERATION_TIMEOUT, operation)
            .await
            .unwrap_or_else(|_| Err(Error::ExactUnitTimeout("observation")));

        finish_connection(self, result).await
    }

    /// Reobserves manager presence after the stop-side reference was released.
    ///
    /// This method intentionally does not call `RefUnit`: a reference would
    /// itself prolong collection and make the final absence condition
    /// self-defeating. A retained terminal object is returned as `Present`,
    /// never as `Absent`. Final completion also requires an independent exact
    /// cgroup-path absence check against a freshly validated cgroup root.
    ///
    /// # Errors
    ///
    /// Returns an error for any result other than authoritative `NoSuchUnit`
    /// or a stable manager-sandwiched present observation.
    pub async fn observe_after_unref(
        self,
        name: &SandboxUnitName,
        role: ExactUnitRole,
    ) -> Result<PostUnrefUnitObservation> {
        let operation = async {
            let unit_name = role.name(name);
            match self.client.manager.get_unit(unit_name).await {
                Err(error) if is_no_such_unit(&error) => Ok(PostUnrefUnitObservation::Absent),
                Err(error) => Err(error.into()),
                Ok(object_path) => {
                    let unreferenced = UnitReference {
                        name: unit_name.to_owned(),
                        object_path,
                    };
                    self.client
                        .observe_reference(name, role, &unreferenced)
                        .await
                        .map(PostUnrefUnitObservation::Present)
                }
            }
        };
        let result = tokio::time::timeout(EXACT_OPERATION_TIMEOUT, operation)
            .await
            .unwrap_or_else(|_| Err(Error::ExactUnitTimeout("post-Unref observation")));

        finish_connection(self, result).await
    }

    /// Stops only the manager object matching an exact binding and invocation.
    ///
    /// `GetUnit` precedes `RefUnit`; the object path is rechecked after the
    /// reference is acquired.  The target is compared before submission and
    /// after a `done` job. Every ordinary return attempts bounded `UnrefUnit`
    /// and connection close. Cancellation synchronously shuts down the owned
    /// socket through the connection's independent shutdown anchor.
    ///
    /// # Errors
    ///
    /// Returns an error for D-Bus failures, malformed manager evidence, object
    /// substitution, or failure to release the unit reference.
    pub async fn stop_exact_unit<E>(
        self,
        name: &SandboxUnitName,
        role: ExactUnitRole,
        target: ExactUnitTarget,
        confirm_quiescence: &mut (
                 dyn FnMut(&ExactUnitObservation) -> std::result::Result<bool, E> + Send
             ),
    ) -> std::result::Result<ExactStopOutcome, ExactStopError<E>> {
        let mut prepare_quiescence =
            |_: &ExactUnitObservation| -> std::result::Result<(), E> { Ok(()) };
        self.stop_exact_unit_prepared(
            name,
            role,
            target,
            &mut prepare_quiescence,
            confirm_quiescence,
        )
        .await
    }

    /// Stops an exact unit while letting the caller pin pre-stop kernel identity.
    ///
    /// `prepare_quiescence` runs with the manager reference held after the
    /// target matches and immediately before `StopUnit`. `confirm_quiescence`
    /// runs after the exact `done` job and repeated target comparison. This
    /// lets a Linux caller retain the pre-stop leader pidfd and cgroup object,
    /// then prove their death and emptiness without trusting numeric IDs.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::stop_exact_unit`], plus caller
    /// quiescence preparation failures.
    pub async fn stop_exact_unit_prepared<E>(
        self,
        name: &SandboxUnitName,
        role: ExactUnitRole,
        target: ExactUnitTarget,
        prepare_quiescence: &mut (
                 dyn FnMut(&ExactUnitObservation) -> std::result::Result<(), E> + Send
             ),
        confirm_quiescence: &mut (
                 dyn FnMut(&ExactUnitObservation) -> std::result::Result<bool, E> + Send
             ),
    ) -> std::result::Result<ExactStopOutcome, ExactStopError<E>> {
        let operation = async {
            let reference = match self.client.acquire_unit_reference(name, role).await {
                Ok(Some(reference)) => reference,
                Ok(None) => return Ok(ExactStopOutcome::MissingManagerObject),
                Err(error) => return Err(ExactStopError::Systemd(error)),
            };

            let outcome = async {
                let before = self
                    .client
                    .observe_reference(name, role, &reference)
                    .await
                    .map_err(ExactStopError::Systemd)?;
                if !before.matches(target) {
                    return Ok(ExactStopOutcome::Foreign(before));
                }
                prepare_quiescence(&before).map_err(ExactStopError::Quiescence)?;

                let job_path = self
                    .client
                    .manager
                    .stop_unit(role.name(name), "replace")
                    .await
                    .map_err(Error::from)
                    .map_err(ExactStopError::Systemd)?;
                let job = self
                    .client
                    .await_job(job_path)
                    .await
                    .map_err(ExactStopError::Systemd)?;
                if job.result != JobResult::Done {
                    return Ok(ExactStopOutcome::JobFailed(job.result));
                }

                let after = self
                    .client
                    .observe_reference(name, role, &reference)
                    .await
                    .map_err(ExactStopError::Systemd)?;
                if !after.matches(target) {
                    return Ok(ExactStopOutcome::Foreign(after));
                }
                if after.is_intermediate_terminal()
                    && confirm_quiescence(&after).map_err(ExactStopError::Quiescence)?
                {
                    Ok(ExactStopOutcome::AwaitingAbsence(after))
                } else {
                    Ok(ExactStopOutcome::Residual(after))
                }
            }
            .await;

            finish_exact_stop(&self.client.manager, &reference, outcome).await
        };
        let result = tokio::time::timeout(EXACT_OPERATION_TIMEOUT, operation)
            .await
            .unwrap_or_else(|_| {
                Err(ExactStopError::Systemd(Error::ExactUnitTimeout(
                    "stop operation",
                )))
            });

        finish_exact_connection(self, result).await
    }

    #[cfg(unix)]
    async fn from_unix_stream(stream: UnixStream) -> Result<Self> {
        let (shutdown, stream) = prepare_unix_stream(stream)?;
        let connection = zbus::connection::Builder::unix_stream(stream)
            .build()
            .await
            .map_err(Error::SystemdUnavailable)?;
        let client = SystemdClient::from_connection(connection).await?;

        Ok(Self {
            _shutdown: shutdown,
            client,
        })
    }
}

#[cfg(unix)]
fn prepare_unix_stream(
    stream: UnixStream,
) -> Result<(SocketShutdownAnchor, tokio::net::UnixStream)> {
    let shutdown_stream = stream
        .try_clone()
        .map_err(zbus::Error::from)
        .map_err(Error::SystemdUnavailable)?;
    let shutdown = SocketShutdownAnchor {
        stream: shutdown_stream,
    };
    stream
        .set_nonblocking(true)
        .map_err(zbus::Error::from)
        .map_err(Error::SystemdUnavailable)?;
    let stream = tokio::net::UnixStream::from_std(stream)
        .map_err(zbus::Error::from)
        .map_err(Error::SystemdUnavailable)?;

    Ok((shutdown, stream))
}

impl SystemdClient {
    async fn acquire_unit_reference(
        &self,
        name: &SandboxUnitName,
        role: ExactUnitRole,
    ) -> Result<Option<UnitReference>> {
        let unit_name = role.name(name);
        let object_path = match self.manager.get_unit(unit_name).await {
            Ok(path) => path,
            Err(error) if is_no_such_unit(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        };

        tokio::time::timeout(
            REFERENCE_OPERATION_TIMEOUT,
            self.manager.ref_unit(unit_name),
        )
        .await
        .map_err(|_| Error::ExactUnitTimeout("RefUnit reply"))??;
        let reference = UnitReference {
            name: unit_name.to_owned(),
            object_path,
        };
        let current = match self.manager.get_unit(unit_name).await {
            Ok(path) => path,
            Err(error) => {
                let result = if is_no_such_unit(&error) {
                    Err(Error::InvalidSandboxUnit(
                        "unit disappeared after RefUnit succeeded".to_owned(),
                    ))
                } else {
                    Err(error.into())
                };
                return finish_reference(&self.manager, &reference, result).await;
            }
        };
        if current != reference.object_path {
            let result = Err(Error::InvalidSandboxUnit(
                "unit object path changed across RefUnit".to_owned(),
            ));
            return finish_reference(&self.manager, &reference, result).await;
        }

        Ok(Some(reference))
    }

    async fn observe_reference(
        &self,
        name: &SandboxUnitName,
        role: ExactUnitRole,
        reference: &UnitReference,
    ) -> Result<ExactUnitObservation> {
        let unit = UnitProxy::builder(&self.conn)
            .path(reference.object_path.clone())?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        let service = ServiceProxy::builder(&self.conn)
            .path(reference.object_path.clone())?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;

        let expected_name = role.name(name);
        let id_before = unit.id().await?;
        let invocation_before = parse_invocation_id(unit.invocation_id().await?)?;
        let environment_before = service.environment().await?;
        let binding = parse_launch_binding(&environment_before, role)?;

        let active_state = unit.active_state().await?;
        let sub_state = unit.sub_state().await?;
        let main_pid = NonZeroU32::new(service.main_pid().await?);
        let cgroup =
            parse_exact_cgroup(&role.expected_cgroup(name), service.control_group().await?)?;

        let environment_after = service.environment().await?;
        let invocation_after = parse_invocation_id(unit.invocation_id().await?)?;
        let id_after = unit.id().await?;
        if id_before != expected_name
            || id_after != expected_name
            || id_before != id_after
            || invocation_before != invocation_after
            || environment_before != environment_after
        {
            return Err(Error::InvalidSandboxUnit(
                "unit identity changed during reference-held observation".to_owned(),
            ));
        }

        Ok(ExactUnitObservation {
            role,
            object_path: reference.object_path.clone(),
            binding,
            invocation_id: invocation_after,
            active_state: active_state.clone(),
            sub_state: sub_state.clone(),
            state: ExactUnitState::from_manager(&active_state, &sub_state),
            cgroup,
            main_pid,
        })
    }
}

async fn finish_reference<T>(
    manager: &ManagerProxy<'static>,
    reference: &UnitReference,
    result: Result<T>,
) -> Result<T> {
    let released = reference.release(manager).await;
    match (result, released) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

async fn finish_exact_stop<T, E>(
    manager: &ManagerProxy<'static>,
    reference: &UnitReference,
    result: std::result::Result<T, ExactStopError<E>>,
) -> std::result::Result<T, ExactStopError<E>> {
    let released = reference
        .release(manager)
        .await
        .map_err(ExactStopError::Systemd);
    match (result, released) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

async fn finish_connection<T>(client: ExactUnitClient, result: Result<T>) -> Result<T> {
    let closed = close_connection(&client.client.conn).await;
    match (result, closed) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

async fn finish_exact_connection<T, E>(
    client: ExactUnitClient,
    result: std::result::Result<T, ExactStopError<E>>,
) -> std::result::Result<T, ExactStopError<E>> {
    let closed = close_connection(&client.client.conn)
        .await
        .map_err(ExactStopError::Systemd);
    match (result, closed) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

async fn close_connection(connection: &zbus::Connection) -> Result<()> {
    tokio::time::timeout(REFERENCE_OPERATION_TIMEOUT, connection.clone().close())
        .await
        .map_err(|_| Error::ExactUnitTimeout("connection close"))??;
    Ok(())
}

pub(super) fn prepare_then_guard<T, E>(
    prepare: impl FnOnce() -> Result<T>,
    before_submission: &mut (dyn FnMut() -> std::result::Result<(), E> + Send),
) -> std::result::Result<T, ExactStartError<E>> {
    let prepared = prepare().map_err(ExactStartError::Systemd)?;
    before_submission().map_err(ExactStartError::Guard)?;
    Ok(prepared)
}

pub(super) fn parse_launch_binding(
    environment: &[String],
    role: ExactUnitRole,
) -> Result<Option<[u8; 32]>> {
    let prefix = role.binding_prefix();
    let mut values = environment
        .iter()
        .filter_map(|entry| entry.strip_prefix(prefix));
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() || value.len() != 64 {
        return Err(Error::InvalidSandboxUnit(
            "unit environment has a repeated or malformed launch binding".to_owned(),
        ));
    }

    let mut binding = [0; 32];
    for (output, pair) in binding.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *output = super::decode_hex(pair[0])
            .and_then(|high| high.checked_mul(16))
            .and_then(|high| super::decode_hex(pair[1]).and_then(|low| high.checked_add(low)))
            .ok_or_else(|| {
                Error::InvalidSandboxUnit(
                    "unit launch binding is not canonical lowercase hexadecimal".to_owned(),
                )
            })?;
    }
    if binding == [0; 32] {
        return Err(Error::InvalidSandboxUnit(
            "unit launch binding is zero".to_owned(),
        ));
    }
    Ok(Some(binding))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_specific_binding_parser_is_strict() {
        let guardian = format!("{GUARDIAN_BINDING_PREFIX}{}", "ab".repeat(32));
        let payload = format!("{PAYLOAD_BINDING_PREFIX}{}", "cd".repeat(32));
        assert_eq!(
            parse_launch_binding(std::slice::from_ref(&guardian), ExactUnitRole::Guardian).unwrap(),
            Some([0xab; 32])
        );
        assert_eq!(
            parse_launch_binding(std::slice::from_ref(&payload), ExactUnitRole::Payload).unwrap(),
            Some([0xcd; 32])
        );
        assert_eq!(
            parse_launch_binding(&[payload], ExactUnitRole::Guardian).unwrap(),
            None
        );
        assert!(
            parse_launch_binding(&[guardian.clone(), guardian], ExactUnitRole::Guardian).is_err()
        );
        assert!(
            parse_launch_binding(
                &[format!("{PAYLOAD_BINDING_PREFIX}{}", "AB".repeat(32))],
                ExactUnitRole::Payload,
            )
            .is_err()
        );
        assert!(
            parse_launch_binding(
                &[format!("{PAYLOAD_BINDING_PREFIX}{}", "00".repeat(32))],
                ExactUnitRole::Payload,
            )
            .is_err()
        );
    }

    #[test]
    fn target_rejects_sentinel_identities() {
        assert!(ExactUnitTarget::new([0; 32], [1; 16]).is_err());
        assert!(ExactUnitTarget::new([1; 32], [0; 16]).is_err());
        assert!(ExactUnitTarget::new([1; 32], [2; 16]).is_ok());
    }
}
