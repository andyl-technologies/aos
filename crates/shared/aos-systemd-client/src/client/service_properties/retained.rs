//! Retains partial values and native bookends of the existing PID1 readers.
//!
//! These mechanical destinations create no manager connection, permission,
//! readiness, unit role or payment. The enclosing original prepays its actual
//! finite query and retains this whole owner through independently owed posts.

use super::*;
use zbus::proxy::ProxyImpl as _;

/// Reports a retained, interrupted or repeated property observation.
#[derive(Debug, thiserror::Error)]
#[error("original PID1 property observation remains incomplete or closed")]
pub struct ServicePropertiesReadClosedV2;

#[derive(Default)]
pub(super) struct BookendCaptureOriginalV2 {
    pub(super) bus: Option<zbus::fdo::DBusProxy<'static>>,
    pub(super) manager_name: Option<zbus::names::BusName<'static>>,
    pub(super) owner: Option<zbus::names::OwnedUniqueName>,
    pub(super) owner_pid: Option<u32>,
    pub(super) manager: Option<ManagerProxy<'static>>,
    pub(super) path: Option<zbus::zvariant::OwnedObjectPath>,
    pub(super) unit: Option<UnitProxy<'static>>,
    pub(super) service: Option<ServiceProxy<'static>>,
    pub(super) id: Option<String>,
    pub(super) active: Option<String>,
    pub(super) pid: Option<u32>,
    pub(super) invocation: Option<Vec<u8>>,
    pub(super) substate: Option<String>,
}

#[derive(Default)]
pub(super) struct BookendAfterOriginalV2 {
    pub(super) id: Option<String>,
    pub(super) active: Option<String>,
    pub(super) pid: Option<u32>,
    pub(super) invocation: Option<Vec<u8>>,
    pub(super) substate: Option<String>,
    pub(super) owner: Option<zbus::names::OwnedUniqueName>,
}

// These are actual systemd261.2 service vtable fields, not an issuer result.
// The same before/after unit tuple binds them to one completed invocation.
const SUCCESSFUL_ONESHOT_PROPERTIES_V1: &[&str] = &[
    "Type", "RemainAfterExit", "ExecMainCode", "ExecMainStatus", "Result",
];

/// Retains one active-service property read and all reached partial values.
///
/// The caller supplies its already-paid, original manager by borrow. The
/// unchanged unique-PID1 recipe and property loop execute once; the final
/// bookend is owed once initial capture succeeds, including primary refusal.
#[must_use = "retain the actual property and bookend prefixes through posts"]
pub struct ServicePropertiesReadOriginalV2 {
    capture: BookendCaptureOriginalV2,
    original: Option<ServicePropertyBookendV1<'static>>,
    properties: Option<zbus::fdo::PropertiesProxy<'static>>,
    service: Vec<OwnedValue>,
    unit: Vec<OwnedValue>,
    primary: Option<Result<()>>,
    after: BookendAfterOriginalV2,
    after_result: Option<Result<()>>,
    reentry: Option<Error>,
    entered: bool,
    transferred: bool,
    aliases_retired: bool,
}

impl ServicePropertiesReadOriginalV2 {
    /// Creates empty slots without connecting, observing or allocating arrays.
    #[must_use]
    pub fn new() -> Self {
        Self {
            capture: BookendCaptureOriginalV2::default(),
            original: None,
            properties: None,
            service: Vec::new(),
            unit: Vec::new(),
            primary: None,
            after: BookendAfterOriginalV2::default(),
            after_result: None,
            reentry: None,
            entered: false,
            transferred: false,
            aliases_retired: false,
        }
    }

    /// Bounds archive carriers and the real property-table arrays.
    ///
    /// Dynamic decoded values, raw messages and manager transport stay in the
    /// same canonical manager schedule. Names are bounded by the D-Bus unit
    /// name limit; no Rust field is a namespace entry.
    #[must_use]
    pub fn receiving_memory_bytes_v2(service_count: usize, unit_count: usize) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(
                service_count
                    .checked_add(unit_count)?
                    .checked_mul(std::mem::size_of::<OwnedValue>())?,
            )?
            .checked_add(255)
    }

    /// Observes an active unit through the same original manager and engine.
    ///
    /// # Errors
    /// Retains all partial capture/property values and the first native or
    /// semantic cause. The independent after bookend still runs after primary
    /// refusal once the original before bookend has actually been captured.
    pub async fn observe_once_v2(
        &mut self,
        client: &SystemdClient,
        name: &str,
        expected_pid: u32,
        service: &[&str],
        unit: &[&str],
    ) -> std::result::Result<(), ServicePropertiesReadClosedV2> {
        self.observe_selected_once_v2(
            client,
            name,
            expected_pid,
            service,
            unit,
            ObservationPhase::Active,
        )
        .await
    }

    /// Observes the same unit while starting or running through the same engine.
    ///
    /// # Errors
    /// Retains the same native prefixes and independent after as the active
    /// observation. Only the existing activating/start or active/running state
    /// predicate differs; this does not make the notify service ready.
    pub async fn observe_startup_once_v2(
        &mut self,
        client: &SystemdClient,
        name: &str,
        expected_pid: u32,
        service: &[&str],
        unit: &[&str],
    ) -> std::result::Result<(), ServicePropertiesReadClosedV2> {
        self.observe_selected_once_v2(
            client,
            name,
            expected_pid,
            service,
            unit,
            ObservationPhase::StartingOrRunning,
        )
        .await
    }

    /// Observes the completed successful invocation of a remain-after-exit oneshot.
    ///
    /// The supplied service roster must begin with Type, RemainAfterExit,
    /// ExecMainCode, ExecMainStatus and Result. Remaining property and unit
    /// reads use the same fixed schema, manager and retained prefix engine.
    /// This establishes observation DATA only, never floor/readiness authority.
    ///
    /// # Errors
    /// Rejects wrong roster or phase, a live main PID, missing/changed invocation,
    /// failure status, native refusal or reentry. The independently owed final
    /// tuple still runs after a returned primary refusal.
    pub async fn observe_successful_oneshot_once_v1(
        &mut self, client: &SystemdClient, name: &str,
        service: &[&str], unit: &[&str],
    ) -> std::result::Result<(), ServicePropertiesReadClosedV2> {
        self.observe_selected_once_v2(client, name, 0, service, unit,
            ObservationPhase::SuccessfulOneshot).await
    }

    /// Copies the actual fully bracketed invocation coordinate as comparison DATA.
    ///
    /// This borrows the native archive before positive alias retirement; no
    /// supplied bytes or success flag can install an invocation here.
    #[must_use]
    pub fn completed_invocation_data_v1(&self) -> Option<[u8;16]> {
        if !self.complete() { return None; }
        self.original.as_ref()?.before.3.as_slice().try_into().ok()
    }

    async fn observe_selected_once_v2(
        &mut self,
        client: &SystemdClient,
        name: &str,
        expected_pid: u32,
        service: &[&str],
        unit: &[&str],
        phase: ObservationPhase,
    ) -> std::result::Result<(), ServicePropertiesReadClosedV2> {
        self.observe_selected_deadline_once_v2(
            client,
            name,
            expected_pid,
            service,
            unit,
            phase,
            None,
        )
        .await
    }

    /// Observes an active unit with both stages bound by the original deadline.
    ///
    /// # Errors
    /// Parks the actual primary timeout before attempting its independently
    /// owed after. Both use the same supplied absolute deadline; no relative
    /// grace, reentry, replacement connection or successful-after replay occurs.
    pub async fn observe_deadline_once_v2(
        &mut self,
        client: &SystemdClient,
        name: &str,
        expected_pid: u32,
        service: &[&str],
        unit: &[&str],
        deadline: tokio::time::Instant,
    ) -> std::result::Result<(), ServicePropertiesReadClosedV2> {
        self.observe_selected_deadline_once_v2(
            client,
            name,
            expected_pid,
            service,
            unit,
            ObservationPhase::Active,
            Some(deadline),
        )
        .await
    }

    async fn observe_selected_deadline_once_v2(
        &mut self,
        client: &SystemdClient,
        name: &str,
        expected_pid: u32,
        service: &[&str],
        unit: &[&str],
        phase: ObservationPhase,
        deadline: Option<tokio::time::Instant>,
    ) -> std::result::Result<(), ServicePropertiesReadClosedV2> {
        if self.entered {
            self.reentry.get_or_insert_with(closed);
            return Err(ServicePropertiesReadClosedV2);
        }
        self.entered = true;
        if matches!(phase, ObservationPhase::SuccessfulOneshot)
            && !service.starts_with(SUCCESSFUL_ONESHOT_PROPERTIES_V1) {
            self.primary = Some(Err(changed("successful oneshot roster is incomplete")));
            return Err(ServicePropertiesReadClosedV2);
        }
        let primary = self.observe_body(client, name, expected_pid, service, unit, phase);
        self.primary = Some(match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, primary)
                .await
                .unwrap_or_else(|_| Err(Error::ExactUnitTimeout("service property primary"))),
            None => primary.await,
        });
        if let Some(original) = self.original.as_ref() {
            let after = finish_service_property_bookend_into_v2(
                &original.bus,
                original.manager_name.clone(),
                &original.owner,
                &original.unit,
                &original.service,
                original.name.as_ref(),
                original.expected_main_pid,
                original.phase,
                &original.before,
                original.before_substate.as_deref(),
                original.decoding,
                &mut self.after,
            );
            self.after_result = Some(match deadline {
                Some(deadline) => tokio::time::timeout_at(deadline, after)
                    .await
                    .unwrap_or_else(|_| Err(Error::ExactUnitTimeout("service property after"))),
                None => after.await,
            });
        }
        if self.complete() {
            Ok(())
        } else {
            Err(ServicePropertiesReadClosedV2)
        }
    }

    async fn observe_body(
        &mut self,
        client: &SystemdClient,
        name: &str,
        expected_pid: u32,
        service: &[&str],
        unit: &[&str],
        phase: ObservationPhase,
    ) -> Result<()> {
        // Refuse before copying a hostile name. The enclosing query owns the
        // real allowed unit/expected PID comparison; this is only byte custody.
        if name.len() > 255 {
            return Err(changed("service name exceeds D-Bus bound"));
        }
        self.original = Some(
            ServicePropertyBookendV1::capture_inner_into(
                &client.conn,
                Cow::Owned(name.to_owned()),
                expected_pid,
                phase,
                false,
                PropertyDecodingV1::for_client(client),
                &mut self.capture,
            )
            .await?,
        );
        let original = self.original.as_ref().ok_or_else(closed)?;
        self.properties = Some(
            zbus::fdo::PropertiesProxy::builder(&client.conn)
                .destination(original.owner.clone())?
                .path(original.path.clone())?
                .build()
                .await?,
        );
        self.service = Vec::with_capacity(service.len());
        self.unit = Vec::with_capacity(unit.len());
        let properties = self.properties.as_ref().ok_or_else(closed)?;
        read_properties_into_v2(
            properties,
            "org.freedesktop.systemd1.Service",
            service,
            original.service.inner(),
            original.decoding,
            &mut self.service,
        )
        .await?;
        read_properties_into_v2(
            properties,
            "org.freedesktop.systemd1.Unit",
            unit,
            original.unit.inner(),
            original.decoding,
            &mut self.unit,
        )
        .await?;
        if matches!(phase, ObservationPhase::SuccessfulOneshot) {
            require_successful_oneshot_values_v1(&self.service)?;
        }
        Ok(())
    }

    fn complete(&self) -> bool {
        !self.transferred
            && self.reentry.is_none()
            && matches!(self.primary, Some(Ok(())))
            && matches!(self.after_result, Some(Ok(())))
    }

    /// Borrows service values only after the actual primary and after succeed.
    #[must_use]
    pub fn service_values_v2(&self) -> Option<&[OwnedValue]> {
        self.complete().then_some(self.service.as_slice())
    }

    /// Borrows unit values only after the actual primary and after succeed.
    #[must_use]
    pub fn unit_values_v2(&self) -> Option<&[OwnedValue]> {
        self.complete().then_some(self.unit.as_slice())
    }

    /// Moves only the actual complete property tables once, without another read.
    #[must_use]
    pub fn take_completed_v2(&mut self) -> Option<(Vec<OwnedValue>, Vec<OwnedValue>)> {
        if !self.complete() {
            return None;
        }
        self.transferred = true;
        Some((
            std::mem::take(&mut self.service),
            std::mem::take(&mut self.unit),
        ))
    }

    /// Retires only successful native connection aliases after the real bookend.
    ///
    /// Values and native/semantic results remain resident. Failure and partial
    /// capture cannot enter this disposition, nor can it reopen the manager.
    #[must_use]
    pub fn retire_completed_native_aliases_v2(&mut self) -> bool {
        if self.aliases_retired
            || self.reentry.is_some()
            || !matches!(self.primary, Some(Ok(())))
            || !matches!(self.after_result, Some(Ok(())))
        {
            return false;
        }
        drop(self.properties.take());
        drop(self.original.take());
        self.aliases_retired = true;
        true
    }

    /// Borrows the primary original cause before any owed-after or reentry cause.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        error(&self.primary)
            .or_else(|| error(&self.after_result))
            .or(self.reentry.as_ref())
    }
}

impl Default for ServicePropertiesReadOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

/// Retains the exact existing ten-call service/cgroup locator observation.
///
/// The path remains DATA. The caller independently pins its compiled native
/// cgroup and process. This owner neither connects nor selects another reader.
#[must_use = "retain the original service/cgroup read through enclosing posts"]
pub struct ServiceControlGroupReadOriginalV2 {
    path: Option<zbus::zvariant::OwnedObjectPath>,
    unit: Option<UnitProxy<'static>>,
    service: Option<ServiceProxy<'static>>,
    before: BookendAfterOriginalV2,
    control_group: Option<String>,
    primary: Option<Result<()>>,
    after_result: Option<Result<()>>,
    after: BookendAfterOriginalV2,
    result: Option<Result<super::super::ServiceControlGroupObservation>>,
    entered: bool,
    reentry: Option<Error>,
    aliases_retired: bool,
}

impl ServiceControlGroupReadOriginalV2 {
    /// Creates empty retained slots without issuing a manager call.
    #[must_use]
    pub fn new() -> Self {
        Self {
            path: None,
            unit: None,
            service: None,
            before: BookendAfterOriginalV2::default(),
            control_group: None,
            primary: None,
            after_result: None,
            after: BookendAfterOriginalV2::default(),
            result: None,
            entered: false,
            reentry: None,
            aliases_retired: false,
        }
    }

    /// Bounds the original carrier; dynamic strings remain in the manager quote.
    #[must_use]
    pub fn receiving_memory_bytes_v2() -> usize {
        std::mem::size_of::<Self>() * 2
    }

    /// Enters the sole ten-call control-group observation once.
    ///
    /// # Errors
    /// Retains actual partial tuples and original errors on native refusal.
    pub async fn observe_once_v2(
        &mut self,
        client: &SystemdClient,
        name: &str,
    ) -> std::result::Result<(), ServicePropertiesReadClosedV2> {
        if self.entered {
            self.reentry.get_or_insert_with(closed);
            return Err(ServicePropertiesReadClosedV2);
        }
        self.entered = true;
        self.result = Some(self.observe_body_into(client, name, true).await);
        if self.completed_v2().is_some() {
            Ok(())
        } else {
            Err(ServicePropertiesReadClosedV2)
        }
    }

    pub(in crate::client) async fn observe_body(
        &mut self,
        client: &SystemdClient,
        name: &str,
    ) -> Result<super::super::ServiceControlGroupObservation> {
        self.observe_body_into(client, name, false).await
    }

    async fn observe_body_into(
        &mut self,
        client: &SystemdClient,
        name: &str,
        retained: bool,
    ) -> Result<super::super::ServiceControlGroupObservation> {
        if !name.ends_with(".service") || name.contains('/') || name.contains('\0') {
            return Err(Error::InvalidSandboxUnit(
                "service name is not an exact unit name".to_owned(),
            ));
        }
        self.path = Some(client.manager.get_unit(name).await?);
        self.unit = Some(
            UnitProxy::builder(&client.conn)
                .path(self.path.as_ref().ok_or_else(closed)?.clone())?
                .cache_properties(CacheProperties::No)
                .build()
                .await?,
        );
        self.service = Some(
            ServiceProxy::builder(&client.conn)
                .path(self.path.as_ref().ok_or_else(closed)?.clone())?
                .cache_properties(CacheProperties::No)
                .build()
                .await?,
        );
        let unit = self.unit.as_ref().ok_or_else(closed)?;
        let service = self.service.as_ref().ok_or_else(closed)?;
        // Preserve the original ten-call order and short circuits. This
        // lower read does not add a new after RPC after an unreturned call.
        let decoding = PropertyDecodingV1::for_client(client);
        self.before.id = Some(decoding.get::<String>(unit.inner(), "Id").await?);
        self.before.invocation = Some(
            decoding
                .get::<Vec<u8>>(unit.inner(), "InvocationID")
                .await?,
        );
        self.before.active = Some(decoding.get::<String>(unit.inner(), "ActiveState").await?);
        self.before.pid = Some(decoding.get::<u32>(service.inner(), "MainPID").await?);
        self.primary = Some(
            async {
                self.control_group = Some(
                    decoding
                        .get::<String>(service.inner(), "ControlGroup")
                        .await?,
                );
                Ok(())
            }
            .await,
        );
        if !retained && matches!(self.primary, Some(Err(_))) {
            return self
                .primary
                .take()
                .ok_or_else(closed)?
                .and_then(|()| Err(closed()));
        }
        self.after_result = Some(
            async {
                self.after.pid = Some(decoding.get::<u32>(service.inner(), "MainPID").await?);
                self.after.active =
                    Some(decoding.get::<String>(unit.inner(), "ActiveState").await?);
                self.after.invocation = Some(
                    decoding
                        .get::<Vec<u8>>(unit.inner(), "InvocationID")
                        .await?,
                );
                self.after.id = Some(decoding.get::<String>(unit.inner(), "Id").await?);
                Ok(())
            }
            .await,
        );
        if !matches!(self.primary, Some(Ok(()))) || !matches!(self.after_result, Some(Ok(()))) {
            if !retained {
                return self
                    .after_result
                    .take()
                    .ok_or_else(closed)?
                    .and_then(|()| Err(closed()));
            }
            return Err(closed());
        }
        let before = (
            self.before.id.as_deref().ok_or_else(closed)?,
            self.before.active.as_deref().ok_or_else(closed)?,
            self.before.pid.ok_or_else(closed)?,
            self.before.invocation.as_deref().ok_or_else(closed)?,
        );
        let after = (
            self.after.id.as_deref().ok_or_else(closed)?,
            self.after.active.as_deref().ok_or_else(closed)?,
            self.after.pid.ok_or_else(closed)?,
            self.after.invocation.as_deref().ok_or_else(closed)?,
        );
        let group = self.control_group.as_ref().ok_or_else(closed)?;
        let (invocation_id, main_pid) =
            validate_control_group_parts_v2(name, before, after, group)?;
        Ok(super::super::ServiceControlGroupObservation {
            control_group: self.control_group.take().ok_or_else(closed)?,
            main_pid,
            invocation_id,
        })
    }

    /// Borrows only the actual complete locator observation.
    #[must_use]
    pub fn completed_v2(&self) -> Option<&super::super::ServiceControlGroupObservation> {
        if self.reentry.is_some() {
            return None;
        }
        self.result.as_ref()?.as_ref().ok()
    }

    /// Retires successful proxy aliases only after the actual complete read.
    #[must_use]
    pub fn retire_completed_native_aliases_v2(&mut self) -> bool {
        if self.aliases_retired || self.completed_v2().is_none() {
            return false;
        }
        drop(self.service.take());
        drop(self.unit.take());
        self.aliases_retired = true;
        true
    }

    /// Borrows the actual first native or semantic refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        error(&self.primary)
            .or_else(|| error(&self.after_result))
            .or_else(|| error(&self.result))
            .or(self.reentry.as_ref())
    }
}

impl Default for ServiceControlGroupReadOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) fn validate_control_group_parts_v2(
    name: &str,
    before: (&str, &str, u32, &[u8]),
    after: (&str, &str, u32, &[u8]),
    group: &str,
) -> Result<([u8; 16], std::num::NonZeroU32)> {
    let invocation: [u8; 16] = before
        .3
        .try_into()
        .map_err(|_| changed("service invocation is invalid"))?;
    let pid =
        std::num::NonZeroU32::new(before.2).ok_or_else(|| changed("service main PID is absent"))?;
    let normalized = group.len() <= 4096
        && group.starts_with('/')
        && group
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains('\0'));
    if before != after
        || before.0 != name
        || before.1 != "active"
        || invocation == [0; 16]
        || !normalized
    {
        return Err(changed(
            "service identity or cgroup changed during observation",
        ));
    }
    Ok((invocation, pid))
}

fn require_successful_oneshot_values_v1(values: &[OwnedValue]) -> Result<()> {
    let Some([kind, remain, code, status, result]) = values.get(..5) else {
        return Err(changed("successful oneshot readback is incomplete"));
    };
    if <&str>::try_from(kind).ok() != Some("oneshot")
        || bool::try_from(remain).ok() != Some(true)
        || i32::try_from(code).ok() != Some(1) // Linux CLD_EXITED.
        || i32::try_from(status).ok() != Some(0)
        || <&str>::try_from(result).ok() != Some("success") {
        return Err(changed("oneshot invocation did not finish successfully"));
    }
    Ok(())
}

fn error<T>(result: &Option<Result<T>>) -> Option<&Error> {
    result.as_ref().and_then(|result| result.as_ref().err())
}

pub(super) fn closed() -> Error {
    changed("original PID1 property reader is closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_oneshot_requires_real_exit_code_and_zero_status() {
        fn fields(code: i32, status: i32) -> Vec<OwnedValue> {
            vec![OwnedValue::from_static_value(zbus::zvariant::Value::from("oneshot")),
                OwnedValue::from(true), OwnedValue::from(code), OwnedValue::from(status),
                OwnedValue::from_static_value(zbus::zvariant::Value::from("success"))]
        }
        assert!(require_successful_oneshot_values_v1(&fields(1, 0)).is_ok());
        assert!(require_successful_oneshot_values_v1(&fields(0, 0)).is_err());
        assert!(require_successful_oneshot_values_v1(&fields(2, 0)).is_err());
        assert!(require_successful_oneshot_values_v1(&fields(1, 1)).is_err());
        assert!(require_successful_oneshot_values_v1(&[]).is_err());
    }

    #[test]
    fn primary_failure_survives_a_distinct_failed_after_and_reentry() {
        let mut original = ServicePropertiesReadOriginalV2::new();
        original.service.push(OwnedValue::from(7_u32));
        original.primary = Some(Err(changed("primary property failed")));
        original.after_result = Some(Err(changed("after bookend failed")));
        original.reentry = Some(changed("reentry"));
        let first = error(&original.primary).unwrap() as *const Error;

        assert_eq!(original.failure().unwrap() as *const Error, first);
        assert_eq!(original.service.len(), 1);
        assert!(original.take_completed_v2().is_none());
    }
}
