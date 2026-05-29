//! Hand-written zbus proxy traits for `org.freedesktop.systemd1`.
//!
//! No `zbus-xmlgen` build dependency, no codegen step — the surface we use is
//! narrow (~12 methods, 3 signals, a handful of properties) and inlining the
//! `#[proxy]` traits keeps the diff reviewable.
//!
//! Signatures verified against current systemd source at
//! `src/core/dbus-manager.c`:
//!   - `JobRemoved` = `(u id, o job, s unit, s result)`  (:3448-3450)
//!   - `Reloading`  = `(b active)`                         (:3455-3457)
//!   - `Reexecute`  is `SD_BUS_VTABLE_METHOD_NO_REPLY`     (:3252)
//!   - `Subscribe` semantics (API-bus peers get no signals until subscribed)
//!     (:1376-1410, `method_subscribe`)

use zbus::zvariant::OwnedObjectPath;

/// `org.freedesktop.systemd1.Manager`.
#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
pub trait Manager {
    fn subscribe(&self) -> zbus::Result<()>;
    fn unsubscribe(&self) -> zbus::Result<()>;

    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn stop_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn restart_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn reload_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;

    /// `Manager.Reload()` — the D-Bus equivalent of `systemctl daemon-reload`.
    fn reload(&self) -> zbus::Result<()>;

    /// Re-execute systemd (PID 1). Declared `no_reply` because systemd marks
    /// it `SD_BUS_VTABLE_METHOD_NO_REPLY` (dbus-manager.c:3252) — without the
    /// annotation zbus would block forever awaiting a reply that is
    /// contractually never sent. No apm caller in v1; declared for surface
    /// stability only (spec §10.1).
    #[zbus(no_reply)]
    fn reexecute(&self) -> zbus::Result<()>;

    fn reset_failed(&self) -> zbus::Result<()>;
    fn reset_failed_unit(&self, name: &str) -> zbus::Result<()>;

    fn get_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    fn list_units_by_patterns(
        &self,
        states: &[&str],
        patterns: &[&str],
    ) -> zbus::Result<Vec<ListUnitsEntry>>;

    fn reboot(&self) -> zbus::Result<()>;

    #[zbus(signal)]
    fn job_new(&self, id: u32, job: OwnedObjectPath, unit: String) -> zbus::Result<()>;

    #[zbus(signal)]
    fn job_removed(
        &self,
        id: u32,
        job: OwnedObjectPath,
        unit: String,
        result: String,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    fn reloading(&self, active: bool) -> zbus::Result<()>;
}

/// `org.freedesktop.systemd1.Unit` — built per-path off a dynamic object path
/// returned by `get_unit` / `list_units_by_patterns`.
#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1"
)]
pub trait Unit {
    #[zbus(property)]
    fn active_state(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn sub_state(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn load_state(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn unit_file_state(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn fragment_path(&self) -> zbus::Result<String>;
}

/// `org.freedesktop.systemd1.Service` — per-path, for `.service` units only.
#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Service",
    default_service = "org.freedesktop.systemd1"
)]
pub trait Service {
    #[zbus(property)]
    fn exec_main_status(&self) -> zbus::Result<i32>;
}

/// One entry returned by `Manager.ListUnitsByPatterns` — D-Bus signature
/// `(ssssssouso)`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zbus::zvariant::Type)]
pub struct ListUnitsEntry {
    pub name: String,
    pub description: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub followed: String,
    pub object_path: OwnedObjectPath,
    pub job_id: u32,
    pub job_type: String,
    pub job_object_path: OwnedObjectPath,
}
