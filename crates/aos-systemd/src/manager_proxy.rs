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

use zbus::zvariant::{OwnedObjectPath, OwnedValue};

/// One name/value entry in systemd's transient-unit property array.
pub(crate) type TransientProperty = (String, OwnedValue);

/// One auxiliary unit passed alongside a transient unit.
pub(crate) type AuxiliaryUnit = (String, Vec<TransientProperty>);

/// `org.freedesktop.systemd1.Manager`.
#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
pub trait Manager {
    /// Opt this API-bus peer into receiving manager signals
    /// (`JobNew`/`JobRemoved`/`Reloading`); without it systemd sends none.
    fn subscribe(&self) -> zbus::Result<()>;
    /// Undo [`subscribe`](Self::subscribe); signals stop flowing.
    fn unsubscribe(&self) -> zbus::Result<()>;

    /// Enqueue a start job for `name`; returns the job object path.
    /// `mode` is a systemd job mode (`"replace"`, `"isolate"`, ...).
    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    /// Enqueue a stop job for `name`; returns the job object path.
    fn stop_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    /// Enqueue a restart job for `name`; returns the job object path.
    fn restart_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    /// Enqueue a reload job for `name`; returns the job object path.
    fn reload_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;

    /// Atomically load and enqueue a start job for a transient unit.
    fn start_transient_unit(
        &self,
        name: &str,
        mode: &str,
        properties: &[TransientProperty],
        auxiliary_units: &[AuxiliaryUnit],
    ) -> zbus::Result<OwnedObjectPath>;

    /// Freeze every process in a unit's cgroup subtree.
    fn freeze_unit(&self, name: &str) -> zbus::Result<()>;
    /// Thaw every process in a unit's cgroup subtree.
    fn thaw_unit(&self, name: &str) -> zbus::Result<()>;
    /// Deliver one signal to the selected process set of a loaded unit.
    fn kill_unit(&self, name: &str, whom: &str, signal: i32) -> zbus::Result<()>;

    /// `Manager.Reload()` — the D-Bus equivalent of `systemctl daemon-reload`.
    fn reload(&self) -> zbus::Result<()>;

    /// Re-execute systemd (PID 1). Declared `no_reply` because systemd marks
    /// it `SD_BUS_VTABLE_METHOD_NO_REPLY` (dbus-manager.c:3252) — without the
    /// annotation zbus would block forever awaiting a reply that is
    /// contractually never sent. No apm caller in v1; declared for surface
    /// stability only (spec §10.1).
    #[zbus(no_reply)]
    fn reexecute(&self) -> zbus::Result<()>;

    /// Clear the "failed" state of all units (`systemctl reset-failed`).
    fn reset_failed(&self) -> zbus::Result<()>;
    /// Clear the "failed" state of a single unit.
    fn reset_failed_unit(&self, name: &str) -> zbus::Result<()>;

    /// Resolve a unit name to its object path; fails with `NoSuchUnit`
    /// if the unit is not currently loaded.
    fn get_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    /// List units filtered by active states and shell-glob name patterns;
    /// empty slices mean "no filter".
    fn list_units_by_patterns(
        &self,
        states: &[&str],
        patterns: &[&str],
    ) -> zbus::Result<Vec<ListUnitsEntry>>;

    /// Queue a reboot (`systemctl reboot`); returns once queued, not when
    /// the reboot happens.
    fn reboot(&self) -> zbus::Result<()>;

    /// `JobNew` signal: a job was enqueued.
    #[zbus(signal)]
    fn job_new(&self, id: u32, job: OwnedObjectPath, unit: String) -> zbus::Result<()>;

    /// `JobRemoved` signal: a job finished; `result` is its terminal
    /// label (`"done"`, `"failed"`, `"timeout"`, ...).
    #[zbus(signal)]
    fn job_removed(
        &self,
        id: u32,
        job: OwnedObjectPath,
        unit: String,
        result: String,
    ) -> zbus::Result<()>;

    /// `Reloading` signal: emitted with `active = true` when a daemon
    /// reload begins and `false` when it completes.
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
    /// Canonical primary name by which systemd loaded this unit.
    #[zbus(property)]
    fn id(&self) -> zbus::Result<String>;
    /// High-level activation state (`"active"`, `"failed"`, ...).
    #[zbus(property)]
    fn active_state(&self) -> zbus::Result<String>;
    /// Low-level, unit-type-specific state (`"running"`, `"auto-restart"`, ...).
    #[zbus(property)]
    fn sub_state(&self) -> zbus::Result<String>;
    /// Whether the unit file was loaded (`"loaded"`, `"not-found"`, ...).
    #[zbus(property)]
    fn load_state(&self) -> zbus::Result<String>;
    /// Install state of the unit file (`"enabled"`, `"masked"`, ...).
    #[zbus(property)]
    fn unit_file_state(&self) -> zbus::Result<String>;
    /// Filesystem path of the unit's fragment (its main unit file).
    #[zbus(property)]
    fn fragment_path(&self) -> zbus::Result<String>;
    /// Current cgroup freezer state (`running`, `freezing`, or `frozen`).
    #[zbus(property)]
    fn freezer_state(&self) -> zbus::Result<String>;
    /// Per-activation identifier; all zeroes while no invocation exists.
    #[zbus(property)]
    fn invocation_id(&self) -> zbus::Result<Vec<u8>>;
}

/// `org.freedesktop.systemd1.Service` — per-path, for `.service` units only.
#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Service",
    default_service = "org.freedesktop.systemd1"
)]
pub trait Service {
    /// Exit status (or signal number) of the service's main process.
    #[zbus(property)]
    fn exec_main_status(&self) -> zbus::Result<i32>;
    /// `RestartSec` — the delay systemd waits before each automatic restart,
    /// in microseconds. Named explicitly because the D-Bus property is
    /// `RestartUSec`, which the default snake-to-Pascal mapping would render
    /// `RestartUsec`.
    #[zbus(property, name = "RestartUSec")]
    fn restart_usec(&self) -> zbus::Result<u64>;
    /// `NRestarts` — count of automatic restarts systemd has performed for
    /// this service since it was last reset.
    #[zbus(property)]
    fn n_restarts(&self) -> zbus::Result<u32>;
    /// Current main PID, or zero when the service has none.
    #[zbus(property)]
    fn main_pid(&self) -> zbus::Result<u32>;
    /// Unit cgroup path relative to the cgroup-v2 root.
    #[zbus(property)]
    fn control_group(&self) -> zbus::Result<String>;
}

/// One entry returned by `Manager.ListUnitsByPatterns` — D-Bus signature
/// `(ssssssouso)`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zbus::zvariant::Type)]
pub struct ListUnitsEntry {
    /// Unit name, including the type suffix (e.g. `sshd.service`).
    pub name: String,
    /// Human-readable description from the unit file.
    pub description: String,
    /// Load state (`"loaded"`, `"not-found"`, `"masked"`, ...).
    pub load_state: String,
    /// Activation state (`"active"`, `"failed"`, `"activating"`, ...).
    pub active_state: String,
    /// Unit-type-specific sub-state (`"running"`, `"auto-restart"`, ...).
    pub sub_state: String,
    /// Name of the unit this one follows (alias targets); empty if none.
    pub followed: String,
    /// D-Bus object path of the unit.
    pub object_path: OwnedObjectPath,
    /// Numeric id of the queued job for this unit, or 0 if none.
    pub job_id: u32,
    /// Type of the queued job (`"start"`, `"stop"`, ...); empty if none.
    pub job_type: String,
    /// D-Bus object path of the queued job; `/` if none.
    pub job_object_path: OwnedObjectPath,
}
