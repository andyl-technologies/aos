//! `aos-systemd` — a typed, async client for `org.freedesktop.systemd1` over
//! D-Bus (zbus 5).
//!
//! This crate is the *transport* layer: it speaks to systemd directly so apm
//! can propagate job results, classify outcomes, and read unit properties
//! without shelling out to `systemctl`. It has no apm- or apr-specific
//! knowledge and deliberately does not depend on `aos-core`.
//!
//! Entry point: [`SystemdClient::connect`].

mod client;
mod error;
mod manager_proxy;
mod sandbox;

pub use client::{
    FailedUnit, FailedUnitsReport, JobOutcome, JobResult, RestartPolicy, SettleOutcome,
    SystemdClient,
};
pub use error::{Error, Result};
pub use manager_proxy::ListUnitsEntry;
pub use sandbox::{
    CpuWeight, FreezerState, SandboxCgroupPath, SandboxDevice, SandboxResources, SandboxUnitName,
    SandboxUnitObservation, SandboxUnitSpec,
};

// `unit_property` returns a `zbus::zvariant::OwnedValue` in its public
// signature. Re-export it (and `Value`, needed to inspect the variant) so
// downstream consumers can name and destructure the result without taking a
// direct zbus dependency of their own.
pub use zbus::zvariant::{OwnedValue, Value};
