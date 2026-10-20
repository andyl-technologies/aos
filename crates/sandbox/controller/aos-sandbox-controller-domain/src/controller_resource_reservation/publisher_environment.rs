//! Retains the new selected Publisher profile's actual system-bus environment.
//!
//! The finite installed profile accepts an absent address or the byte-exact
//! fixed local endpoint used by the existing bounded PID1 observer. It rejects
//! all other effective addresses before observation/future construction. This
//! startup DATA check supplies neither a connection nor an admission witness;
//! the original Controller profile still owns its independent PID1 bookends.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

const ADDRESS: &str = "DBUS_SYSTEM_BUS_ADDRESS";
const LOCAL_SYSTEM_BUS: &[u8] = b"unix:path=/run/dbus/system_bus_socket";

/// Reports an unsupported, changed or repeated fixed process-bus readback.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
pub enum ControllerPublisherBusEnvironmentErrorV1 {
    /// The effective address is outside the selected fixed endpoint grammar.
    #[error("selected Publisher system-bus address is unsupported")]
    Unsupported,
    /// Independent actual process observations differ.
    #[error("selected Publisher system-bus environment changed")]
    Changed,
    /// The original capture is incomplete or has been entered again.
    #[error("selected Publisher system-bus observation is incomplete or repeated")]
    Closed,
}

/// Retains one fixed actual process-bus initial/final readback as passive DATA.
///
/// This owner creates no connection, payer, profile or observation permission.
#[doc(hidden)]
pub struct ControllerPublisherBusEnvironmentV1 {
    initial: Option<Option<OsString>>,
    initial_check: Option<Result<(), ControllerPublisherBusEnvironmentErrorV1>>,
    final_value: Option<Option<OsString>>,
    final_check: Option<Result<(), ControllerPublisherBusEnvironmentErrorV1>>,
    reentry: Option<ControllerPublisherBusEnvironmentErrorV1>,
}

impl ControllerPublisherBusEnvironmentV1 {
    /// Prepares empty original slots without reading the process environment.
    pub const fn new() -> Self {
        Self {
            initial: None,
            initial_check: None,
            final_value: None,
            final_check: None,
            reentry: None,
        }
    }

    // Selected startup has prepaid both inherited exec-profile string copies.
    // Unlike unit-file inspection this reads the effective process environment,
    // including values delivered through EnvironmentFile or inherited launch.
    /// Captures and retains the actual initial effective process address once.
    ///
    /// The actual role must prepay the inherited exec-profile string frontier.
    ///
    /// # Errors
    /// Retains unsupported address bytes and the original typed refusal.
    pub fn capture_initial(&mut self) -> Result<(), ()> {
        if self.initial.is_some() {
            self.reentry.get_or_insert(ControllerPublisherBusEnvironmentErrorV1::Closed);
            return Err(());
        }
        self.initial = Some(std::env::var_os(ADDRESS));
        self.initial_check = Some(match self.initial.as_ref() {
            Some(value) => require_local(value.as_deref()),
            None => Err(ControllerPublisherBusEnvironmentErrorV1::Closed),
        });
        if matches!(self.initial_check, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    // Runs even when the initial contract or an intervening constructor failed.
    /// Captures the independent final effective process address once.
    ///
    /// # Errors
    /// Retains unsupported, changed, incomplete or repeated native DATA checks.
    pub fn capture_final(&mut self) -> Result<(), ()> {
        if self.final_value.is_some() {
            self.reentry.get_or_insert(ControllerPublisherBusEnvironmentErrorV1::Closed);
            return Err(());
        }
        self.final_value = Some(std::env::var_os(ADDRESS));
        self.final_check = Some(match (self.initial.as_ref(), self.final_value.as_ref()) {
            (Some(initial), Some(final_value)) => require_same_local(
                initial.as_deref(), final_value.as_deref(),
            ),
            _ => Err(ControllerPublisherBusEnvironmentErrorV1::Closed),
        });
        if self.failure().is_none() && matches!(self.final_check, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Borrows the first original comparison/refusal without another read.
    pub fn failure(&self) -> Option<&ControllerPublisherBusEnvironmentErrorV1> {
        self.initial_check.as_ref().and_then(|result| result.as_ref().err())
            .or_else(|| self.final_check.as_ref().and_then(|result| result.as_ref().err()))
            .or(self.reentry.as_ref())
    }
}

fn require_local(address: Option<&OsStr>) -> Result<(), ControllerPublisherBusEnvironmentErrorV1> {
    match address {
        None => Ok(()),
        Some(address) if address.as_bytes() == LOCAL_SYSTEM_BUS => Ok(()),
        Some(_) => Err(ControllerPublisherBusEnvironmentErrorV1::Unsupported),
    }
}

fn require_same_local(
    initial: Option<&OsStr>,
    final_value: Option<&OsStr>,
) -> Result<(), ControllerPublisherBusEnvironmentErrorV1> {
    require_local(final_value)?;
    if initial == final_value {
        Ok(())
    } else {
        Err(ControllerPublisherBusEnvironmentErrorV1::Changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_absence_or_the_exact_fixed_local_endpoint_is_supported() {
        assert!(require_local(None).is_ok());
        assert!(require_local(Some(OsStr::from_bytes(LOCAL_SYSTEM_BUS))).is_ok());
        for unsupported in [
            b"".as_slice(), b"unix:path=/another/socket", b"unix:abstract=system",
            b"tcp:host=localhost,port=123", b"unixexec:path=/program",
            b"unix:path=/run/dbus/system_bus_socket;unix:path=/fallback",
            b"unix:path=/run/dbus/system_bus_socket,guid=0123456789abcdef0123456789abcdef",
            b"unix:path=/run/dbus/%73ystem_bus_socket", b"\xff",
        ] {
            assert!(matches!(require_local(Some(OsStr::from_bytes(unsupported))),
                Err(ControllerPublisherBusEnvironmentErrorV1::Unsupported)));
        }
    }

    #[test]
    fn actual_process_environment_is_retained_before_refusal() {
        const CHILD: &str = "AOS_TEST_SELECTED_PUBLISHER_BUS_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let mut owner = ControllerPublisherBusEnvironmentV1::new();
            assert!(owner.capture_initial().is_err());
            let first = std::ptr::from_ref(owner.failure().unwrap());

            assert!(owner.capture_final().is_err());
            assert!(owner.capture_initial().is_err());

            assert_eq!(owner.initial.as_ref().unwrap().as_deref(),
                Some(OsStr::new("unixexec:path=/unsupported")));
            assert_eq!(owner.initial, owner.final_value);
            assert_eq!(first, std::ptr::from_ref(owner.failure().unwrap()));
            return;
        }

        // A fresh process supplies a real inherited environment without
        // mutating this multithreaded test process's global environment.
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("controller_resource_reservation::publisher_environment::tests::actual_process_environment_is_retained_before_refusal")
            .env(CHILD, "1")
            .env(ADDRESS, "unixexec:path=/unsupported")
            .status().unwrap();

        assert!(status.success());
    }

    #[test]
    fn effective_absence_to_explicit_local_change_still_refuses_currentness() {
        let explicit = Some(OsStr::from_bytes(LOCAL_SYSTEM_BUS));
        assert!(require_same_local(None, None).is_ok());
        assert!(require_same_local(explicit, explicit).is_ok());
        assert!(matches!(require_same_local(None, explicit),
            Err(ControllerPublisherBusEnvironmentErrorV1::Changed)));
        assert!(matches!(require_same_local(explicit, None),
            Err(ControllerPublisherBusEnvironmentErrorV1::Changed)));
    }
}
