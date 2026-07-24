//! Crucible-shmem network attachment for deterministic QEMU launches.
//!
//! A [`CrucibleShmemNetworkDevice`] attaches a stock virtio-net front-end to an
//! otherwise unconnected emulated QEMU hub. The carried
//! `0020-crucible-net-tx-callback` patch diverts guest TX frames to the loaded
//! Crucible plugin before the hub sees them, and the plugin delivers scheduled
//! RX frames through the lossless queue exported by
//! `0009-crucible-net-deterministic`.
//!
//! The hub has no host network backend. It exists only to give the NIC the peer
//! QEMU's queue API requires, so no host socket, TAP interface, helper, or user
//! networking implementation can originate or receive application traffic.
//!
//! ```text
//! -netdev hubport,id=crucible-netdev0,hubid=0
//! -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56
//! ```

use super::QemuLaunchCommandError;

/// Default hostless hub-port netdev identifier.
pub const DEFAULT_CRUCIBLE_SHMEM_NETDEV_ID: &str = "crucible-netdev0";

/// Default virtio-net device identifier.
pub const DEFAULT_CRUCIBLE_SHMEM_NETWORK_DEVICE_ID: &str = "crucible-net-device0";

/// Default fixed locally administered guest MAC address.
pub const DEFAULT_CRUCIBLE_SHMEM_NETWORK_MAC: &str = "52:54:00:12:34:56";

/// A deterministic Crucible network device attached to a launched guest.
///
/// The attached QEMU hub has no external backend. Guest TX and scheduled RX are
/// therefore possible only through the loaded Crucible plugin and its shared
/// memory frame rings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrucibleShmemNetworkDevice {
    netdev_id: String,
    device_id: String,
    mac: String,
    hub_id: u32,
}

impl CrucibleShmemNetworkDevice {
    /// Builds a hostless virtio-net attachment with fixed default identity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            netdev_id: DEFAULT_CRUCIBLE_SHMEM_NETDEV_ID.to_owned(),
            device_id: DEFAULT_CRUCIBLE_SHMEM_NETWORK_DEVICE_ID.to_owned(),
            mac: DEFAULT_CRUCIBLE_SHMEM_NETWORK_MAC.to_owned(),
            hub_id: 0,
        }
    }

    /// Returns the device with explicit netdev and device identifiers.
    #[must_use]
    pub fn with_ids(mut self, netdev_id: impl Into<String>, device_id: impl Into<String>) -> Self {
        self.netdev_id = netdev_id.into();
        self.device_id = device_id.into();
        self
    }

    /// Returns the device with an explicit fixed guest MAC address.
    #[must_use]
    pub fn with_mac(mut self, mac: impl Into<String>) -> Self {
        self.mac = mac.into();
        self
    }

    /// Returns the device attached to a different emulated hub.
    #[must_use]
    pub const fn with_hub_id(mut self, hub_id: u32) -> Self {
        self.hub_id = hub_id;
        self
    }

    /// Returns the hostless hub-port netdev identifier.
    #[must_use]
    pub fn netdev_id(&self) -> &str {
        &self.netdev_id
    }

    /// Returns the virtio-net device identifier.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Returns the fixed guest MAC address.
    #[must_use]
    pub fn mac(&self) -> &str {
        &self.mac
    }

    /// Returns the emulated QEMU hub identifier.
    #[must_use]
    pub const fn hub_id(&self) -> u32 {
        self.hub_id
    }

    /// Appends the hostless hub-port and virtio-net arguments.
    pub(crate) fn append_qemu_args(&self, args: &mut Vec<String>) {
        args.extend([
            "-netdev".to_owned(),
            format!("hubport,id={},hubid={}", self.netdev_id, self.hub_id),
            "-device".to_owned(),
            format!(
                "virtio-net-pci,netdev={},id={},mac={}",
                self.netdev_id, self.device_id, self.mac
            ),
        ]);
    }

    /// Appends canonical launch-identity lines describing this attachment.
    pub(super) fn append_hash_material(&self, lines: &mut Vec<String>) {
        lines.extend([
            "crucible_shmem_network=present".to_owned(),
            "crucible_shmem_network_backend=hostless-hubport".to_owned(),
            format!("crucible_shmem_network_netdev_id={}", self.netdev_id),
            format!("crucible_shmem_network_device_id={}", self.device_id),
            format!("crucible_shmem_network_mac={}", self.mac),
            format!("crucible_shmem_network_hub_id={}", self.hub_id),
        ]);
    }

    /// Validates option identifiers and the canonical MAC representation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLaunchCommandError::InvalidLaunchText`] when an identifier
    /// contains option delimiters or when the MAC is not six lowercase
    /// hexadecimal octets separated by colons.
    pub(crate) fn validate(&self) -> Result<(), QemuLaunchCommandError> {
        validate_option_token("crucible_shmem_network_netdev_id", &self.netdev_id)?;
        validate_option_token("crucible_shmem_network_device_id", &self.device_id)?;
        if !is_canonical_mac(&self.mac) {
            return Err(QemuLaunchCommandError::InvalidLaunchText {
                field: "crucible_shmem_network_mac",
            });
        }
        Ok(())
    }
}

impl Default for CrucibleShmemNetworkDevice {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_option_token(field: &'static str, value: &str) -> Result<(), QemuLaunchCommandError> {
    super::validate_launch_text(field, value)?;
    if value.contains(',') || value.contains('=') {
        return Err(QemuLaunchCommandError::InvalidLaunchText { field });
    }
    Ok(())
}

fn is_canonical_mac(mac: &str) -> bool {
    let mut octets = mac.split(':');
    let valid = octets.by_ref().take(6).all(|octet| {
        octet.len() == 2
            && octet
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    valid && octets.next().is_none() && mac.matches(':').count() == 5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_attachment_uses_only_a_hostless_hubport() {
        let device = CrucibleShmemNetworkDevice::new();
        let mut args = Vec::new();
        device.append_qemu_args(&mut args);
        assert_eq!(
            args,
            vec![
                "-netdev",
                "hubport,id=crucible-netdev0,hubid=0",
                "-device",
                "virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56",
            ]
        );
        assert!(
            args.iter().all(|arg| !arg.contains("user")
                && !arg.contains("tap")
                && !arg.contains("socket"))
        );
    }

    #[test]
    fn attachment_identity_covers_every_field() {
        let device = CrucibleShmemNetworkDevice::new()
            .with_ids("net-a", "nic-a")
            .with_mac("52:54:00:aa:bb:cc")
            .with_hub_id(7);
        let mut lines = Vec::new();
        device.append_hash_material(&mut lines);
        assert_eq!(
            lines,
            vec![
                "crucible_shmem_network=present",
                "crucible_shmem_network_backend=hostless-hubport",
                "crucible_shmem_network_netdev_id=net-a",
                "crucible_shmem_network_device_id=nic-a",
                "crucible_shmem_network_mac=52:54:00:aa:bb:cc",
                "crucible_shmem_network_hub_id=7",
            ]
        );
    }

    #[test]
    fn validation_rejects_option_injection_and_noncanonical_mac() {
        assert!(
            CrucibleShmemNetworkDevice::new()
                .with_ids("net,model=user", "nic")
                .validate()
                .is_err()
        );
        assert!(
            CrucibleShmemNetworkDevice::new()
                .with_mac("52:54:00:AA:BB:CC")
                .validate()
                .is_err()
        );
        assert!(
            CrucibleShmemNetworkDevice::new()
                .with_mac("52:54:00:aa:bb")
                .validate()
                .is_err()
        );
    }
}
