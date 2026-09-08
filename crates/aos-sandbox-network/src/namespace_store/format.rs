//! Canonical names, bounded activation, replay, and systemd dump decoding.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{BorrowedFd, OwnedFd};

use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceIdentity, NamespaceKind};
use aos_sandbox_linux::seqpacket::RecordSubjectListener;
use rustix::fs::{FileType, Mode};

use super::NetworkNamespaceStoreError;

const NAME_PREFIX: &str = "aos-network-netns-v1-";
const HANDLE_HEX_LENGTH: usize = 64;
const SYSTEMD_DUMP_PATH_MAX: usize = 64;
const LINUX_O_ACCMODE: u32 = 0b11;
const LINUX_MINIMUM_MAX_ARG_STRLEN: usize = 128 * 1024;
const LISTEN_FDNAMES_ENV_PREFIX_BYTES: usize = "LISTEN_FDNAMES=".len();

/// Caps retained Network namespace custody independently of service configuration.
///
/// The bound keeps systemd's single `LISTEN_FDNAMES=...` environment string,
/// including its key, separators, and terminating NUL, below Linux's 128-KiB
/// minimum `MAX_ARG_STRLEN`. It is intentionally distinct from lifetime handle
/// or allocation-generation limits.
pub const MAXIMUM_RETAINED_NETWORK_NAMESPACES: usize = 1_024;

pub(super) type RawSystemdStoreRow = (String, u32, u32, u32, u64, u32, u32, String, u32);

/// Names one namespace descriptor retained for a Network handle.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NetworkNamespaceStoreName(String);

impl NetworkNamespaceStoreName {
    /// Derives the sole accepted descriptor-store name for `network_handle`.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceStoreError::InvalidName`] for the zero handle,
    /// which is reserved as an invalid sentinel throughout Network custody.
    pub fn from_network_handle(
        network_handle: [u8; 32],
    ) -> Result<Self, NetworkNamespaceStoreError> {
        if network_handle == [0; 32] {
            return Err(NetworkNamespaceStoreError::InvalidName);
        }

        const HEX: &[u8; 16] = b"0123456789abcdef";

        let mut name = String::with_capacity(NAME_PREFIX.len() + HANDLE_HEX_LENGTH);
        name.push_str(NAME_PREFIX);
        for byte in network_handle {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(Self(name))
    }

    /// Parses an exact versioned systemd descriptor-store name.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceStoreError::InvalidName`] for a wrong prefix,
    /// length, case, delimiter, control byte, or non-hexadecimal suffix.
    pub fn parse(value: &str) -> Result<Self, NetworkNamespaceStoreError> {
        let suffix = value
            .strip_prefix(NAME_PREFIX)
            .ok_or(NetworkNamespaceStoreError::InvalidName)?;
        if suffix.len() != HANDLE_HEX_LENGTH
            || suffix.bytes().all(|byte| byte == b'0')
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(NetworkNamespaceStoreError::InvalidName);
        }

        Ok(Self(value.to_owned()))
    }

    /// Returns the exact name sent to and restored by systemd.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decodes the Network handle carried by this canonical name.
    #[must_use]
    pub fn network_handle(&self) -> [u8; 32] {
        let suffix = &self.0.as_bytes()[NAME_PREFIX.len()..];
        let mut handle = [0_u8; 32];
        for (index, pair) in suffix.chunks_exact(2).enumerate() {
            handle[index] = (hex_value(pair[0]) << 4) | hex_value(pair[1]);
        }
        handle
    }
}

const fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

/// Owns one systemd-restored, kernel-typed Network namespace descriptor.
#[derive(Debug)]
pub struct RetainedNetworkNamespace {
    name: NetworkNamespaceStoreName,
    namespace: NamespaceFd,
}

impl RetainedNetworkNamespace {
    /// Returns the exact handle-derived descriptor-store name.
    #[must_use]
    pub fn name(&self) -> &NetworkNamespaceStoreName {
        &self.name
    }

    /// Returns the Network handle decoded from the canonical store name.
    #[must_use]
    pub fn network_handle(&self) -> [u8; 32] {
        self.name.network_handle()
    }

    /// Returns the namespace identity verified by `nsfs` and `NS_GET_NSTYPE`.
    #[must_use]
    pub const fn identity(&self) -> NamespaceIdentity {
        self.namespace.identity()
    }

    /// Borrows the retained Network namespace descriptor.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.namespace.as_fd()
    }
}

/// Owns one listener and the complete retained namespace activation tail.
#[derive(Debug)]
pub struct ActivatedNetworkDescriptors {
    /// The record-subject Network listener at activation descriptor 3.
    pub listener: RecordSubjectListener,
    /// Every canonically named, kernel-typed retained namespace.
    pub namespaces: BTreeMap<NetworkNamespaceStoreName, RetainedNetworkNamespace>,
    pub(super) maximum_entries: usize,
    pub(super) host_network_identity: NamespaceIdentity,
}

impl ActivatedNetworkDescriptors {
    /// Returns the configured service-manager descriptor-store capacity.
    #[must_use]
    pub const fn maximum_entries(&self) -> usize {
        self.maximum_entries
    }

    pub(super) fn identities(&self) -> BTreeMap<NetworkNamespaceStoreName, NamespaceIdentity> {
        self.namespaces
            .iter()
            .map(|(name, retained)| (name.clone(), retained.identity()))
            .collect()
    }
}

/// Binds one protected current-boot replay row to expected namespace custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkNamespaceCustodyRequirementV1 {
    network_handle: [u8; 32],
    namespace_identity: NamespaceIdentity,
}

impl NetworkNamespaceCustodyRequirementV1 {
    /// Constructs one requirement after protected catalog and policy recovery.
    ///
    /// This type does not itself prove the source of either input. The caller
    /// must construct the complete set only after validating the protected
    /// catalog, current Linux boot, canonical pin, non-host namespace identity,
    /// and mandatory packet-policy observation.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkNamespaceStoreError::ReplayConflict`] for sentinel
    /// handle or physical identity values.
    pub fn new(
        network_handle: [u8; 32],
        namespace_identity: NamespaceIdentity,
    ) -> Result<Self, NetworkNamespaceStoreError> {
        if network_handle == [0; 32]
            || namespace_identity.device == 0
            || namespace_identity.inode == 0
        {
            return Err(NetworkNamespaceStoreError::ReplayConflict);
        }

        Ok(Self {
            network_handle,
            namespace_identity,
        })
    }
}

/// Adopts the exact listener-plus-retained-tail systemd activation contract.
///
/// The executable startup boundary must first take ownership of the systemd
/// descriptor table and validate `LISTEN_PID` and `LISTEN_FDS`. This safe layer
/// accepts only an already-typed record-subject listener and owned tail
/// descriptors. `activation_names` must name the listener `aos-netd`, followed
/// by one unique canonical store name per tail descriptor.
///
/// # Errors
///
/// Returns [`NetworkNamespaceStoreError`] for malformed activation metadata,
/// capacity overflow, duplicate names or identities, wrong descriptor types,
/// or a descriptor resolving to the host Network namespace.
pub fn adopt_systemd_activation(
    listener: RecordSubjectListener,
    activation_names: &str,
    retained_descriptors: Vec<OwnedFd>,
    configured_capacity: usize,
    host_network_identity: NamespaceIdentity,
) -> Result<ActivatedNetworkDescriptors, NetworkNamespaceStoreError> {
    listener
        .validate_current()
        .map_err(|_| invalid_activation("listener violates the record-subject contract"))?;
    if host_network_identity.device == 0 || host_network_identity.inode == 0 {
        return Err(invalid_activation(
            "host Network namespace identity is invalid",
        ));
    }
    if configured_capacity == 0
        || configured_capacity > MAXIMUM_RETAINED_NETWORK_NAMESPACES
        || retained_descriptors.len() > configured_capacity
    {
        return Err(invalid_activation(
            "configured capacity is outside the fixed hard bound",
        ));
    }
    let descriptor_count = retained_descriptors
        .len()
        .checked_add(1)
        .ok_or_else(|| invalid_activation("activation descriptor count overflow"))?;
    let names = parse_activation_names(activation_names, descriptor_count)?;
    let retained_names = names.into_iter().skip(1).flatten().collect();

    adopt_descriptor_values(
        listener,
        retained_names,
        retained_descriptors,
        configured_capacity,
        host_network_identity,
    )
}

/// Validates an exact complete replay set against restored descriptor custody.
///
/// Requirements must be strictly ordered by handle and must represent every
/// permitted current-boot catalog or pending-attempt row. No missing, extra,
/// renamed, or physically different retained descriptor is accepted.
///
/// # Errors
///
/// Returns [`NetworkNamespaceStoreError::ReplayConflict`] for an invalid or
/// non-exact requirement set.
pub fn validate_activation_replay(
    activation: &ActivatedNetworkDescriptors,
    requirements: &[NetworkNamespaceCustodyRequirementV1],
) -> Result<(), NetworkNamespaceStoreError> {
    if requirements.windows(2).any(|pair| {
        pair[0].network_handle >= pair[1].network_handle
            || pair[0].namespace_identity == pair[1].namespace_identity
    }) || requirements.len() != activation.namespaces.len()
    {
        return Err(NetworkNamespaceStoreError::ReplayConflict);
    }

    for requirement in requirements {
        let name = NetworkNamespaceStoreName::from_network_handle(requirement.network_handle)
            .map_err(|_| NetworkNamespaceStoreError::ReplayConflict)?;
        let retained = activation
            .namespaces
            .get(&name)
            .ok_or(NetworkNamespaceStoreError::ReplayConflict)?;
        if retained.identity() != requirement.namespace_identity {
            return Err(NetworkNamespaceStoreError::ReplayConflict);
        }
    }

    Ok(())
}

pub(super) fn parse_activation_names(
    names: &str,
    descriptor_count: usize,
) -> Result<Vec<Option<NetworkNamespaceStoreName>>, NetworkNamespaceStoreError> {
    const LISTENER_NAME_BYTES: usize = "aos-netd".len();
    const ENTRY_BYTES: usize = 1 + NAME_PREFIX.len() + HANDLE_HEX_LENGTH;
    const ACTIVATION_NAMES_MAX: usize =
        LISTENER_NAME_BYTES + MAXIMUM_RETAINED_NETWORK_NAMESPACES * ENTRY_BYTES;

    let environment_string_bytes = LISTEN_FDNAMES_ENV_PREFIX_BYTES
        .checked_add(names.len())
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or_else(|| invalid_activation("activation name table size overflow"))?;
    if descriptor_count == 0
        || descriptor_count > MAXIMUM_RETAINED_NETWORK_NAMESPACES + 1
        || names.len() > ACTIVATION_NAMES_MAX
        || environment_string_bytes > LINUX_MINIMUM_MAX_ARG_STRLEN
    {
        return Err(invalid_activation(
            "activation name table exceeds hard bounds",
        ));
    }
    let values = names.split(':').collect::<Vec<_>>();
    if values.len() != descriptor_count || values.first() != Some(&"aos-netd") {
        return Err(invalid_activation(
            "activation listener name or name count is invalid",
        ));
    }

    let mut parsed = Vec::with_capacity(descriptor_count);
    parsed.push(None);
    for value in values.into_iter().skip(1) {
        parsed.push(Some(NetworkNamespaceStoreName::parse(value)?));
    }
    let unique = parsed.iter().skip(1).collect::<BTreeSet<_>>();
    if unique.len() + 1 != descriptor_count {
        return Err(invalid_activation("activation names are duplicated"));
    }
    Ok(parsed)
}

fn adopt_descriptor_values(
    listener: RecordSubjectListener,
    names: Vec<NetworkNamespaceStoreName>,
    descriptors: Vec<OwnedFd>,
    maximum_entries: usize,
    host_network_identity: NamespaceIdentity,
) -> Result<ActivatedNetworkDescriptors, NetworkNamespaceStoreError> {
    if names.len() != descriptors.len()
        || names.len() > maximum_entries
        || maximum_entries == 0
        || maximum_entries > MAXIMUM_RETAINED_NETWORK_NAMESPACES
    {
        return Err(invalid_activation("descriptor and name counts differ"));
    }

    let mut namespaces = BTreeMap::new();
    let mut identities = BTreeSet::new();
    for (name, descriptor) in names.into_iter().zip(descriptors) {
        let namespace = NamespaceFd::from_owned(descriptor, NamespaceKind::Network)
            .map_err(|_| invalid_activation("retained descriptor is not a Network namespace"))?;
        let identity = namespace.identity();
        if identity == host_network_identity
            || !identities.insert((identity.device, identity.inode))
            || namespaces.contains_key(&name)
        {
            return Err(invalid_activation(
                "retained namespace identity or name is not unique and non-host",
            ));
        }
        namespaces.insert(name.clone(), RetainedNetworkNamespace { name, namespace });
    }
    if namespaces.len() > maximum_entries {
        return Err(invalid_activation(
            "retained namespace count exceeds capacity",
        ));
    }

    Ok(ActivatedNetworkDescriptors {
        listener,
        namespaces,
        maximum_entries,
        host_network_identity,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoreSnapshot {
    pub(super) maximum_entries: usize,
    pub(super) reported_entries: usize,
    pub(super) entries: BTreeMap<NetworkNamespaceStoreName, NamespaceIdentity>,
}

pub(super) fn parse_systemd_snapshot(
    maximum_entries: u32,
    reported_entries: u32,
    rows: Vec<RawSystemdStoreRow>,
) -> Result<StoreSnapshot, NetworkNamespaceStoreError> {
    let maximum_entries = usize::try_from(maximum_entries)
        .map_err(|_| invalid_snapshot("manager capacity does not fit usize"))?;
    let reported_entries = usize::try_from(reported_entries)
        .map_err(|_| invalid_snapshot("manager count does not fit usize"))?;
    if maximum_entries == 0
        || maximum_entries > MAXIMUM_RETAINED_NETWORK_NAMESPACES
        || reported_entries != rows.len()
        || reported_entries > maximum_entries
        || rows.len() > MAXIMUM_RETAINED_NETWORK_NAMESPACES
    {
        return Err(invalid_snapshot(
            "manager capacity, count, and row set disagree",
        ));
    }

    let mut entries = BTreeMap::new();
    let mut identities = BTreeSet::new();
    for (name, mode, major, minor, inode, rmajor, rminor, path, flags) in rows {
        let name = NetworkNamespaceStoreName::parse(&name)
            .map_err(|_| invalid_snapshot("manager returned a noncanonical name"))?;
        let identity = NamespaceIdentity {
            device: rustix::fs::makedev(major, minor),
            inode,
        };
        let expected_path = format!("net:[{inode}]");
        if FileType::from_raw_mode(mode) != FileType::RegularFile
            || Mode::from_raw_mode(mode).intersects(Mode::WUSR | Mode::WGRP | Mode::WOTH)
            || identity.device == 0
            || identity.inode == 0
            || rmajor != 0
            || rminor != 0
            || path.len() > SYSTEMD_DUMP_PATH_MAX
            || path != expected_path
            || flags & LINUX_O_ACCMODE != 0
            || !identities.insert((identity.device, identity.inode))
            || entries.insert(name, identity).is_some()
        {
            return Err(invalid_snapshot(
                "manager returned a malformed or duplicate namespace row",
            ));
        }
    }

    Ok(StoreSnapshot {
        maximum_entries,
        reported_entries,
        entries,
    })
}

fn invalid_snapshot(message: &'static str) -> NetworkNamespaceStoreError {
    NetworkNamespaceStoreError::Systemd(message.to_owned())
}

const fn invalid_activation(message: &'static str) -> NetworkNamespaceStoreError {
    NetworkNamespaceStoreError::InvalidActivation(message)
}
