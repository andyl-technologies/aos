//! Closed transient-unit contract for per-assignment lease guardians.
//!
//! The specification transfers exactly ten named read-only authority
//! descriptors and starts one descriptor-pinned executable. It exposes no
//! general property map or arbitrary service-manager operation.

use std::collections::BTreeMap;
use std::os::fd::BorrowedFd;
use std::sync::Arc;
use std::time::Duration;

use zbus::zvariant::Fd;

use super::{
    SandboxDescriptorPath, SandboxUnitName, bool_property, complex_property, duration_micros,
    exec_property, invalid, string_array_property, string_property, u32_property, u64_property,
};
use crate::client::{JobOutcome, SystemdClient};
use crate::error::Result;
use crate::manager_proxy::AuxiliaryUnit;

const GUARDIAN_SLICE: &str = "aos-assignment-guardians.slice";
const GUARDIAN_STATE_PREFIX: &str = "aos/lease-guards";
const GUARDIAN_ENVIRONMENT_PREFIX: &str = "AOS_GUARDIAN_INCARNATION=";
const GUARDIAN_ALLOWED_ADDRESS_FAMILIES: &[&str] = &["AF_UNIX"];
const GUARDIAN_ALLOWED_SYSCALLS: &[&str] = &["@system-service"];
const GUARDIAN_DENIED_SOCKET_OPERATIONS: &[&str] =
    &["accept", "accept4", "bind", "connect", "listen"];

/// Names every exact authority descriptor consumed by a guardian.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GuardianCredentialRole {
    /// Controller-plan trust policy.
    BrokerPlanPolicy,
    /// Controller-plan Ed25519 public key.
    BrokerPlanPublicKey,
    /// Controller-plan revocation scope.
    BrokerPlanRevocationScope,
    /// Ownership-lease trust policy.
    OwnershipLeasePolicy,
    /// Ownership-authority Ed25519 public key.
    OwnershipLeasePublicKey,
    /// Sole node identity accepted by the guardian.
    NodeId,
    /// Canonical signed Guardian plan.
    BrokerPlan,
    /// Detached controller signature over the plan.
    BrokerPlanSignature,
    /// Canonical signed ownership lease.
    OwnershipLease,
    /// Detached authority signature over the lease.
    OwnershipLeaseSignature,
}

impl GuardianCredentialRole {
    const ALL: [Self; 10] = [
        Self::BrokerPlanPolicy,
        Self::BrokerPlanPublicKey,
        Self::BrokerPlanRevocationScope,
        Self::OwnershipLeasePolicy,
        Self::OwnershipLeasePublicKey,
        Self::NodeId,
        Self::BrokerPlan,
        Self::BrokerPlanSignature,
        Self::OwnershipLease,
        Self::OwnershipLeaseSignature,
    ];

    /// Returns the fixed systemd descriptor name consumed by the binary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrokerPlanPolicy => "broker-plan-policy.cbor",
            Self::BrokerPlanPublicKey => "broker-plan-public-key",
            Self::BrokerPlanRevocationScope => "broker-revocation-scope",
            Self::OwnershipLeasePolicy => "ownership-lease-policy.cbor",
            Self::OwnershipLeasePublicKey => "ownership-lease-public-key",
            Self::NodeId => "node-id",
            Self::BrokerPlan => "broker-plan.cbor",
            Self::BrokerPlanSignature => "broker-plan-signature.cbor",
            Self::OwnershipLease => "ownership-lease.cbor",
            Self::OwnershipLeaseSignature => "ownership-lease-signature.cbor",
        }
    }
}

/// Owns one exact complete set of descriptor-pinned guardian authority inputs.
#[derive(Clone, Debug)]
pub struct GuardianCredentialDescriptors {
    descriptors: BTreeMap<GuardianCredentialRole, Arc<std::os::fd::OwnedFd>>,
}

impl GuardianCredentialDescriptors {
    /// Duplicates and owns one descriptor for every fixed guardian role.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing, duplicate, or extra role, or when a
    /// descriptor cannot be duplicated into close-on-exec storage.
    pub fn from_descriptors(
        entries: Vec<(GuardianCredentialRole, BorrowedFd<'_>)>,
    ) -> Result<Self> {
        if entries.len() != GuardianCredentialRole::ALL.len() {
            return Err(invalid(
                "guardian requires exactly ten authority descriptors",
            ));
        }
        let mut descriptors = BTreeMap::new();
        for (role, descriptor) in entries {
            let owned = descriptor.try_clone_to_owned().map_err(|error| {
                invalid(format!("cannot duplicate guardian descriptor: {error}"))
            })?;
            if descriptors.insert(role, Arc::new(owned)).is_some() {
                return Err(invalid("guardian authority descriptor role is duplicated"));
            }
        }
        if !GuardianCredentialRole::ALL
            .iter()
            .all(|role| descriptors.contains_key(role))
        {
            return Err(invalid("guardian authority descriptor role is missing"));
        }
        Ok(Self { descriptors })
    }

    fn transferred(&self) -> Result<Vec<(Fd<'static>, String)>> {
        GuardianCredentialRole::ALL
            .iter()
            .map(|role| {
                let descriptor = self
                    .descriptors
                    .get(role)
                    .ok_or_else(|| invalid("guardian descriptor set became incomplete"))?
                    .try_clone()
                    .map_err(|error| {
                        invalid(format!("cannot transfer guardian descriptor: {error}"))
                    })?;
                Ok((Fd::from(descriptor), role.as_str().to_owned()))
            })
            .collect()
    }
}

/// Defines the sole systemd transient service shape accepted for a guardian.
#[derive(Clone, Debug)]
pub struct GuardianUnitSpec {
    name: SandboxUnitName,
    executable: SandboxDescriptorPath,
    credentials: GuardianCredentialDescriptors,
    incarnation_hex: String,
    timeout_start: Duration,
}

impl GuardianUnitSpec {
    /// Constructs one capability-less, network-listener-free guardian unit.
    ///
    /// The executable is descriptor-pinned, automatic restart is disabled, and
    /// each assignment receives a separate dynamic service identity and 0700
    /// durable state directory. The only allowed address family is `AF_UNIX`
    /// for the one readiness datagram; bind/listen/connect/accept are denied.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero incarnation-derived name or invalid start
    /// timeout.
    pub fn new(
        name: SandboxUnitName,
        executable: SandboxDescriptorPath,
        credentials: GuardianCredentialDescriptors,
        timeout_start: Duration,
    ) -> Result<Self> {
        let (_, incarnation) = SandboxUnitName::from_service_name(name.as_str())
            .ok_or_else(|| invalid("guardian unit name is not canonical"))?;
        duration_micros(timeout_start, "guardian start timeout")?;
        Ok(Self {
            name,
            executable,
            credentials,
            incarnation_hex: super::encode_hex(incarnation),
            timeout_start,
        })
    }

    /// Returns the incarnation-derived guardian service name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.guardian()
    }

    fn properties(&self) -> Result<Vec<crate::manager_proxy::TransientProperty>> {
        let environment = format!("{GUARDIAN_ENVIRONMENT_PREFIX}{}", self.incarnation_hex);
        let state_directory = format!("{GUARDIAN_STATE_PREFIX}/{}", self.incarnation_hex);
        Ok(vec![
            string_property("Description", format!("AOS lease guardian {}", self.name)),
            string_property("Type", "notify"),
            string_property("NotifyAccess", "main"),
            string_property("Slice", GUARDIAN_SLICE),
            string_property("Restart", "no"),
            string_property("CollectMode", "inactive-or-failed"),
            bool_property("DynamicUser", true),
            string_array_property("StateDirectory", vec![state_directory])?,
            u32_property("StateDirectoryMode", 0o700),
            u32_property("UMask", 0o077),
            u64_property("CapabilityBoundingSet", 0),
            u64_property("AmbientCapabilities", 0),
            bool_property("NoNewPrivileges", true),
            complex_property(
                "RestrictAddressFamilies",
                (
                    true,
                    GUARDIAN_ALLOWED_ADDRESS_FAMILIES
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>(),
                ),
            )?,
            complex_property(
                "SystemCallFilter",
                (
                    true,
                    GUARDIAN_ALLOWED_SYSCALLS
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>(),
                ),
            )?,
            complex_property(
                "SystemCallFilter",
                (
                    false,
                    GUARDIAN_DENIED_SOCKET_OPERATIONS
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect::<Vec<_>>(),
                ),
            )?,
            string_array_property("SystemCallArchitectures", vec!["native".to_owned()])?,
            string_property("ProtectSystem", "strict"),
            string_property("ProtectHome", "yes"),
            bool_property("PrivateTmp", true),
            bool_property("PrivateDevices", true),
            bool_property("ProtectKernelTunables", true),
            bool_property("ProtectKernelModules", true),
            bool_property("ProtectControlGroups", true),
            bool_property("ProtectClock", true),
            u64_property("RestrictNamespaces", 0),
            bool_property("LockPersonality", true),
            bool_property("MemoryDenyWriteExecute", true),
            bool_property("RestrictRealtime", true),
            bool_property("RestrictSUIDSGID", true),
            string_array_property(
                "InaccessiblePaths",
                vec!["/run/dbus/system_bus_socket".to_owned()],
            )?,
            complex_property("ExtraFileDescriptors", self.credentials.transferred()?)?,
            string_array_property("Environment", vec![environment])?,
            bool_property("SetLoginEnvironment", false),
            u64_property(
                "TimeoutStartUSec",
                duration_micros(self.timeout_start, "guardian start timeout")?,
            ),
            exec_property(&self.executable.path, vec![self.executable.path.clone()])?,
        ])
    }
}

impl SystemdClient {
    /// Creates and starts one closed guardian unit, then awaits its start job.
    ///
    /// This is the only guardian service-manager operation exposed by the
    /// typed transport. The borrowed specification retains the executable and
    /// authority descriptor pins through activation; `Restart=no` prevents
    /// reuse after those pins are released.
    ///
    /// # Errors
    ///
    /// Returns an error when property compilation, D-Bus submission, or job
    /// completion fails.
    pub async fn start_guardian_unit(&self, spec: &GuardianUnitSpec) -> Result<JobOutcome> {
        let properties = spec.properties()?;
        let auxiliary_units: Vec<AuxiliaryUnit> = Vec::new();
        let path = self
            .manager
            .start_transient_unit(spec.name(), "fail", &properties, &auxiliary_units)
            .await?;
        self.await_job(path).await
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::AsFd as _;

    use super::*;

    fn spec() -> GuardianUnitSpec {
        let executable = File::open("/proc/self/exe")
            .unwrap_or_else(|error| panic!("test executable failed: {error}"));
        let executable = SandboxDescriptorPath::for_current_process(executable.as_fd())
            .unwrap_or_else(|error| panic!("test executable pin failed: {error}"));
        let files = GuardianCredentialRole::ALL
            .iter()
            .map(|role| {
                let file = File::open("/proc/self/exe")
                    .unwrap_or_else(|error| panic!("test descriptor failed: {error}"));
                (*role, file)
            })
            .collect::<Vec<_>>();
        let descriptors = GuardianCredentialDescriptors::from_descriptors(
            files
                .iter()
                .map(|(role, file)| (*role, file.as_fd()))
                .collect(),
        )
        .unwrap_or_else(|error| panic!("test credential set failed: {error}"));
        GuardianUnitSpec::new(
            SandboxUnitName::from_incarnation([0xab; 16]),
            executable,
            descriptors,
            Duration::from_secs(10),
        )
        .unwrap_or_else(|error| panic!("test guardian spec failed: {error}"))
    }

    #[test]
    fn property_contract_is_capabilityless_and_closed() {
        let properties = spec()
            .properties()
            .unwrap_or_else(|error| panic!("property compilation failed: {error}"));
        let names = properties
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "Description",
                "Type",
                "NotifyAccess",
                "Slice",
                "Restart",
                "CollectMode",
                "DynamicUser",
                "StateDirectory",
                "StateDirectoryMode",
                "UMask",
                "CapabilityBoundingSet",
                "AmbientCapabilities",
                "NoNewPrivileges",
                "RestrictAddressFamilies",
                "SystemCallFilter",
                "SystemCallFilter",
                "SystemCallArchitectures",
                "ProtectSystem",
                "ProtectHome",
                "PrivateTmp",
                "PrivateDevices",
                "ProtectKernelTunables",
                "ProtectKernelModules",
                "ProtectControlGroups",
                "ProtectClock",
                "RestrictNamespaces",
                "LockPersonality",
                "MemoryDenyWriteExecute",
                "RestrictRealtime",
                "RestrictSUIDSGID",
                "InaccessiblePaths",
                "ExtraFileDescriptors",
                "Environment",
                "SetLoginEnvironment",
                "TimeoutStartUSec",
                "ExecStart",
            ]
        );

        let signatures = properties
            .iter()
            .map(|(name, value)| (name.as_str(), value.value_signature().to_string()))
            .collect::<Vec<_>>();
        assert_eq!(
            signatures,
            vec![
                ("Description", "s".to_owned()),
                ("Type", "s".to_owned()),
                ("NotifyAccess", "s".to_owned()),
                ("Slice", "s".to_owned()),
                ("Restart", "s".to_owned()),
                ("CollectMode", "s".to_owned()),
                ("DynamicUser", "b".to_owned()),
                ("StateDirectory", "as".to_owned()),
                ("StateDirectoryMode", "u".to_owned()),
                ("UMask", "u".to_owned()),
                ("CapabilityBoundingSet", "t".to_owned()),
                ("AmbientCapabilities", "t".to_owned()),
                ("NoNewPrivileges", "b".to_owned()),
                ("RestrictAddressFamilies", "(bas)".to_owned()),
                ("SystemCallFilter", "(bas)".to_owned()),
                ("SystemCallFilter", "(bas)".to_owned()),
                ("SystemCallArchitectures", "as".to_owned()),
                ("ProtectSystem", "s".to_owned()),
                ("ProtectHome", "s".to_owned()),
                ("PrivateTmp", "b".to_owned()),
                ("PrivateDevices", "b".to_owned()),
                ("ProtectKernelTunables", "b".to_owned()),
                ("ProtectKernelModules", "b".to_owned()),
                ("ProtectControlGroups", "b".to_owned()),
                ("ProtectClock", "b".to_owned()),
                ("RestrictNamespaces", "t".to_owned()),
                ("LockPersonality", "b".to_owned()),
                ("MemoryDenyWriteExecute", "b".to_owned()),
                ("RestrictRealtime", "b".to_owned()),
                ("RestrictSUIDSGID", "b".to_owned()),
                ("InaccessiblePaths", "as".to_owned()),
                ("ExtraFileDescriptors", "a(hs)".to_owned()),
                ("Environment", "as".to_owned()),
                ("SetLoginEnvironment", "b".to_owned()),
                ("TimeoutStartUSec", "t".to_owned()),
                ("ExecStart", "a(sasb)".to_owned()),
            ]
        );

        for name in [
            "CapabilityBoundingSet",
            "AmbientCapabilities",
            "RestrictNamespaces",
        ] {
            let (_, value) = properties
                .iter()
                .find(|(property, _)| property == name)
                .unwrap_or_else(|| panic!("missing {name}"));
            assert_eq!(u64::try_from(value).unwrap_or(u64::MAX), 0);
        }
    }

    #[test]
    fn authority_descriptors_have_one_exact_canonical_order() {
        let properties = spec()
            .properties()
            .unwrap_or_else(|error| panic!("property compilation failed: {error}"));
        let (_, value) = properties
            .into_iter()
            .find(|(name, _)| name == "ExtraFileDescriptors")
            .unwrap_or_else(|| panic!("guardian descriptor property is absent"));
        let descriptors = Vec::<(Fd<'static>, String)>::try_from(value)
            .unwrap_or_else(|error| panic!("descriptor property decode failed: {error}"));
        assert_eq!(
            descriptors
                .iter()
                .map(|(_, name)| name.as_str())
                .collect::<Vec<_>>(),
            GuardianCredentialRole::ALL
                .iter()
                .map(|role| role.as_str())
                .collect::<Vec<_>>()
        );
    }
}
