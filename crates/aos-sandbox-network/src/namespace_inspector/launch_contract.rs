//! Static namespace-inspector deployment contract and digest.
//!
//! The contract names immutable artifacts by protected canonical path, content
//! digest, and expected metadata. It intentionally excludes boot-local device,
//! inode, mount, pidfd, process, and cgroup observations because copied guest
//! filesystem objects do not have builder-predictable inode identities. A
//! future protected loader must authenticate the decoded bytes and compare
//! retained live descriptors separately.
//!
//! ```text
//! AOSNIMC1 | version:u16 | kind:u8 | reserved:u8 | total:u32
//! fixed paths and ordered argv | static environment-name sets
//! ordered artifact roles/path/content-digest/expected metadata
//! static-property-count:u16 | static properties in descriptor-table order
//! ```

use sha2::{Digest as _, Sha256};

use super::manager_query::codec::{self, Decoder, Encoder};
use super::manager_query::{
    ManagerPropertyObservationV1, NamespaceInspectorManagerQueryError, validate_property_sequence,
};

const CONTRACT_MAGIC: &[u8; 8] = b"AOSNIMC1";
const CONTRACT_KIND: u8 = 1;
const CONTRACT_DIGEST_DOMAIN: &[u8] = b"AOS-NETWORK-NAMESPACE-INSPECTOR-DEPLOYMENT-CONTRACT-V1\0";
const MAXIMUM_PATH_BYTES: usize = 512;
const MAXIMUM_UNIT_NAME_BYTES: usize = 256;
const MAXIMUM_ARGUMENTS: usize = 16;
const MAXIMUM_ENVIRONMENT_NAMES: usize = 64;
const ARTIFACT_COUNT: usize = 4;

/// Identifies the static deployment digest without interchanging it with
/// lifecycle-worker object or launch-contract digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceInspectorDeploymentDigestV1([u8; 32]);

impl NamespaceInspectorDeploymentDigestV1 {
    pub(super) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Identifies one immutable artifact role in the static deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NamespaceInspectorArtifactRoleV1 {
    /// The namespace-inspector executable started by the service unit.
    InspectorExecutable,
    /// The one-shot libsystemd query helper executable.
    ManagerQueryHelperExecutable,
    /// The immutable inspector service template fragment.
    InspectorServiceFragment,
    /// The immutable inspector socket-unit fragment.
    InspectorSocketFragment,
}

impl NamespaceInspectorArtifactRoleV1 {
    const fn code(self) -> u8 {
        match self {
            Self::InspectorExecutable => 1,
            Self::ManagerQueryHelperExecutable => 2,
            Self::InspectorServiceFragment => 3,
            Self::InspectorSocketFragment => 4,
        }
    }

    fn from_code(code: u8) -> Result<Self, NamespaceInspectorManagerQueryError> {
        match code {
            1 => Ok(Self::InspectorExecutable),
            2 => Ok(Self::ManagerQueryHelperExecutable),
            3 => Ok(Self::InspectorServiceFragment),
            4 => Ok(Self::InspectorSocketFragment),
            _ => Err(NamespaceInspectorManagerQueryError::InvalidContract),
        }
    }
}

/// Names one immutable source artifact without predicting its runtime inode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceInspectorArtifactExpectationV1 {
    role: NamespaceInspectorArtifactRoleV1,
    canonical_path: String,
    content_digest: [u8; 32],
    expected_mode: u32,
    expected_uid: u32,
    expected_gid: u32,
}

impl NamespaceInspectorArtifactExpectationV1 {
    fn validate(&self) -> Result<(), NamespaceInspectorManagerQueryError> {
        if !absolute_path_is_valid(&self.canonical_path)
            || self.content_digest == [0; 32]
            || self.expected_mode & !0o7777 != 0
        {
            return Err(NamespaceInspectorManagerQueryError::InvalidContract);
        }
        Ok(())
    }
}

/// Holds decoded static deployment bytes without claiming protected origin.
///
/// Ordered vectors retain semantics for argv, fragment/drop-in search order,
/// and path policy. Environment-name collections are canonical unordered sets.
/// Runtime manager environment values and all boot-local identities are absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceInspectorDeploymentContractV1 {
    inspector_arguments: Vec<String>,
    helper_arguments: Vec<String>,
    service_unit_template: String,
    socket_unit: String,
    control_socket_path: String,
    manager_socket_path: String,
    service_drop_in_paths: Vec<String>,
    socket_drop_in_paths: Vec<String>,
    read_only_paths: Vec<String>,
    read_write_paths: Vec<String>,
    inaccessible_paths: Vec<String>,
    allowed_environment_names: Vec<String>,
    forbidden_environment_names: Vec<String>,
    artifacts: Vec<NamespaceInspectorArtifactExpectationV1>,
    static_properties: Vec<ManagerPropertyObservationV1>,
}

impl NamespaceInspectorDeploymentContractV1 {
    /// Decodes bounded canonical bytes without authenticating their source.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceInspectorManagerQueryError`] when the record is
    /// oversized, malformed, noncanonical, truncated, or violates the closed
    /// artifact and static-property tables.
    pub(crate) fn decode_untrusted(
        bytes: &[u8],
    ) -> Result<Self, NamespaceInspectorManagerQueryError> {
        codec::decode_contract(bytes)
    }

    /// Encodes the canonical static deployment record.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceInspectorManagerQueryError`] when this value violates
    /// a structural limit or a closed table.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, NamespaceInspectorManagerQueryError> {
        self.validate()?;
        codec::encode_contract(self)
    }

    /// Computes the domain-separated digest of the canonical contract bytes.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceInspectorManagerQueryError`] when the contract cannot
    /// be canonically encoded.
    pub(crate) fn digest(
        &self,
    ) -> Result<NamespaceInspectorDeploymentDigestV1, NamespaceInspectorManagerQueryError> {
        let bytes = self.encode()?;
        let mut digest = Sha256::new();
        digest.update(CONTRACT_DIGEST_DOMAIN);
        digest.update(bytes);
        Ok(NamespaceInspectorDeploymentDigestV1::from_bytes(
            digest.finalize().into(),
        ))
    }

    pub(super) fn static_properties(&self) -> &[ManagerPropertyObservationV1] {
        &self.static_properties
    }

    pub(super) fn validate(&self) -> Result<(), NamespaceInspectorManagerQueryError> {
        validate_ordered_text(
            &self.inspector_arguments,
            MAXIMUM_ARGUMENTS,
            MAXIMUM_PATH_BYTES,
        )?;
        validate_ordered_text(
            &self.helper_arguments,
            MAXIMUM_ARGUMENTS,
            MAXIMUM_PATH_BYTES,
        )?;
        if self.inspector_arguments.is_empty()
            || self.helper_arguments.is_empty()
            || !absolute_path_is_valid(&self.inspector_arguments[0])
            || !absolute_path_is_valid(&self.helper_arguments[0])
            || !service_template_is_valid(&self.service_unit_template)
            || !socket_unit_is_valid(&self.socket_unit)
            || !absolute_path_is_valid(&self.control_socket_path)
            || !absolute_path_is_valid(&self.manager_socket_path)
        {
            return Err(NamespaceInspectorManagerQueryError::InvalidContract);
        }

        validate_ordered_paths(&self.service_drop_in_paths)?;
        validate_ordered_paths(&self.socket_drop_in_paths)?;
        validate_ordered_paths(&self.read_only_paths)?;
        validate_ordered_paths(&self.read_write_paths)?;
        validate_ordered_paths(&self.inaccessible_paths)?;
        codec::validate_sorted_text_set(
            &self.allowed_environment_names,
            MAXIMUM_ENVIRONMENT_NAMES,
        )?;
        codec::validate_sorted_text_set(
            &self.forbidden_environment_names,
            MAXIMUM_ENVIRONMENT_NAMES,
        )?;
        for name in self
            .allowed_environment_names
            .iter()
            .chain(&self.forbidden_environment_names)
        {
            codec::validate_environment_name(name)?;
        }
        if self
            .allowed_environment_names
            .iter()
            .any(|name| self.forbidden_environment_names.binary_search(name).is_ok())
        {
            return Err(NamespaceInspectorManagerQueryError::InvalidContract);
        }

        if self.artifacts.len() != ARTIFACT_COUNT {
            return Err(NamespaceInspectorManagerQueryError::InvalidContract);
        }
        for (index, artifact) in self.artifacts.iter().enumerate() {
            artifact.validate()?;
            if usize::from(artifact.role.code()) != index + 1 {
                return Err(NamespaceInspectorManagerQueryError::InvalidContract);
            }
        }
        if self.artifacts[0].canonical_path != self.inspector_arguments[0]
            || self.artifacts[1].canonical_path != self.helper_arguments[0]
        {
            return Err(NamespaceInspectorManagerQueryError::InvalidContract);
        }

        validate_property_sequence(&self.static_properties, true)
    }
}

fn absolute_path_is_valid(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    !path.is_empty()
        && path.len() <= MAXIMUM_PATH_BYTES
        && path.starts_with('/')
        && !path.ends_with('/')
        && !path.as_bytes().contains(&0)
        && path[1..]
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn unit_stem_is_valid(unit: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= MAXIMUM_UNIT_NAME_BYTES
        && unit.is_ascii()
        && !unit.as_bytes().contains(&0)
        && unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.' | b'-'))
}

fn service_template_is_valid(unit: &str) -> bool {
    unit.len() <= MAXIMUM_UNIT_NAME_BYTES
        && unit
            .strip_suffix("@.service")
            .is_some_and(unit_stem_is_valid)
}

fn socket_unit_is_valid(unit: &str) -> bool {
    unit.len() <= MAXIMUM_UNIT_NAME_BYTES
        && unit.strip_suffix(".socket").is_some_and(unit_stem_is_valid)
}

fn validate_ordered_paths(paths: &[String]) -> Result<(), NamespaceInspectorManagerQueryError> {
    if paths.len() > codec::MAXIMUM_COLLECTION_ELEMENTS
        || paths.iter().any(|path| !absolute_path_is_valid(path))
    {
        return Err(NamespaceInspectorManagerQueryError::InvalidContract);
    }
    Ok(())
}

fn validate_ordered_text(
    values: &[String],
    maximum_elements: usize,
    maximum_bytes: usize,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    if values.len() > maximum_elements {
        return Err(NamespaceInspectorManagerQueryError::FieldTooLarge);
    }
    for value in values {
        if value.is_empty() || value.len() > maximum_bytes {
            return Err(NamespaceInspectorManagerQueryError::InvalidText);
        }
        codec::validate_text(value)?;
    }
    Ok(())
}

pub(super) fn encode_contract_body(
    contract: &NamespaceInspectorDeploymentContractV1,
    encoder: &mut Encoder,
) -> Result<(), NamespaceInspectorManagerQueryError> {
    encoder.strings(&contract.inspector_arguments)?;
    encoder.strings(&contract.helper_arguments)?;
    encoder.text(&contract.service_unit_template)?;
    encoder.text(&contract.socket_unit)?;
    encoder.text(&contract.control_socket_path)?;
    encoder.text(&contract.manager_socket_path)?;
    encoder.strings(&contract.service_drop_in_paths)?;
    encoder.strings(&contract.socket_drop_in_paths)?;
    encoder.strings(&contract.read_only_paths)?;
    encoder.strings(&contract.read_write_paths)?;
    encoder.strings(&contract.inaccessible_paths)?;
    encoder.strings(&contract.allowed_environment_names)?;
    encoder.strings(&contract.forbidden_environment_names)?;

    encoder.count(contract.artifacts.len())?;
    for artifact in &contract.artifacts {
        encoder.u8(artifact.role.code());
        encoder.text(&artifact.canonical_path)?;
        encoder.bytes(&artifact.content_digest);
        encoder.u32(artifact.expected_mode);
        encoder.u32(artifact.expected_uid);
        encoder.u32(artifact.expected_gid);
    }
    encoder.properties(&contract.static_properties)?;
    Ok(())
}

pub(super) fn decode_contract_body(
    decoder: &mut Decoder<'_>,
) -> Result<NamespaceInspectorDeploymentContractV1, NamespaceInspectorManagerQueryError> {
    let inspector_arguments = decoder.strings(MAXIMUM_ARGUMENTS, MAXIMUM_PATH_BYTES)?;
    let helper_arguments = decoder.strings(MAXIMUM_ARGUMENTS, MAXIMUM_PATH_BYTES)?;
    let service_unit_template = decoder.text(MAXIMUM_UNIT_NAME_BYTES)?;
    let socket_unit = decoder.text(MAXIMUM_UNIT_NAME_BYTES)?;
    let control_socket_path = decoder.text(MAXIMUM_PATH_BYTES)?;
    let manager_socket_path = decoder.text(MAXIMUM_PATH_BYTES)?;
    let service_drop_in_paths =
        decoder.strings(codec::MAXIMUM_COLLECTION_ELEMENTS, MAXIMUM_PATH_BYTES)?;
    let socket_drop_in_paths =
        decoder.strings(codec::MAXIMUM_COLLECTION_ELEMENTS, MAXIMUM_PATH_BYTES)?;
    let read_only_paths =
        decoder.strings(codec::MAXIMUM_COLLECTION_ELEMENTS, MAXIMUM_PATH_BYTES)?;
    let read_write_paths =
        decoder.strings(codec::MAXIMUM_COLLECTION_ELEMENTS, MAXIMUM_PATH_BYTES)?;
    let inaccessible_paths =
        decoder.strings(codec::MAXIMUM_COLLECTION_ELEMENTS, MAXIMUM_PATH_BYTES)?;
    let allowed_environment_names =
        decoder.strings(MAXIMUM_ENVIRONMENT_NAMES, codec::MAXIMUM_TEXT_BYTES)?;
    let forbidden_environment_names =
        decoder.strings(MAXIMUM_ENVIRONMENT_NAMES, codec::MAXIMUM_TEXT_BYTES)?;

    let artifact_count = decoder.count(ARTIFACT_COUNT)?;
    if artifact_count != ARTIFACT_COUNT {
        return Err(NamespaceInspectorManagerQueryError::InvalidContract);
    }
    let mut artifacts = Vec::with_capacity(artifact_count);
    for _ in 0..artifact_count {
        artifacts.push(NamespaceInspectorArtifactExpectationV1 {
            role: NamespaceInspectorArtifactRoleV1::from_code(decoder.u8()?)?,
            canonical_path: decoder.text(MAXIMUM_PATH_BYTES)?,
            content_digest: decoder.array()?,
            expected_mode: decoder.u32()?,
            expected_uid: decoder.u32()?,
            expected_gid: decoder.u32()?,
        });
    }
    let static_properties = decoder.properties(true)?;

    let contract = NamespaceInspectorDeploymentContractV1 {
        inspector_arguments,
        helper_arguments,
        service_unit_template,
        socket_unit,
        control_socket_path,
        manager_socket_path,
        service_drop_in_paths,
        socket_drop_in_paths,
        read_only_paths,
        read_write_paths,
        inaccessible_paths,
        allowed_environment_names,
        forbidden_environment_names,
        artifacts,
        static_properties,
    };
    contract.validate()?;
    Ok(contract)
}

pub(super) const fn contract_magic() -> &'static [u8; 8] {
    CONTRACT_MAGIC
}

pub(super) const fn contract_kind() -> u8 {
    CONTRACT_KIND
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::namespace_inspector::manager_query::codec::test_properties;

    pub(in crate::namespace_inspector) fn contract() -> NamespaceInspectorDeploymentContractV1 {
        NamespaceInspectorDeploymentContractV1 {
            inspector_arguments: vec!["/bin/aos-sandbox-network-namespace-inspector".into()],
            helper_arguments: vec!["/bin/aos-systemd-manager-query".into()],
            service_unit_template: "aos-sandbox-network-namespace-inspector@.service".into(),
            socket_unit: "aos-sandbox-network-namespace-inspector.socket".into(),
            control_socket_path: "/run/aos/sandbox-network-namespace-inspector/control.sock".into(),
            manager_socket_path: "/run/systemd/private".into(),
            service_drop_in_paths: vec!["/etc/systemd/system/inspector-service.conf".into()],
            socket_drop_in_paths: vec!["/etc/systemd/system/inspector-socket.conf".into()],
            read_only_paths: vec![
                "/var/lib/aos/sandbox-network/namespace-inspector/expected-final".into(),
            ],
            read_write_paths: vec![
                "/var/lib/aos/sandbox-network/namespace-inspector/spent-staging".into(),
                "/var/lib/aos/sandbox-network/namespace-inspector/spent-final".into(),
            ],
            inaccessible_paths: vec![
                "/var/lib/aos/sandbox-network/broker-state".into(),
                "/var/lib/aos/sandbox-network/namespace-inspector/expected-staging".into(),
            ],
            allowed_environment_names: vec!["LANG".into(), "PATH".into()],
            forbidden_environment_names: vec![
                "LD_AUDIT".into(),
                "LD_LIBRARY_PATH".into(),
                "LD_PRELOAD".into(),
            ],
            artifacts: vec![
                NamespaceInspectorArtifactExpectationV1 {
                    role: NamespaceInspectorArtifactRoleV1::InspectorExecutable,
                    canonical_path: "/bin/aos-sandbox-network-namespace-inspector".into(),
                    content_digest: [1; 32],
                    expected_mode: 0o555,
                    expected_uid: 0,
                    expected_gid: 0,
                },
                NamespaceInspectorArtifactExpectationV1 {
                    role: NamespaceInspectorArtifactRoleV1::ManagerQueryHelperExecutable,
                    canonical_path: "/bin/aos-systemd-manager-query".into(),
                    content_digest: [2; 32],
                    expected_mode: 0o555,
                    expected_uid: 0,
                    expected_gid: 0,
                },
                NamespaceInspectorArtifactExpectationV1 {
                    role: NamespaceInspectorArtifactRoleV1::InspectorServiceFragment,
                    canonical_path: "/etc/systemd/system/inspector-service.conf".into(),
                    content_digest: [3; 32],
                    expected_mode: 0o444,
                    expected_uid: 0,
                    expected_gid: 0,
                },
                NamespaceInspectorArtifactExpectationV1 {
                    role: NamespaceInspectorArtifactRoleV1::InspectorSocketFragment,
                    canonical_path: "/etc/systemd/system/inspector-socket.conf".into(),
                    content_digest: [4; 32],
                    expected_mode: 0o444,
                    expected_uid: 0,
                    expected_gid: 0,
                },
            ],
            static_properties: test_properties(true),
        }
    }

    #[test]
    fn contract_round_trip_and_digest_are_canonical() {
        let expected = contract();
        let bytes = expected.encode().unwrap();
        let decoded = NamespaceInspectorDeploymentContractV1::decode_untrusted(&bytes).unwrap();
        assert_eq!(decoded, expected);
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert_eq!(
            *decoded.digest().unwrap().as_bytes(),
            [
                161, 105, 235, 195, 227, 27, 5, 168, 184, 227, 41, 253, 77, 175, 112, 183, 82, 52,
                63, 252, 207, 20, 154, 201, 248, 152, 115, 110, 210, 234, 17, 192,
            ]
        );
    }

    #[test]
    fn path_and_argv_order_are_digest_significant() {
        let expected = contract();
        let expected_digest = expected.digest().unwrap();

        let mut reordered_paths = expected.clone();
        reordered_paths.read_write_paths.swap(0, 1);
        assert_ne!(reordered_paths.digest().unwrap(), expected_digest);

        let mut extended_argv = expected.clone();
        extended_argv.inspector_arguments.push("unexpected".into());
        assert_ne!(extended_argv.digest().unwrap(), expected_digest);
    }

    #[test]
    fn environment_name_sets_require_canonical_order() {
        let mut expected = contract();
        expected.forbidden_environment_names.swap(0, 1);
        assert_eq!(
            expected.encode(),
            Err(NamespaceInspectorManagerQueryError::NoncanonicalSet)
        );
    }

    #[test]
    fn artifact_roles_are_closed_and_ordered() {
        let mut expected = contract();
        expected.artifacts.swap(0, 1);
        assert_eq!(
            expected.encode(),
            Err(NamespaceInspectorManagerQueryError::InvalidContract)
        );
    }

    #[test]
    fn paths_are_absolute_and_lexically_canonical() {
        for path in [
            "relative/path",
            "/trailing/",
            "/repeated//separator",
            "/current/./entry",
            "/parent/../entry",
        ] {
            let mut expected = contract();
            expected.control_socket_path = path.into();
            assert_eq!(
                expected.encode(),
                Err(NamespaceInspectorManagerQueryError::InvalidContract)
            );
        }
    }

    #[test]
    fn unit_names_use_fixed_template_and_socket_grammars() {
        for service in [
            "inspector.service",
            "inspector@instance.service",
            "inspector @.service",
            "path/inspector@.service",
        ] {
            let mut expected = contract();
            expected.service_unit_template = service.into();
            assert_eq!(
                expected.encode(),
                Err(NamespaceInspectorManagerQueryError::InvalidContract)
            );
        }
        for socket in ["inspector@.socket", "inspector.socket/", "inspector socket"] {
            let mut expected = contract();
            expected.socket_unit = socket.into();
            assert_eq!(
                expected.encode(),
                Err(NamespaceInspectorManagerQueryError::InvalidContract)
            );
        }

        let mut expected = contract();
        expected.service_unit_template = format!(
            "{}@.service",
            "a".repeat(MAXIMUM_UNIT_NAME_BYTES - "@.service".len() + 1)
        );
        assert_eq!(
            expected.encode(),
            Err(NamespaceInspectorManagerQueryError::InvalidContract)
        );

        let mut expected = contract();
        expected.socket_unit = format!(
            "{}.socket",
            "a".repeat(MAXIMUM_UNIT_NAME_BYTES - ".socket".len() + 1)
        );
        assert_eq!(
            expected.encode(),
            Err(NamespaceInspectorManagerQueryError::InvalidContract)
        );
    }

    #[test]
    fn environment_policy_names_use_variable_grammar() {
        for name in ["1BAD", "BAD-NAME", "BAD=VALUE"] {
            let mut expected = contract();
            expected.allowed_environment_names = vec![name.into()];
            assert_eq!(
                expected.encode(),
                Err(NamespaceInspectorManagerQueryError::InvalidText)
            );
        }
    }

    #[test]
    fn static_digest_has_no_runtime_identity_fields() {
        let fields = format!("{:#?}", contract());
        for forbidden in [
            "device_id",
            "inode",
            "pidfd",
            "control_group_id",
            "invocation_id",
            "accepted_socket_cookie",
        ] {
            assert!(!fields.contains(forbidden));
        }
    }
}
