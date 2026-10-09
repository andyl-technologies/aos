//! Dormant untrusted Nix client and narrowing-proxy policy.
//!
//! These declarations are source-only configuration inputs. They do not open
//! a daemon socket, render a system unit, or install a proxy. The fixed values
//! make the security claim mechanically inspectable before any implementation
//! is qualified.

use aos_sandbox_core::{ObjectDigest, PrincipalId, ResourceId};
use sha2::{Digest as _, Sha256};

use super::EnvironmentExecutionErrorV1;

/// Exact daemon settings required for the untrusted-client profile.
pub const UNTRUSTED_NIX_DAEMON_SETTINGS_V1: [(&str, &str); 8] = [
    ("accept-flake-config", "false"),
    ("allow-import-from-derivation", "false"),
    ("builders", ""),
    ("require-sigs", "true"),
    ("sandbox", "true"),
    ("substituters", ""),
    ("trusted-public-keys", ""),
    ("trusted-users", ""),
];

/// Names authority that remains unavailable to every untrusted Nix client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DeniedNixAuthorityV1 {
    /// Becoming a Nix trusted user or impersonating one is forbidden.
    TrustedUser = 1,
    /// Direct mutation of store paths or the state database is forbidden.
    DirectStoreMutation = 2,
    /// Adding, deleting, or replacing GC roots is forbidden.
    GcRootMutation = 3,
    /// Selecting a caller-controlled substituter is forbidden.
    SubstituterSelection = 4,
    /// Reading or selecting signing keys is forbidden.
    SigningKeyAccess = 5,
    /// Enumerating paths outside the authorized disclosure domain is forbidden.
    CrossDomainPathDisclosure = 6,
    /// Publishing a NAR or cache record is separately authorized and forbidden.
    CachePublication = 7,
    /// Loading daemon or flake-supplied configuration is forbidden.
    ConfigurationOverride = 8,
    /// Forwarding an arbitrary Nix daemon operation is forbidden.
    RawDaemonOperation = 9,
}

/// Complete fail-closed denied-authority set for the v1 profile.
pub const DENIED_NIX_AUTHORITIES_V1: [DeniedNixAuthorityV1; 9] = [
    DeniedNixAuthorityV1::TrustedUser,
    DeniedNixAuthorityV1::DirectStoreMutation,
    DeniedNixAuthorityV1::GcRootMutation,
    DeniedNixAuthorityV1::SubstituterSelection,
    DeniedNixAuthorityV1::SigningKeyAccess,
    DeniedNixAuthorityV1::CrossDomainPathDisclosure,
    DeniedNixAuthorityV1::CachePublication,
    DeniedNixAuthorityV1::ConfigurationOverride,
    DeniedNixAuthorityV1::RawDaemonOperation,
];

/// Defines the three semantic verbs understood by the narrowing proxy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NixNarrowingProxyOperationV1 {
    /// Resolves one protected recipe already committed by the controller.
    ResolveProtectedRecipe = 1,
    /// Realizes one exact authorized derivation and bounded output set.
    RealizeAuthorizedDerivation = 2,
    /// Queries metadata for one path in the selected read audience.
    QueryAuthorizedPathInfo = 3,
}

/// Identifies one physically separate Nix store and disclosure database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NixStoreTrustDomainV1 {
    identity: ResourceId,
    disclosure_policy: ObjectDigest,
}

impl NixStoreTrustDomainV1 {
    /// Constructs one logical domain without accepting a host store path.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1::InvalidModel`] for sentinel
    /// identity or policy values.
    pub fn new(
        identity: ResourceId,
        disclosure_policy: ObjectDigest,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        if identity.as_bytes() == &[0; 16] || disclosure_policy.as_bytes() == &[0; 32] {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        Ok(Self {
            identity,
            disclosure_policy,
        })
    }

    /// Returns the logical trust-domain identity.
    #[must_use]
    pub const fn identity(self) -> ResourceId {
        self.identity
    }

    /// Returns the exact path-disclosure policy commitment.
    #[must_use]
    pub const fn disclosure_policy(self) -> ObjectDigest {
        self.disclosure_policy
    }
}

/// Declares the concrete untrusted daemon-client boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UntrustedNixClientConfigurationV1 {
    client: PrincipalId,
    endpoint: ResourceId,
    domain: NixStoreTrustDomainV1,
}

impl UntrustedNixClientConfigurationV1 {
    /// Constructs the fixed v1 configuration for one non-root client.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1::InvalidModel`] for sentinel
    /// identities. The model intentionally has no trusted-user or option fields.
    pub fn new(
        client: PrincipalId,
        endpoint: ResourceId,
        domain: NixStoreTrustDomainV1,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        if client.as_bytes() == &[0; 16] || endpoint.as_bytes() == &[0; 16] {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        Ok(Self {
            client,
            endpoint,
            domain,
        })
    }

    /// Borrows the complete exact daemon setting set.
    #[must_use]
    pub const fn daemon_settings(&self) -> &[(&'static str, &'static str)] {
        &UNTRUSTED_NIX_DAEMON_SETTINGS_V1
    }

    /// Borrows the complete denied authority set.
    #[must_use]
    pub const fn denied_authorities(&self) -> &[DeniedNixAuthorityV1] {
        &DENIED_NIX_AUTHORITIES_V1
    }

    /// Returns the client principal, which provisioning must map to a non-root account.
    #[must_use]
    pub const fn client(&self) -> PrincipalId {
        self.client
    }

    /// Returns the logical scoped endpoint rather than a daemon socket path.
    #[must_use]
    pub const fn endpoint(&self) -> ResourceId {
        self.endpoint
    }

    /// Returns the physically isolated store trust domain.
    #[must_use]
    pub const fn domain(&self) -> NixStoreTrustDomainV1 {
        self.domain
    }

    /// Commits the complete fixed untrusted-client configuration.
    #[must_use]
    pub fn commitment(&self) -> ObjectDigest {
        let mut digest = Sha256::new()
            .chain_update(b"aos.sandbox.environment.untrusted-nix-client.v1\0")
            .chain_update(self.client.as_bytes())
            .chain_update(self.endpoint.as_bytes())
            .chain_update(self.domain.identity().as_bytes())
            .chain_update(self.domain.disclosure_policy().as_bytes());
        for (name, value) in UNTRUSTED_NIX_DAEMON_SETTINGS_V1 {
            digest = digest
                .chain_update((name.len() as u16).to_be_bytes())
                .chain_update(name.as_bytes())
                .chain_update((value.len() as u16).to_be_bytes())
                .chain_update(value.as_bytes());
        }
        for denied in DENIED_NIX_AUTHORITIES_V1 {
            digest = digest.chain_update([denied as u8]);
        }
        ObjectDigest::from_bytes(digest.finalize().into())
    }
}

/// Declares the bounded request surface of a mandatory narrowing proxy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NixNarrowingProxyPolicyV1 {
    endpoint: ResourceId,
    domain: NixStoreTrustDomainV1,
    maximum_request_bytes: u64,
    maximum_response_bytes: u64,
    maximum_output_objects: u32,
}

impl NixNarrowingProxyPolicyV1 {
    /// Constructs one path-free, closed-verb proxy policy.
    ///
    /// # Errors
    ///
    /// Returns [`EnvironmentExecutionErrorV1::InvalidModel`] for sentinel or
    /// excessive bounds.
    pub fn new(
        endpoint: ResourceId,
        domain: NixStoreTrustDomainV1,
        maximum_request_bytes: u64,
        maximum_response_bytes: u64,
        maximum_output_objects: u32,
    ) -> Result<Self, EnvironmentExecutionErrorV1> {
        if endpoint.as_bytes() == &[0; 16]
            || maximum_request_bytes == 0
            || maximum_request_bytes > super::MAXIMUM_NIX_BUILD_CONTROL_BYTES
            || maximum_response_bytes == 0
            || maximum_response_bytes > super::MAXIMUM_NIX_BUILD_CONTROL_BYTES
            || maximum_output_objects == 0
            || !usize::try_from(maximum_output_objects)
                .is_ok_and(|count| count <= super::MAXIMUM_NIX_STORE_PRESENTATION_OBJECTS)
        {
            return Err(EnvironmentExecutionErrorV1::InvalidModel);
        }
        Ok(Self {
            endpoint,
            domain,
            maximum_request_bytes,
            maximum_response_bytes,
            maximum_output_objects,
        })
    }

    /// Borrows the complete closed operation vocabulary.
    #[must_use]
    pub const fn operations(&self) -> &[NixNarrowingProxyOperationV1] {
        const OPERATIONS: [NixNarrowingProxyOperationV1; 3] = [
            NixNarrowingProxyOperationV1::ResolveProtectedRecipe,
            NixNarrowingProxyOperationV1::RealizeAuthorizedDerivation,
            NixNarrowingProxyOperationV1::QueryAuthorizedPathInfo,
        ];
        &OPERATIONS
    }

    /// Borrows the exact upstream daemon settings the proxy must preserve.
    #[must_use]
    pub const fn daemon_settings(&self) -> &[(&'static str, &'static str)] {
        &UNTRUSTED_NIX_DAEMON_SETTINGS_V1
    }

    /// Borrows the complete denied authority set enforced on every proxy verb.
    #[must_use]
    pub const fn denied_authorities(&self) -> &[DeniedNixAuthorityV1] {
        &DENIED_NIX_AUTHORITIES_V1
    }

    /// Returns the logical proxy endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> ResourceId {
        self.endpoint
    }

    /// Returns the physically isolated store trust domain.
    #[must_use]
    pub const fn domain(&self) -> NixStoreTrustDomainV1 {
        self.domain
    }

    /// Returns the request byte ceiling.
    #[must_use]
    pub const fn maximum_request_bytes(&self) -> u64 {
        self.maximum_request_bytes
    }

    /// Returns the response byte ceiling.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u64 {
        self.maximum_response_bytes
    }

    /// Returns the terminal output-object ceiling.
    #[must_use]
    pub const fn maximum_output_objects(&self) -> u32 {
        self.maximum_output_objects
    }

    /// Commits the endpoint, trust domain, bounds, and closed operation set.
    #[must_use]
    pub fn commitment(&self) -> ObjectDigest {
        let mut digest = Sha256::new()
            .chain_update(b"aos.sandbox.environment.nix-narrowing-proxy.v1\0")
            .chain_update(self.endpoint.as_bytes())
            .chain_update(self.domain.identity().as_bytes())
            .chain_update(self.domain.disclosure_policy().as_bytes())
            .chain_update(self.maximum_request_bytes.to_be_bytes())
            .chain_update(self.maximum_response_bytes.to_be_bytes())
            .chain_update(self.maximum_output_objects.to_be_bytes());
        for operation in self.operations() {
            digest = digest.chain_update([*operation as u8]);
        }
        for (name, value) in self.daemon_settings() {
            digest = digest
                .chain_update((name.len() as u16).to_be_bytes())
                .chain_update(name.as_bytes())
                .chain_update((value.len() as u16).to_be_bytes())
                .chain_update(value.as_bytes());
        }
        for denied in self.denied_authorities() {
            digest = digest.chain_update([*denied as u8]);
        }
        ObjectDigest::from_bytes(digest.finalize().into())
    }
}

/// Carries the exact protected client boundary selected for one build effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NixClientBoundaryV1 {
    /// Uses the complete fixed untrusted-daemon settings and denied authorities.
    UntrustedDaemon(UntrustedNixClientConfigurationV1),
    /// Uses the closed-operation narrowing proxy and its exact bounds.
    NarrowingProxy(NixNarrowingProxyPolicyV1),
}

impl NixClientBoundaryV1 {
    /// Returns the commitment covering every security-relevant client field.
    #[must_use]
    pub fn commitment(&self) -> ObjectDigest {
        match self {
            Self::UntrustedDaemon(configuration) => configuration.commitment(),
            Self::NarrowingProxy(configuration) => configuration.commitment(),
        }
    }

    /// Returns the exact logical endpoint the backend must use.
    #[must_use]
    pub const fn endpoint(&self) -> ResourceId {
        match self {
            Self::UntrustedDaemon(configuration) => configuration.endpoint(),
            Self::NarrowingProxy(configuration) => configuration.endpoint(),
        }
    }

    /// Returns the exact isolated store trust domain.
    #[must_use]
    pub const fn domain(&self) -> NixStoreTrustDomainV1 {
        match self {
            Self::UntrustedDaemon(configuration) => configuration.domain(),
            Self::NarrowingProxy(configuration) => configuration.domain(),
        }
    }

    /// Borrows the fixed daemon settings enforced for either transport.
    #[must_use]
    pub const fn daemon_settings(&self) -> &[(&'static str, &'static str)] {
        &UNTRUSTED_NIX_DAEMON_SETTINGS_V1
    }

    /// Borrows the authorities denied for either transport.
    #[must_use]
    pub const fn denied_authorities(&self) -> &[DeniedNixAuthorityV1] {
        &DENIED_NIX_AUTHORITIES_V1
    }

    /// Borrows the proxy's complete closed operation set, when selected.
    #[must_use]
    pub const fn proxy_operations(&self) -> Option<&[NixNarrowingProxyOperationV1]> {
        match self {
            Self::UntrustedDaemon(_) => None,
            Self::NarrowingProxy(configuration) => Some(configuration.operations()),
        }
    }

    pub(crate) fn matches_policy(&self, policy: super::NixBuildPolicyV1) -> bool {
        match self {
            Self::UntrustedDaemon(_) => {
                policy.transport() == super::NixBuildTransportV1::UntrustedDaemonClient
            }
            Self::NarrowingProxy(configuration) => {
                policy.transport() == super::NixBuildTransportV1::NarrowingProxy
                    && configuration.maximum_request_bytes() <= policy.maximum_control_bytes()
                    && configuration.maximum_response_bytes() <= policy.maximum_control_bytes()
                    && configuration.maximum_output_objects() == policy.maximum_output_objects()
            }
        }
    }
}

pub(crate) fn encode_nix_client_boundary_v1(boundary: NixClientBoundaryV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(85);
    match boundary {
        NixClientBoundaryV1::UntrustedDaemon(configuration) => {
            bytes.push(1);
            bytes.extend_from_slice(configuration.client().as_bytes());
            bytes.extend_from_slice(configuration.endpoint().as_bytes());
            encode_domain(&mut bytes, configuration.domain());
        }
        NixClientBoundaryV1::NarrowingProxy(configuration) => {
            bytes.push(2);
            bytes.extend_from_slice(configuration.endpoint().as_bytes());
            encode_domain(&mut bytes, configuration.domain());
            bytes.extend_from_slice(&configuration.maximum_request_bytes().to_be_bytes());
            bytes.extend_from_slice(&configuration.maximum_response_bytes().to_be_bytes());
            bytes.extend_from_slice(&configuration.maximum_output_objects().to_be_bytes());
        }
    }
    bytes
}

pub(crate) fn decode_nix_client_boundary_v1(
    bytes: &[u8],
) -> Result<NixClientBoundaryV1, EnvironmentExecutionErrorV1> {
    match bytes.first().copied() {
        Some(1) if bytes.len() == 81 => {
            let client = PrincipalId::from_bytes(array(&bytes[1..17])?);
            let endpoint = ResourceId::from_bytes(array(&bytes[17..33])?);
            let domain = decode_domain(&bytes[33..81])?;
            Ok(NixClientBoundaryV1::UntrustedDaemon(
                UntrustedNixClientConfigurationV1::new(client, endpoint, domain)?,
            ))
        }
        Some(2) if bytes.len() == 85 => {
            let endpoint = ResourceId::from_bytes(array(&bytes[1..17])?);
            let domain = decode_domain(&bytes[17..65])?;
            Ok(NixClientBoundaryV1::NarrowingProxy(
                NixNarrowingProxyPolicyV1::new(
                    endpoint,
                    domain,
                    u64::from_be_bytes(array(&bytes[65..73])?),
                    u64::from_be_bytes(array(&bytes[73..81])?),
                    u32::from_be_bytes(array(&bytes[81..85])?),
                )?,
            ))
        }
        _ => Err(EnvironmentExecutionErrorV1::InvalidModel),
    }
}

fn encode_domain(bytes: &mut Vec<u8>, domain: NixStoreTrustDomainV1) {
    bytes.extend_from_slice(domain.identity().as_bytes());
    bytes.extend_from_slice(domain.disclosure_policy().as_bytes());
}

fn decode_domain(bytes: &[u8]) -> Result<NixStoreTrustDomainV1, EnvironmentExecutionErrorV1> {
    if bytes.len() != 48 {
        return Err(EnvironmentExecutionErrorV1::InvalidModel);
    }
    NixStoreTrustDomainV1::new(
        ResourceId::from_bytes(array(&bytes[..16])?),
        ObjectDigest::from_bytes(array(&bytes[16..48])?),
    )
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], EnvironmentExecutionErrorV1> {
    bytes
        .try_into()
        .map_err(|_| EnvironmentExecutionErrorV1::InvalidModel)
}
