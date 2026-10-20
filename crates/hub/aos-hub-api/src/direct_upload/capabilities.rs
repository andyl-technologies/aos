//! Authenticated public transport discovery, without provider credentials.

use serde::{Deserialize, Serialize};

use super::*;

/// Closed resource selector for authenticated direct transport discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectGetCapabilities {
    /// Logical target whose current ACL/topology is resolved by Native.
    pub target: DirectCapabilitiesTarget,
}

/// Reusable resource owner, independently of any per-object upload path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DirectCapabilitiesTarget {
    /// Authenticated ready delivery route, resolved to a canonical cache owner.
    CacheDelivery {
        /// Canonical HTTP(S) route locator; never a provider or Begin object key.
        delivery_url: String,
    },
    /// Managed cache namespace; Native still authorizes every BeginBatch item.
    Cache {
        /// Stable logical cache identity.
        cache_id: String,
    },
    /// Retained publication namespace and admitted inventory plan.
    Publication {
        /// Stable retained publication/plan identity.
        publication_id: String,
    },
    /// Existing OCI registry/repository owner, independently of logical upload IDs.
    OciRepository {
        /// Stable registry identity from the existing container API.
        registry: String,
        /// Canonical repository namespace.
        repository: String,
    },
}

impl DirectCapabilitiesTarget {
    /// Checks a reusable logical owner without granting per-object storage scope.
    ///
    /// # Errors
    /// Returns an error for malformed cache/publication/registry/repository IDs.
    pub fn validate(&self) -> DirectUploadResult<()> {
        use super::validation::require;
        let valid = match self {
            Self::CacheDelivery { delivery_url } => valid_direct_delivery_url(delivery_url),
            Self::Cache { cache_id } => valid_direct_identity(cache_id),
            Self::Publication { publication_id } => valid_direct_identity(publication_id),
            Self::OciRepository {
                registry,
                repository,
            } => valid_direct_identity(registry) && valid_direct_path(repository),
        };
        require(valid, "invalid direct capability owner")
    }
}

/// Checks a canonical HTTP(S) metadata locator without assigning cache authority.
pub fn valid_direct_delivery_url(value: &str) -> bool {
    canonical_direct_delivery_url(value).is_ok_and(|canonical| canonical == value)
}

/// Normalizes a discovery locator using the existing ready-route slash rule.
///
/// This performs no fetch, grants no cache/provider authority, and does not
/// relax HTTPS requirements for provider capabilities. Client Hub transport
/// policy and Native authenticated ready-route/ACL resolution remain required.
///
/// # Errors
/// Returns an error for excessive length, whitespace/control characters,
/// non-HTTP(S) URLs, credentials, query strings or fragments.
pub fn canonical_direct_delivery_url(value: &str) -> DirectUploadResult<String> {
    use super::validation::require;
    require(
        value.len() <= 2048 && value.trim() == value && !value.chars().any(char::is_control),
        "invalid direct delivery locator",
    )?;
    let url =
        url::Url::parse(value).map_err(|_| DirectUploadError("invalid direct delivery locator"))?;
    require(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "invalid direct delivery locator",
    )?;
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// Explicit server transport policy, never inferred from failed requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectAdvertisedTransferMode {
    /// Private direct staging is required and currently qualified.
    DirectRequired,
    /// This server explicitly advertises its existing application upload path.
    Legacy,
}

/// Public provider confinement projection resolved for one required placement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectProviderProfile {
    /// Required destination row, independent of any per-file final key.
    pub placement_id: WireInteger,
    /// Exact reviewed placement version.
    pub placement_resource_version: WireInteger,
    /// Exact placement writer specification version.
    pub write_spec_version: WireInteger,
    /// Exact storage binding row identity.
    pub binding_id: WireInteger,
    /// Exact storage binding version.
    pub binding_resource_version: WireInteger,
    /// Exact binding writer revision.
    pub binding_write_revision: WireInteger,
    /// Qualified checksum selected before grant requests.
    pub checksum_algorithm: DirectChecksumAlgorithm,
    /// HTTPS origin only, independently pinned by the authenticated response.
    pub provider_origin: String,
    /// Exact protected credential/coordinate publication commitment, no secrets.
    pub profile_fingerprint: String,
    /// Exact independently qualified private staging policy commitment.
    pub private_policy_digest: String,
}

/// Bounded public discovery reply with explicit transport and protocol limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectUploadCapabilities {
    /// Exact authorized target echoed to prevent cross-resource adoption.
    pub target: DirectCapabilitiesTarget,
    /// Exact delivery locator echo only when discovery resolved CacheDelivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_delivery_url: Option<String>,
    /// Authenticated deployment namespace, or empty for explicit unconfigured Legacy.
    #[serde(default)]
    pub deployment_id: String,
    /// Stable authenticated actor identity, or empty alongside the Legacy deployment.
    #[serde(default)]
    pub principal_id: String,
    /// Closed protocol version, currently one.
    pub version: u32,
    /// Explicit protocol capability identifier.
    pub capability: String,
    /// Current reviewed transport mode; failure is never a legacy advertisement.
    pub transfer_mode: DirectAdvertisedTransferMode,
    /// Exact reviewed owner/configuration generation.
    pub config_generation: WireInteger,
    /// Exclusive authenticated metadata cache deadline; no provider settlement.
    pub valid_until: WireInteger,
    /// Maximum whole request or reply bytes, including delegated URLs.
    pub maximum_control_bytes: u32,
    /// Maximum objects per batch.
    pub maximum_batch_items: u32,
    /// Aggregate provider parts/grants per batch after placement fanout.
    pub maximum_batch_parts: u32,
    /// Minimum complete object size; one when any required external destination cannot abort empty puts.
    #[serde(default)]
    pub minimum_object_bytes: WireInteger,
    /// Maximum full object size.
    #[serde(default)]
    pub maximum_object_bytes: WireInteger,
    /// Minimum nonfinal part geometry.
    #[serde(default)]
    pub minimum_part_bytes: WireInteger,
    /// Maximum part geometry.
    #[serde(default)]
    pub maximum_part_bytes: WireInteger,
    /// Sorted reviewed required destinations; empty only for explicit legacy.
    #[serde(default)]
    pub profiles: Vec<DirectProviderProfile>,
}

impl DirectUploadCapabilities {
    /// Checks the closed response shape before correlation with its request.
    ///
    /// # Errors
    /// Returns an error for an invalid canonical owner, locator echo or limits.
    pub fn validate(&self) -> DirectUploadResult<()> {
        let target = self.requested_delivery_url.as_ref().map_or_else(
            || self.target.clone(),
            |delivery_url| DirectCapabilitiesTarget::CacheDelivery {
                delivery_url: delivery_url.clone(),
            },
        );
        self.validate_for(&target)
    }

    /// Matches discovery to the exact retained authenticated journal namespace.
    ///
    /// This grants no resource ACL and makes no assertion about arbitrary Hub
    /// resets. Native must preserve these identities or use a new deployment.
    ///
    /// # Errors
    /// Returns an error for changed or malformed deployment/principal identity.
    pub fn validate_actor_for(&self, deployment: &str, principal: &str) -> DirectUploadResult<()> {
        super::validation::require(
            valid_direct_identity(deployment)
                && valid_direct_digest(principal)
                && self.deployment_id == deployment
                && self.principal_id == principal,
            "direct capability actor namespace mismatch",
        )
    }

    /// Matches the complete original Begin destination set to reusable discovery.
    ///
    /// Every binding/writer revision, credential publication, private policy and
    /// checksum must match; this does not authorize a client-chosen final key.
    ///
    /// # Errors
    /// Returns an error for expired discovery, changed or incomplete placement
    /// sets, or any mismatched reviewed profile field.
    pub fn validate_placements_for(
        &self,
        target: &DirectCapabilitiesTarget,
        placements: &[DirectPlacementRef],
        latest_now: u64,
    ) -> DirectUploadResult<()> {
        use super::validation::require;
        self.validate_at_for(target, latest_now)?;
        require(
            self.transfer_mode == DirectAdvertisedTransferMode::DirectRequired
                && placements.len() == self.profiles.len(),
            "direct capability placement set mismatch",
        )?;
        for (placement, profile) in placements.iter().zip(&self.profiles) {
            profile.validate_placement(placement)?;
        }
        Ok(())
    }

    /// Checks reusable discovery and its exclusive cache deadline.
    ///
    /// # Errors
    /// Returns an error for invalid discovery or an expired conservative time bound.
    pub fn validate_at_for(
        &self,
        target: &DirectCapabilitiesTarget,
        latest_now: u64,
    ) -> DirectUploadResult<()> {
        self.validate_for(target)?;
        super::validation::require(
            latest_now < self.valid_until.get(),
            "direct capability discovery expired",
        )
    }

    /// Checks discovery against the exact authorized target and protocol bounds.
    ///
    /// Network policy remains client-owned; an error is not legacy discovery.
    ///
    /// # Errors
    /// Returns an error for changed target, unknown version/capability, invalid
    /// limits, unordered profiles or an unsupported provider origin projection.
    pub fn validate_for(&self, target: &DirectCapabilitiesTarget) -> DirectUploadResult<()> {
        use super::validation::require;
        target.validate()?;
        let matches_target = match target {
            DirectCapabilitiesTarget::CacheDelivery { delivery_url } => {
                matches!(&self.target, DirectCapabilitiesTarget::Cache { .. })
                    && self.requested_delivery_url.as_ref() == Some(delivery_url)
            }
            _ => &self.target == target && self.requested_delivery_url.is_none(),
        };
        self.target.validate()?;
        require(
            !matches!(&self.target, DirectCapabilitiesTarget::CacheDelivery { .. })
                && self
                    .requested_delivery_url
                    .as_ref()
                    .is_none_or(|value| valid_direct_delivery_url(value)),
            "invalid direct capability canonical owner",
        )?;
        // An explicit standalone Legacy policy need not invent a deployment or
        // actor namespace. Empty identities never authorize direct dispatch or
        // satisfy validate_actor_for; partial modern identity still fails closed.
        let valid_actor =
            valid_direct_identity(&self.deployment_id) && valid_direct_digest(&self.principal_id);
        let unconfigured_legacy = self.transfer_mode == DirectAdvertisedTransferMode::Legacy
            && self.profiles.is_empty()
            && self.deployment_id.is_empty()
            && self.principal_id.is_empty();
        require(
            matches_target
                && (valid_actor || unconfigured_legacy)
                && self.version == 1
                && self.capability == DIRECT_UPLOAD_CAPABILITY
                && (1..=i64::MAX as u64).contains(&self.config_generation.get())
                && self.valid_until.get() > 0,
            "direct-upload discovery correlation mismatch",
        )?;
        require(
            self.maximum_control_bytes > 0
                && self.maximum_control_bytes as usize <= MAX_DIRECT_CONTROL_BYTES
                && self.maximum_batch_items > 0
                && self.maximum_batch_items as usize <= MAX_DIRECT_BATCH_ITEMS
                && self.maximum_batch_parts > 0
                && self.maximum_batch_parts as usize <= MAX_DIRECT_BATCH_PARTS
                && self.maximum_object_bytes.get() > 0
                && self.maximum_object_bytes.get() <= MAX_DIRECT_OBJECT_BYTES
                && self.minimum_object_bytes.get() <= self.maximum_object_bytes.get()
                && self.minimum_part_bytes.get() >= MIN_DIRECT_PART_BYTES
                && self.maximum_part_bytes.get() <= MAX_DIRECT_PART_BYTES
                && self.minimum_part_bytes.get() <= self.maximum_part_bytes.get(),
            "invalid direct-upload advertised limits",
        )?;
        require(
            self.profiles.len() <= MAX_DIRECT_PLACEMENTS
                && (self.transfer_mode == DirectAdvertisedTransferMode::Legacy)
                    == self.profiles.is_empty(),
            "direct-upload discovery transport mismatch",
        )?;
        let mut previous = 0;
        for profile in &self.profiles {
            for value in [
                profile.placement_id,
                profile.placement_resource_version,
                profile.write_spec_version,
                profile.binding_id,
                profile.binding_resource_version,
                profile.binding_write_revision,
            ] {
                require(
                    (1..=i64::MAX as u64).contains(&value.get()),
                    "invalid direct provider profile revision",
                )?;
            }
            require(
                profile.placement_id.get() > previous
                    && valid_direct_digest(&profile.profile_fingerprint)
                    && valid_direct_digest(&profile.private_policy_digest),
                "invalid direct-upload provider profile",
            )?;
            previous = profile.placement_id.get();
            let origin = url::Url::parse(&profile.provider_origin)
                .map_err(|_| DirectUploadError("invalid direct-upload provider origin"))?;
            require(
                origin.scheme() == "https"
                    && origin.host_str().is_some()
                    && origin.username().is_empty()
                    && origin.password().is_none()
                    && origin.query().is_none()
                    && origin.fragment().is_none()
                    && origin.path() == "/"
                    && origin.origin().ascii_serialization() == profile.provider_origin,
                "invalid direct-upload provider origin",
            )?;
        }
        encode_direct_control(self)?;
        Ok(())
    }
}

impl DirectProviderProfile {
    /// Correlates one original destination to this reviewed reusable profile.
    ///
    /// This checks public association fields, not provider reachability, DNS,
    /// credentials, qualification or the private final-key authorization.
    ///
    /// # Errors
    /// Returns an error for malformed or changed destination/profile fields.
    pub fn validate_placement(&self, placement: &DirectPlacementRef) -> DirectUploadResult<()> {
        placement.validate()?;
        super::validation::require(
            placement.placement_id == self.placement_id
                && placement.placement_resource_version == self.placement_resource_version
                && placement.write_spec_version == self.write_spec_version
                && placement.binding_id == self.binding_id
                && placement.binding_resource_version == self.binding_resource_version
                && placement.binding_write_revision == self.binding_write_revision
                && placement.checksum_algorithm == self.checksum_algorithm
                && placement.profile_fingerprint == self.profile_fingerprint
                && placement.private_policy_digest == self.private_policy_digest,
            "direct capability placement profile mismatch",
        )
    }
}
