//! Lifecycle mutations in the runtime capability.

use super::*;

impl RpcService {
    /// Attaches the Nix cache public keys advertised for each registry.
    ///
    /// Registry SSH signing keys authenticate Git objects. Cache keys authenticate
    /// NAR archives and use Nix's raw Ed25519 key format instead.
    ///
    /// # Errors
    /// Returns an error if a cache key is unnamed, malformed, or noncanonical.
    pub fn with_registry_cache_public_keys(
        mut self,
        keys: BTreeMap<String, Vec<String>>,
    ) -> anyhow::Result<Self> {
        for registry_keys in keys.values() {
            for key in registry_keys {
                let (name, encoded) = key
                    .split_once(':')
                    .context("Nix cache public key requires name:base64")?;
                anyhow::ensure!(!name.is_empty(), "Nix cache public key name is empty");
                let canonical =
                    crate::nix_sign::nix_public_key_from_raw(name, encoded.trim_end_matches('='))?;
                anyhow::ensure!(canonical == *key, "Nix cache public key is noncanonical");
            }
        }

        self.registry_cache_public_keys = keys;
        Ok(self)
    }

    /// Attaches the deployment-owned release evidence authority.
    #[must_use]
    pub fn with_release_evidence(
        mut self,
        authority: Arc<dyn crate::release_evidence::ReleaseEvidenceAuthority>,
    ) -> Self {
        self.release_evidence = Some(authority);
        self
    }

    /// Attaches the runtime DNS verifier for organization-domain challenges.
    #[must_use]
    pub fn with_identity_domain_verifier(
        mut self,
        verifier: Arc<dyn crate::topology_probe::IdentityDomainVerifier>,
    ) -> Self {
        self.identity_domain_verifier = Some(verifier);
        self
    }

    /// Construct the service over its dependencies.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Arc<Database>,
        jwt_keys: JwtKeys,
        external_url: String,
        ratelimit: Arc<dyn RateLimiter>,
        surface: Arc<dyn SurfaceProvider>,
        surface_write: Arc<dyn SurfaceWriteProvider>,
        lease: Arc<dyn PublishLease>,
        reindexer: Arc<dyn Reindexer>,
        topology_probes: Arc<dyn TopologyProbeScheduler>,
        sealer: Option<Arc<dyn aos_hub_model::auth::seal::SecretSealer>>,
    ) -> Self {
        Self {
            db,
            jwt_keys,
            external_url,
            registry_cache_public_keys: BTreeMap::new(),
            default_public_delivery_url: None,
            container_rollout: crate::container_rollout::ContainerRollout::default(),
            ratelimit,
            surface,
            surface_write,
            lease,
            reindexer,
            topology_probes,
            sealer,
            secret_versions: None,
            origin_fetch: None,
            kv: None,
            domain_probe_terminator: None,
            identity_domain_verifier: None,
            route_reservation_keyring: None,
            maintenance_jobs: None,
            release_evidence: None,
            pack_validation: pack_validation_gate(),
        }
    }

    /// Attaches the public origin for the instance-default storage binding.
    ///
    /// Explicit canonical route advertisements always take precedence over
    /// this derived delivery policy.
    #[must_use]
    pub fn with_default_public_delivery_url(mut self, url: String) -> Self {
        self.default_public_delivery_url = Some(url);
        self
    }

    /// Attaches the independently configured OCI capability rollout policy.
    #[must_use]
    pub fn with_container_rollout(
        mut self,
        rollout: crate::container_rollout::ContainerRollout,
    ) -> Self {
        self.container_rollout = rollout;
        self
    }

    /// Attaches the runtime provider for immutable secret-version references.
    #[must_use]
    pub fn with_secret_versions(
        mut self,
        resolver: Arc<dyn aos_hub_model::secret_version::SecretVersionResolver>,
    ) -> Self {
        self.secret_versions = Some(resolver);
        self
    }

    /// Attaches the durable queue used to run maintenance jobs on demand.
    #[must_use]
    pub fn with_maintenance_jobs(mut self, queue: Arc<dyn crate::jobs::Queue>) -> Self {
        self.maintenance_jobs = Some(queue);
        self
    }

    /// Attach a [`KvStore`](crate::kv::KvStore) for read-through caching of hot
    /// point-key state, returning the modified service.
    ///
    /// Without it, sessions/tokens/config/routing reads go straight to the
    /// database; with it, those reads are served cache-aside off KV with a short
    /// TTL and invalidated on write (RFC-0004 ch.14 Phase C).
    #[must_use]
    pub fn with_kv(mut self, kv: Arc<dyn crate::kv::KvStore>) -> Self {
        self.kv = Some(kv);
        self
    }

    /// Attach an [`OriginFetch`](crate::fetch::OriginFetch) for streamed proxying
    /// of private-origin cache reads, returning the modified service.
    ///
    /// Without it, a private-origin cache serves a presigned `302`; with it, a
    /// an eligible Hub-proxy route may stream origin bytes through Hub.
    #[must_use]
    pub fn with_origin_fetch(mut self, origin_fetch: Arc<dyn crate::fetch::OriginFetch>) -> Self {
        self.origin_fetch = Some(origin_fetch);
        self
    }

    /// Attaches the runtime-owned route-reservation keyring.
    #[must_use]
    pub fn with_route_reservation_keyring(
        mut self,
        keyring: Arc<dyn RouteReservationKeyring>,
    ) -> Self {
        self.route_reservation_keyring = Some(keyring);
        self
    }

    /// Attaches the runtime-owned domain-probe terminator provider.
    #[must_use]
    pub fn with_domain_probe_terminator(
        mut self,
        provider: Arc<dyn crate::topology_probe::DomainProbeTerminatorProvider>,
    ) -> Self {
        self.domain_probe_terminator = Some(provider);
        self
    }
}
