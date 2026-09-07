//! Strict S3 endpoint, credential, and remote-ref deployment capabilities.
//!
//! Endpoint policy and worker bounds are non-secret deployment state. Secret
//! credentials live in a separate owner-only registered file and are reloaded
//! by the AWS SDK provider when an expiring identity needs refresh.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_credential_types::Credentials;
use aws_credential_types::provider::{ProvideCredentials, error::CredentialsError, future};
use crucible_daemon::campaign_store_composition::{
    AwsSdkS3Client, AwsSdkS3ClientConfig, AwsSdkS3StrongCasClient, S3RefBackend,
    StoreGraphS3Clients, StoreNodeId, StoreNodeSpec, StoreS3EndpointId, StoreS3RefCapability,
};
use serde::Deserialize;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use super::{CliError, campaign_store_error, read_secure_file, validate_absolute_normal_path};

const S3_CREDENTIAL_SCHEMA: &str = "crucible.campaign-s3-credentials";
const S3_CREDENTIAL_VERSION: u32 = 1;
const MAX_S3_CREDENTIAL_FILE_BYTES: usize = 16 * 1024;
const MAX_S3_ENDPOINT_URL_BYTES: usize = 2_048;
const MAX_S3_REGION_BYTES: usize = 64;
const MAX_S3_ACCESS_KEY_ID_BYTES: usize = 256;
const MAX_S3_SECRET_ACCESS_KEY_BYTES: usize = 4 * 1024;
const MAX_S3_SESSION_TOKEN_BYTES: usize = 8 * 1024;
const MAX_S3_BUCKET_BYTES: usize = 63;
const MAX_S3_PREFIX_BYTES: usize = 922;
const MIN_S3_MULTIPART_PART_BYTES: u64 = 5 * 1024 * 1024;
const MAX_S3_MULTIPART_PART_BYTES: u64 = 64 * 1024 * 1024;
const MAX_S3_MULTIPART_PARTS: u64 = 10_000;

/// One strict non-secret endpoint and bounded-worker deployment.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthoredS3Endpoint {
    id: String,
    region: String,
    endpoint_url: String,
    force_path_style: bool,
    credential_path: PathBuf,
    maximum_queued_commands: usize,
    maximum_in_flight_operations: usize,
    maximum_retained_command_bytes: u64,
    operation_timeout_ms: u64,
    strong_cas_conformance: bool,
}

/// One strong-CAS remote ref namespace.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthoredS3RefBackend {
    endpoint: String,
    bucket: String,
    prefix: String,
}

/// Validated non-secret remote-ref configuration.
pub(super) struct ResolvedS3RefBackend {
    endpoint: StoreS3EndpointId,
    bucket: String,
    prefix: String,
}

impl ResolvedS3RefBackend {
    pub(super) fn endpoint(&self) -> &StoreS3EndpointId {
        &self.endpoint
    }

    pub(super) fn build(
        self,
        capabilities: &LoadedS3Capabilities,
    ) -> Result<Arc<S3RefBackend>, CliError> {
        let strong = capabilities
            .strong
            .get(&self.endpoint)
            .cloned()
            .ok_or_else(|| {
                campaign_store_error("S3 ref backend has no exact strong-CAS endpoint capability")
            })?;
        let capability = StoreS3RefCapability::new(self.endpoint, self.bucket, self.prefix, strong)
            .map_err(|error| campaign_store_error(format!("invalid S3 ref backend: {error}")))?;
        Ok(Arc::new(S3RefBackend::new(capability)))
    }
}

impl AuthoredS3RefBackend {
    pub(super) fn resolve(self) -> Result<ResolvedS3RefBackend, CliError> {
        let endpoint = StoreS3EndpointId::new(self.endpoint).map_err(|error| {
            campaign_store_error(format!("invalid S3 ref endpoint ID: {error}"))
        })?;
        validate_s3_location(&self.bucket, &self.prefix)?;
        Ok(ResolvedS3RefBackend {
            endpoint,
            bucket: self.bucket,
            prefix: self.prefix,
        })
    }
}

/// Rejects overlapping physical namespaces before credentials or workers are
/// admitted. An inventory/cleanup scan must never encounter another logical
/// leaf's objects, refs, or administration records.
pub(super) fn validate_s3_namespace_separation(
    nodes: &BTreeMap<StoreNodeId, StoreNodeSpec>,
    refs: Option<&ResolvedS3RefBackend>,
) -> Result<(), CliError> {
    let mut namespaces = nodes
        .values()
        .filter_map(|node| match node {
            StoreNodeSpec::S3 {
                endpoint,
                bucket,
                prefix,
                ..
            } => Some((endpoint, bucket.as_str(), prefix.as_str())),
            _ => None,
        })
        .collect::<Vec<_>>();
    if let Some(refs) = refs {
        namespaces.push((&refs.endpoint, refs.bucket.as_str(), refs.prefix.as_str()));
    }
    for (index, left) in namespaces.iter().enumerate() {
        for right in &namespaces[index + 1..] {
            if left.0 == right.0 && left.1 == right.1 && prefixes_overlap(left.2, right.2) {
                return Err(campaign_store_error(
                    "S3 graph/ref physical namespaces overlap",
                ));
            }
        }
    }
    Ok(())
}

/// Validates one S3 leaf's bucket, prefix, and multipart geometry before any
/// operational capability is constructed.
pub(super) fn validate_s3_storage_configuration(
    bucket: &str,
    prefix: &str,
    maximum_logical_object_bytes: u64,
    multipart_part_bytes: u64,
) -> Result<(), CliError> {
    validate_s3_location(bucket, prefix)?;
    let maximum_upload_bytes = multipart_part_bytes
        .checked_mul(MAX_S3_MULTIPART_PARTS)
        .ok_or_else(|| campaign_store_error("S3 multipart geometry overflows"))?;
    if maximum_logical_object_bytes == 0
        || !(MIN_S3_MULTIPART_PART_BYTES..=MAX_S3_MULTIPART_PART_BYTES)
            .contains(&multipart_part_bytes)
        || maximum_logical_object_bytes > maximum_upload_bytes
    {
        return Err(campaign_store_error("invalid S3 multipart geometry"));
    }
    Ok(())
}

fn validate_s3_location(bucket: &str, prefix: &str) -> Result<(), CliError> {
    let valid_bucket = (3..=MAX_S3_BUCKET_BYTES).contains(&bucket.len())
        && bucket
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    let valid_prefix = prefix.len() <= MAX_S3_PREFIX_BYTES
        && !prefix.starts_with('/')
        && !prefix.ends_with('/')
        && (prefix.is_empty()
            || prefix.split('/').all(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment.len() <= 255
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            }));
    if !valid_bucket || !valid_prefix {
        return Err(campaign_store_error("invalid S3 bucket or prefix"));
    }
    Ok(())
}

fn prefixes_overlap(left: &str, right: &str) -> bool {
    left == right
        || left.is_empty()
        || right.is_empty()
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Loaded ordinary and strong endpoint capabilities for graph/ref construction.
pub(super) struct LoadedS3Capabilities {
    pub(super) graph: StoreGraphS3Clients,
    strong: BTreeMap<StoreS3EndpointId, Arc<AwsSdkS3StrongCasClient>>,
}

/// Indexes and validates endpoint policy before reading any credential file or
/// starting an SDK worker.
pub(super) fn index_s3_endpoints(
    endpoints: Vec<AuthoredS3Endpoint>,
) -> Result<BTreeMap<StoreS3EndpointId, AuthoredS3Endpoint>, CliError> {
    let mut indexed = BTreeMap::new();
    for endpoint in endpoints {
        endpoint.validate_non_secret()?;
        let id = StoreS3EndpointId::new(endpoint.id.clone()).map_err(|error| {
            campaign_store_error(format!("invalid S3 endpoint policy ID: {error}"))
        })?;
        if indexed.insert(id, endpoint).is_some() {
            return Err(campaign_store_error("duplicate S3 endpoint policy ID"));
        }
    }
    Ok(indexed)
}

/// Returns the exact configured endpoint identifiers.
pub(super) fn s3_endpoint_ids(
    endpoints: &BTreeMap<StoreS3EndpointId, AuthoredS3Endpoint>,
) -> BTreeSet<StoreS3EndpointId> {
    endpoints.keys().cloned().collect()
}

/// Loads credential providers and starts one bounded SDK worker per exact
/// endpoint after all static capability matching has completed.
pub(super) fn load_s3_capabilities(
    endpoints: BTreeMap<StoreS3EndpointId, AuthoredS3Endpoint>,
) -> Result<LoadedS3Capabilities, CliError> {
    let mut graph = StoreGraphS3Clients::new();
    let mut strong = BTreeMap::new();
    for (id, endpoint) in endpoints {
        let provider = SecureFileCredentialProvider {
            path: endpoint.credential_path,
        };
        provider.load().map_err(|error| {
            campaign_store_error(format!("cannot load S3 endpoint credentials: {error}"))
        })?;
        let sdk_config = aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new(endpoint.region))
            .credentials_provider(provider)
            .endpoint_url(endpoint.endpoint_url)
            .force_path_style(endpoint.force_path_style)
            .build();
        let worker_config = AwsSdkS3ClientConfig::new(
            endpoint.maximum_queued_commands,
            endpoint.maximum_in_flight_operations,
            endpoint.maximum_retained_command_bytes,
            Duration::from_millis(endpoint.operation_timeout_ms),
        )
        .map_err(|error| campaign_store_error(format!("invalid S3 worker policy: {error}")))?;
        let ordinary = Arc::new(
            AwsSdkS3Client::start(
                id.clone(),
                aws_sdk_s3::Client::from_conf(sdk_config),
                worker_config,
            )
            .map_err(|error| campaign_store_error(format!("cannot start S3 worker: {error}")))?,
        );
        let administration = Arc::new(AwsSdkS3StrongCasClient::from_conformant_service(
            ordinary.clone(),
        ));
        graph
            .insert(id.clone(), ordinary)
            .map_err(|error| campaign_store_error(format!("invalid S3 capability: {error}")))?;
        graph
            .insert_administration(id.clone(), administration.clone())
            .map_err(|error| {
                campaign_store_error(format!("invalid S3 administration capability: {error}"))
            })?;
        strong.insert(id, administration);
    }
    Ok(LoadedS3Capabilities { graph, strong })
}

impl AuthoredS3Endpoint {
    fn validate_non_secret(&self) -> Result<(), CliError> {
        if !self.strong_cas_conformance {
            return Err(campaign_store_error(
                "S3 endpoint lacks the required strong-CAS conformance attestation",
            ));
        }
        if self.region.is_empty()
            || self.region.len() > MAX_S3_REGION_BYTES
            || !self
                .region
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(campaign_store_error("invalid S3 region"));
        }
        let endpoint = Url::parse(&self.endpoint_url)
            .map_err(|error| campaign_store_error(format!("invalid S3 endpoint URL: {error}")))?;
        if self.endpoint_url.len() > MAX_S3_ENDPOINT_URL_BYTES
            || endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "" | "/")
        {
            return Err(campaign_store_error(
                "S3 endpoint URL must be one bounded HTTPS origin without credentials, query, fragment, or path",
            ));
        }
        validate_absolute_normal_path(&self.credential_path, "S3 credential")?;
        AwsSdkS3ClientConfig::new(
            self.maximum_queued_commands,
            self.maximum_in_flight_operations,
            self.maximum_retained_command_bytes,
            Duration::from_millis(self.operation_timeout_ms),
        )
        .map_err(|error| campaign_store_error(format!("invalid S3 worker policy: {error}")))?;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredS3Credentials {
    schema: String,
    version: u32,
    access_key_id: String,
    secret_access_key: String,
    #[serde(default)]
    session_token: Option<String>,
    #[serde(default)]
    expires_at_unix_seconds: Option<u64>,
}

impl Drop for AuthoredS3Credentials {
    fn drop(&mut self) {
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
    }
}

#[derive(Debug)]
struct SecureFileCredentialProvider {
    path: PathBuf,
}

impl SecureFileCredentialProvider {
    fn load(&self) -> Result<Credentials, CliError> {
        let bytes = Zeroizing::new(read_secure_file(
            &self.path,
            MAX_S3_CREDENTIAL_FILE_BYTES,
            "campaign S3 credential",
        )?);
        let text = std::str::from_utf8(&bytes).map_err(|error| {
            campaign_store_error(format!("S3 credential is not UTF-8: {error}"))
        })?;
        let credentials: AuthoredS3Credentials =
            toml::from_str(text).map_err(|_| campaign_store_error("invalid S3 credential body"))?;
        credentials.build()
    }
}

impl ProvideCredentials for SecureFileCredentialProvider {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::new(async move {
            self.load().map_err(|error| {
                CredentialsError::provider_error(io::Error::other(error.to_string()))
            })
        })
    }
}

impl AuthoredS3Credentials {
    fn build(&self) -> Result<Credentials, CliError> {
        if self.schema != S3_CREDENTIAL_SCHEMA || self.version != S3_CREDENTIAL_VERSION {
            return Err(campaign_store_error(
                "unsupported S3 credential schema or version",
            ));
        }
        validate_secret_field(
            &self.access_key_id,
            MAX_S3_ACCESS_KEY_ID_BYTES,
            "access key ID",
        )?;
        validate_secret_field(
            &self.secret_access_key,
            MAX_S3_SECRET_ACCESS_KEY_BYTES,
            "secret access key",
        )?;
        if let Some(token) = self.session_token.as_deref() {
            validate_secret_field(token, MAX_S3_SESSION_TOKEN_BYTES, "session token")?;
        }
        let expiry = self
            .expires_at_unix_seconds
            .map(|seconds| {
                UNIX_EPOCH
                    .checked_add(Duration::from_secs(seconds))
                    .ok_or_else(|| campaign_store_error("S3 credential expiry is invalid"))
            })
            .transpose()?;
        if expiry.is_some_and(|expiry| expiry <= operational_wall_clock_now()) {
            return Err(campaign_store_error("S3 credential is expired"));
        }
        let mut builder = Credentials::builder()
            .access_key_id(self.access_key_id.clone())
            .secret_access_key(self.secret_access_key.clone())
            .provider_name("crucible-campaign-secure-file");
        if let Some(token) = self.session_token.clone() {
            builder = builder.session_token(token);
        }
        if let Some(expiry) = expiry {
            builder = builder.expiry(expiry);
        }
        Ok(builder.build())
    }
}

// Credential expiry is an operational deployment-admission decision. The
// observed wall clock never enters a campaign object, graph identity, or
// deterministic execution result.
// crucible-lint: allow clippy-disallowed-method -- host time rejects expired deployment credentials and never enters canonical state.
#[allow(clippy::disallowed_methods)]
fn operational_wall_clock_now() -> SystemTime {
    SystemTime::now()
}

fn validate_secret_field(value: &str, maximum: usize, role: &str) -> Result<(), CliError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(campaign_store_error(format!("invalid S3 {role}")));
    }
    Ok(())
}
