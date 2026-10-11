//! Explicit HTTPS operator target selection and owned credential-file custody.
//!
//! ```json
//! {"version":1,"endpoint":"https://storage.example","bucket":"private",
//!  "staging_prefix":"reviewed/.aos-direct-upload","credential_file":"keys.json",
//!  "private_policy_file":"policy.json","policy_review_file":"review.json",
//!  "policy_review_sha256":"<reviewed SHA-256>","tls_ca_file":null}
//! ```

use std::path::{Path, PathBuf};

use anyhow::{ensure, Result};
use aos_hub_core::{
    db::BindingRecord,
    direct_upload::{direct_private_stage_policy_commitment, DirectPrivateStagePolicyRef},
    s3surface::S3Surface,
};
use serde::Deserialize;
use zeroize::Zeroize as _;

use super::journal::{digest, read};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: u32,
    endpoint: String,
    bucket: String,
    staging_prefix: String,
    credential_file: PathBuf,
    private_policy_file: PathBuf,
    policy_review_file: PathBuf,
    policy_review_sha256: String,
    tls_ca_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    access_key: String,
    secret_key: String,
    region: String,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.access_key.zeroize();
        self.secret_key.zeroize();
        self.region.zeroize();
    }
}

pub(super) struct Loaded {
    pub endpoint: String,
    pub bucket: String,
    pub prefix: String,
    pub policy: DirectPrivateStagePolicyRef,
    pub policy_review_sha256: String,
    pub surface: S3Surface,
    pub http: reqwest::Client,
    secrets: Vec<zeroize::Zeroizing<String>>,
}

impl Loaded {
    pub fn receipt_secrets(&self) -> Vec<zeroize::Zeroizing<String>> {
        self.secrets
            .iter()
            .map(|secret| zeroize::Zeroizing::new(secret.to_string()))
            .collect()
    }

    pub fn public_receipt(&self, value: &str) -> Result<()> {
        ensure!(
            !self
                .secrets
                .iter()
                .any(|secret| value.contains(secret.as_str())),
            "provider receipt contains protected credential material"
        );
        Ok(())
    }
}

pub(super) fn load(path: &Path) -> Result<Loaded> {
    let config: Config = serde_json::from_slice(&read(path, 64 * 1024, false)?)
        .map_err(|_| anyhow::anyhow!("operator configuration is invalid"))?;
    let base = path.parent().unwrap_or(Path::new("."));
    let endpoint = url::Url::parse(&config.endpoint)
        .map_err(|_| anyhow::anyhow!("operator endpoint is invalid"))?;
    ensure!(
        config.version == 1
            && endpoint.scheme() == "https"
            && endpoint.host_str().is_some()
            && endpoint.path() == "/"
            && endpoint.query().is_none()
            && endpoint.fragment().is_none()
            && endpoint.username().is_empty()
            && endpoint.password().is_none(),
        "operator target must be an explicit HTTPS origin"
    );
    ensure!(
        (3..=63).contains(&config.bucket.len())
            && config
                .bucket
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'.'))
            && config.staging_prefix.len() <= 512
            && config.staging_prefix.split('/').last() == Some(".aos-direct-upload")
            && config
                .staging_prefix
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && !config
                .staging_prefix
                .chars()
                .any(|c| c.is_control() || matches!(c, '\\' | '?' | '#')),
        "operator target escapes its reviewed private staging scope"
    );
    let policy: DirectPrivateStagePolicyRef = serde_json::from_slice(&read(
        &base.join(&config.private_policy_file),
        64 * 1024,
        false,
    )?)
    .map_err(|_| anyhow::anyhow!("private policy reference is invalid"))?;
    ensure!(
        policy.policy_digest
            == direct_private_stage_policy_commitment(&policy.policy_id, &policy.namespace)?
            && digest(&read(
                &base.join(&config.policy_review_file),
                64 * 1024 * 1024,
                false
            )?) == config.policy_review_sha256,
        "independently selected private policy or review changed"
    );
    let credential_bytes =
        zeroize::Zeroizing::new(read(&base.join(&config.credential_file), 16 * 1024, true)?);
    let credentials: Credentials = serde_json::from_slice(&credential_bytes)
        .map_err(|_| anyhow::anyhow!("owned credential file is invalid"))?;
    ensure!(
        credentials.access_key.len() >= 8
            && !credentials.access_key.contains(':')
            && credentials.secret_key.len() >= 8
            && !credentials.region.is_empty()
            && !credentials.region.contains(':'),
        "owned credential material is invalid"
    );
    let capability = zeroize::Zeroizing::new(format!(
        "{}:{}:{}",
        credentials.access_key, credentials.secret_key, credentials.region
    ));
    let binding = BindingRecord {
        name: "operator-provider-experiment".into(),
        kind: "s3".into(),
        endpoint_scheme: Some("https".into()),
        endpoint_host_kind: Some("dns".into()),
        endpoint_host_bytes: Some(
            endpoint
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("operator host absent"))?
                .as_bytes()
                .to_vec(),
        ),
        endpoint_port: endpoint.port().map(i64::from),
        object_bucket: Some(config.bucket.clone()),
        object_prefix: Some(config.staging_prefix.clone()),
        access_mode: Some("private".into()),
        ..BindingRecord::default()
    };
    let surface = S3Surface::from_binding(&binding, "", Some(&capability))?
        .ok_or_else(|| anyhow::anyhow!("operator S3 surface unavailable"))?;
    let mut http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(120));
    if let Some(ca) = &config.tls_ca_file {
        let certificate = reqwest::Certificate::from_pem(&read(&base.join(ca), 256 * 1024, false)?)
            .map_err(|_| anyhow::anyhow!("operator TLS CA is invalid"))?;
        http = http.add_root_certificate(certificate);
    }
    let loaded = Loaded {
        endpoint: endpoint.origin().ascii_serialization(),
        bucket: config.bucket,
        prefix: config.staging_prefix,
        policy,
        policy_review_sha256: config.policy_review_sha256,
        surface,
        http: http
            .build()
            .map_err(|_| anyhow::anyhow!("operator HTTPS client unavailable"))?,
        secrets: vec![
            zeroize::Zeroizing::new(credentials.access_key.clone()),
            zeroize::Zeroizing::new(credentials.secret_key.clone()),
        ],
    };
    for value in [
        &loaded.endpoint,
        &loaded.bucket,
        &loaded.prefix,
        &loaded.policy.policy_id,
        &loaded.policy.namespace,
    ] {
        loaded.public_receipt(value)?;
    }
    Ok(loaded)
}
