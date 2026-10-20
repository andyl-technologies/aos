//! Closed read selections, fixed routes, and bounded inherited input custody.

use std::{collections::BTreeSet, fs::File, io::Read};

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Operation {
    BucketHead,
    Cors,
    Lifecycle,
    Location,
    Versioning,
    Policy,
    Objects,
    Multipart,
    ObjectHead,
    R2Bucket,
    R2Cors,
    R2Lifecycle,
    TokenVerify,
    TokenDetails,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Selection {
    pub version: u32,
    pub provider: String,
    pub endpoint: String,
    pub bucket: String,
    pub prefix: String,
    pub object_keys: Vec<String>,
    pub operations: Vec<Operation>,
    pub account_id: Option<String>,
    pub token_id: Option<String>,
    pub token_kind: Option<String>,
    pub starts_at: u64,
    pub expires_at: u64,
    pub maximum_response_bytes: usize,
}

pub(super) fn safe_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 1024
        && key
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
}

fn identifier(value: &Option<String>) -> bool {
    value.as_ref().is_some_and(|value| {
        value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

impl Selection {
    pub fn validate(&self, now: u64) -> Result<()> {
        let endpoint = url::Url::parse(&self.endpoint)
            .map_err(|_| anyhow::anyhow!("readback endpoint is invalid"))?;
        ensure!(
            self.version == 1
                && matches!(self.provider.as_str(), "r2" | "s3")
                && endpoint.scheme() == "https"
                && endpoint.host_str().is_some()
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.path() == "/"
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && (3..=63).contains(&self.bucket.len())
                && self.bucket.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'.' | b'-'))
                && safe_key(&self.prefix)
                && self.starts_at <= now
                && now < self.expires_at
                && self.expires_at.saturating_sub(self.starts_at) <= 300
                && self.expires_at.saturating_sub(now) > 2
                && (1..=1024 * 1024).contains(&self.maximum_response_bytes)
                && !self.operations.is_empty()
                && self.operations.len() <= 14
                && self
                    .operations
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>()
                    .len()
                    == self.operations.len()
                && self.object_keys.len() <= 16
                && self.object_keys.iter().collect::<BTreeSet<_>>().len() == self.object_keys.len()
                && self
                    .object_keys
                    .iter()
                    .all(|key| safe_key(key) && key.starts_with(&format!("{}/", self.prefix))),
            "readback selection escapes its finite original scope"
        );
        for operation in &self.operations {
            if matches!(
                operation,
                Operation::R2Bucket
                    | Operation::R2Cors
                    | Operation::R2Lifecycle
                    | Operation::TokenVerify
                    | Operation::TokenDetails
            ) {
                ensure!(
                    self.provider == "r2" && identifier(&self.account_id),
                    "R2 API selection differs"
                );
            }
            if matches!(operation, Operation::TokenVerify | Operation::TokenDetails) {
                ensure!(
                    matches!(self.token_kind.as_deref(), Some("user" | "account")),
                    "token kind differs"
                );
            }
            if *operation == Operation::TokenDetails {
                ensure!(identifier(&self.token_id), "token details identity differs");
            }
            if *operation == Operation::ObjectHead {
                ensure!(
                    !self.object_keys.is_empty(),
                    "object HEAD selection is empty"
                );
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct S3Credentials {
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
}

impl Drop for S3Credentials {
    fn drop(&mut self) {
        self.access_key.zeroize();
        self.secret_key.zeroize();
        self.region.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Credentials {
    pub s3: Option<S3Credentials>,
    pub cloudflare_token: Option<String>,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        if let Some(token) = &mut self.cloudflare_token {
            token.zeroize();
        }
    }
}

impl Credentials {
    pub fn protected(&self, bytes: &[u8]) -> bool {
        let values = self
            .s3
            .iter()
            .flat_map(|item| [&item.access_key, &item.secret_key])
            .chain(self.cloudflare_token.iter());
        values.filter(|value| !value.is_empty()).any(|value| {
            bytes
                .windows(value.len())
                .any(|window| window == value.as_bytes())
        })
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(s3) = &self.s3 {
            ensure!(
                (8..=128).contains(&s3.access_key.len())
                    && s3.access_key.bytes().all(|b| b.is_ascii_alphanumeric())
                    && (8..=512).contains(&s3.secret_key.len())
                    && !s3.secret_key.chars().any(char::is_control)
                    && (1..=64).contains(&s3.region.len())
                    && s3
                        .region
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "S3 credential descriptor is invalid"
            );
        }
        if let Some(token) = &self.cloudflare_token {
            ensure!(
                (20..=512).contains(&token.len())
                    && token.bytes().all(|b| b.is_ascii_alphanumeric()
                        || matches!(b, b'-' | b'_' | b'.' | b'~' | b'+' | b'/' | b'=')),
                "Cloudflare credential descriptor is invalid"
            );
        }
        Ok(())
    }
}

pub(super) fn inherited(fd: u32, maximum: u64) -> Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::fs::MetadataExt;
    let mut file = File::open(format!("/proc/self/fd/{fd}"))
        .map_err(|_| anyhow::anyhow!("inherited private descriptor unavailable"))?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == rustix::process::geteuid().as_raw()
            && before.mode() & 0o077 == 0
            && before.nlink() == 1
            && before.len() <= maximum,
        "inherited input custody differs"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    ensure!(
        bytes.len() as u64 == before.len()
            && bytes.len() as u64 <= maximum
            && (
                before.dev(),
                before.ino(),
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec(),
                before.mode(),
                before.uid(),
                before.nlink()
            ) == (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
                after.mode(),
                after.uid(),
                after.nlink()
            ),
        "inherited input changed while consumed"
    );
    Ok(bytes)
}
