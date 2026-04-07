//! Per-domain credential store and authentication management.
//!
//! Supports multiple credential types (bearer tokens, basic auth, AWS SigV4,
//! SSH keys, FTP login) with domain pattern matching (exact and wildcard).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use anyhow::{Context, Result};

/// A credential for authenticating to a remote service.
#[derive(Debug, Clone)]
pub enum Credential {
    /// Bearer token (OAuth2, API key, etc.)
    Bearer {
        token: String,
        refresh: Option<RefreshConfig>,
    },
    /// HTTP Basic authentication.
    Basic { username: String, password: String },
    /// AWS Signature V4 (for S3-compatible services).
    AwsSigV4 {
        region: String,
        profile: Option<String>,
        endpoint: Option<String>,
    },
    /// SSH key authentication (for SFTP).
    SshKey {
        key_path: Option<PathBuf>,
        password: Option<String>,
        use_agent: bool,
    },
    /// SSH password authentication.
    SshPassword { username: String, password: String },
    /// FTP login credentials.
    FtpLogin { username: String, password: String },
    /// Arbitrary HTTP header.
    Header { name: String, value: String },
}

/// Configuration for token refresh (OAuth2 client_credentials flow).
#[derive(Debug, Clone)]
pub struct RefreshConfig {
    /// URL to exchange the provisioning token for an access token.
    pub token_url: String,
    /// The provisioning/refresh token.
    pub provisioning_token: String,
}

/// A per-domain credential store.
///
/// Credentials are matched by domain pattern:
/// - Exact match: `"cache.aos.dev"` matches only `cache.aos.dev`
/// - Wildcard: `"*.aos.dev"` matches `cache.aos.dev`, `api.aos.dev`, etc.
/// - Exact matches take priority over wildcard matches.
pub struct AuthStore {
    credentials: RwLock<HashMap<String, Credential>>,
}

impl std::fmt::Debug for AuthStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let creds = self.credentials.read().unwrap();
        f.debug_struct("AuthStore")
            .field("domains", &creds.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl AuthStore {
    /// Create an empty auth store.
    pub fn new() -> Self {
        Self {
            credentials: RwLock::new(HashMap::new()),
        }
    }

    /// Set credentials for a domain pattern.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// store.set("cache.aos.dev", Credential::Bearer { token: "...", refresh: None });
    /// store.set("*.s3.amazonaws.com", Credential::AwsSigV4 { region: "us-east-1", profile: None, endpoint: None });
    /// ```
    pub fn set(&self, domain_pattern: &str, credential: Credential) {
        let mut creds = self.credentials.write().unwrap();
        creds.insert(domain_pattern.to_string(), credential);
    }

    /// Remove credentials for a domain pattern.
    pub fn remove(&self, domain_pattern: &str) -> Option<Credential> {
        let mut creds = self.credentials.write().unwrap();
        creds.remove(domain_pattern)
    }

    /// Get credentials matching a URL's domain.
    ///
    /// Returns `None` if no matching credentials are found.
    /// Exact matches take priority over wildcard matches.
    pub fn get(&self, url: &str) -> Option<Credential> {
        let host = extract_host(url)?;
        let creds = self.credentials.read().unwrap();

        // 1. Try exact match first.
        if let Some(cred) = creds.get(&host) {
            return Some(cred.clone());
        }

        // 2. Try wildcard patterns.
        let mut best_match: Option<(&str, &Credential)> = None;

        for (pattern, cred) in creds.iter() {
            if pattern_matches(pattern, &host) {
                // Prefer more specific patterns (longer pattern = more specific).
                match best_match {
                    None => best_match = Some((pattern, cred)),
                    Some((existing, _)) => {
                        if pattern.len() > existing.len() {
                            best_match = Some((pattern, cred));
                        }
                    }
                }
            }
        }

        best_match.map(|(_, cred)| cred.clone())
    }

    /// Apply credentials to a reqwest request builder.
    ///
    /// This modifies the request in-place to add authentication headers
    /// based on the credential type.
    pub async fn apply(
        &self,
        url: &str,
        mut builder: reqwest::RequestBuilder,
    ) -> Result<reqwest::RequestBuilder> {
        let cred = match self.get(url) {
            Some(c) => c,
            None => return Ok(builder),
        };

        match cred {
            Credential::Bearer { ref token, .. } => {
                builder = builder.bearer_auth(token);
            }
            Credential::Basic {
                ref username,
                ref password,
            } => {
                builder = builder.basic_auth(username, Some(password));
            }
            Credential::Header {
                ref name,
                ref value,
            } => {
                builder = builder.header(name.as_str(), value.as_str());
            }
            // AWS SigV4, SSH, and FTP credentials are handled by their respective
            // protocol implementations, not by modifying HTTP requests.
            Credential::AwsSigV4 { .. }
            | Credential::SshKey { .. }
            | Credential::SshPassword { .. }
            | Credential::FtpLogin { .. } => {}
        }

        Ok(builder)
    }

    /// Refresh a bearer token using the refresh config, if available.
    ///
    /// Returns `true` if the token was refreshed, `false` if no refresh
    /// config was available.
    pub async fn refresh_token(
        &self,
        domain_pattern: &str,
        client: &reqwest::Client,
    ) -> Result<bool> {
        let refresh_config = {
            let creds = self.credentials.read().unwrap();
            match creds.get(domain_pattern) {
                Some(Credential::Bearer {
                    refresh: Some(ref rc),
                    ..
                }) => Some(rc.clone()),
                _ => None,
            }
        };

        let refresh = match refresh_config {
            Some(rc) => rc,
            None => return Ok(false),
        };

        let resp = client
            .post(&refresh.token_url)
            .bearer_auth(&refresh.provisioning_token)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("grant_type=client_credentials")
            .send()
            .await
            .context("token refresh request failed")?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("token refresh failed: {body}");
        }

        let body: serde_json::Value = resp.json().await.context("parsing token response")?;
        let new_token = body["access_token"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("no access_token in refresh response"))?
            .to_string();

        let mut creds = self.credentials.write().unwrap();
        if let Some(Credential::Bearer {
            ref mut token,
            ..
        }) = creds.get_mut(domain_pattern)
        {
            *token = new_token;
        }

        Ok(true)
    }
}

impl Default for AuthStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the host (domain) from a URL string.
fn extract_host(url: &str) -> Option<String> {
    // Handle s3:// URLs which url::Url treats the bucket as host.
    if let Ok(parsed) = url::Url::parse(url) {
        return parsed.host_str().map(|h| h.to_lowercase());
    }
    None
}

/// Check if a pattern matches a host.
///
/// Supports:
/// - Exact match: `"example.com"` matches `"example.com"`
/// - Wildcard prefix: `"*.example.com"` matches `"sub.example.com"` but not `"example.com"`
fn pattern_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Wildcard: host must end with the suffix and have at least one more component.
        if host == suffix {
            return false;
        }
        host.ends_with(suffix)
            && host.len() > suffix.len()
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host() {
        assert_eq!(
            extract_host("https://cache.aos.dev/path"),
            Some("cache.aos.dev".to_string())
        );
        assert_eq!(
            extract_host("s3://my-bucket/prefix"),
            Some("my-bucket".to_string())
        );
        assert_eq!(
            extract_host("ftp://ftp.example.com:21/dir"),
            Some("ftp.example.com".to_string())
        );
    }

    #[test]
    fn test_pattern_exact_match() {
        assert!(pattern_matches("example.com", "example.com"));
        assert!(!pattern_matches("example.com", "other.com"));
    }

    #[test]
    fn test_pattern_wildcard() {
        assert!(pattern_matches("*.example.com", "sub.example.com"));
        assert!(pattern_matches("*.example.com", "deep.sub.example.com"));
        assert!(!pattern_matches("*.example.com", "example.com"));
        assert!(!pattern_matches("*.example.com", "notexample.com"));
    }

    #[test]
    fn test_auth_store_exact_priority() {
        let store = AuthStore::new();
        store.set(
            "*.aos.dev",
            Credential::Bearer {
                token: "wildcard".to_string(),
                refresh: None,
            },
        );
        store.set(
            "cache.aos.dev",
            Credential::Bearer {
                token: "exact".to_string(),
                refresh: None,
            },
        );

        let cred = store.get("https://cache.aos.dev/path").unwrap();
        match cred {
            Credential::Bearer { token, .. } => assert_eq!(token, "exact"),
            _ => panic!("expected Bearer"),
        }
    }

    #[test]
    fn test_auth_store_wildcard_fallback() {
        let store = AuthStore::new();
        store.set(
            "*.aos.dev",
            Credential::Bearer {
                token: "wildcard".to_string(),
                refresh: None,
            },
        );

        let cred = store.get("https://api.aos.dev/v1/test").unwrap();
        match cred {
            Credential::Bearer { token, .. } => assert_eq!(token, "wildcard"),
            _ => panic!("expected Bearer"),
        }
    }

    #[test]
    fn test_auth_store_no_match() {
        let store = AuthStore::new();
        store.set(
            "cache.aos.dev",
            Credential::Bearer {
                token: "test".to_string(),
                refresh: None,
            },
        );

        assert!(store.get("https://other.example.com/path").is_none());
    }

    #[test]
    fn test_auth_store_remove() {
        let store = AuthStore::new();
        store.set(
            "cache.aos.dev",
            Credential::Bearer {
                token: "test".to_string(),
                refresh: None,
            },
        );
        assert!(store.get("https://cache.aos.dev/path").is_some());

        store.remove("cache.aos.dev");
        assert!(store.get("https://cache.aos.dev/path").is_none());
    }
}
