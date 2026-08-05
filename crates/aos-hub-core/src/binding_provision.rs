//! The single chokepoint for creating a storage binding.
//!
//! Both authoring surfaces — the console `POST .../bindings` handler and the
//! final `PlanCreateStorageBinding`/`CreateStorageBinding` lifecycle (and the
//! `aos hub` CLI) — funnel
//! into [`provision_binding`]. Centralizing it here means credential sealing,
//! input validation, and the `s3`/`r2` origin contract live in exactly one place,
//! so the WebUI, the Connect API, and the CLI cannot drift apart.
//!
//! # What it does
//!
//! - `local_fs`: validates the root is an absolute, traversal-free host path and
//!   stores it verbatim.
//! - `s3` / `r2`: validates the typed endpoint and object location. Long-lived
//!   secret material is never accepted here; immutable secret-manager version
//!   references are attached through the credential lifecycle API.
//!
//! Runtime capability gating (which kinds the *serving* process can actually
//! serve) is the caller's responsibility — see
//! [`RuntimeKind`](crate::binding::RuntimeKind); this module validates only that
//! the inputs form a coherent, persistable binding.

use crate::binding::BindingKind;
use crate::db::Database;
use thiserror::Error;

/// A request to create a storage binding.
pub struct NewBinding<'a> {
    /// Owning org id.
    pub org_id: i64,
    /// Binding name (unique within the org).
    pub name: &'a str,
    /// Backend kind.
    pub kind: BindingKind,
    /// Backend root: a host path for `local_fs`, or the bucket (optionally
    /// `bucket/sub-prefix`) for `s3`/`r2`.
    pub root: &'a str,
    /// Origin configuration for an object-store binding; `None` for `local_fs`.
    pub origin: Option<OriginInput<'a>>,
}

/// The endpoint and access mode for an `s3`/`r2` binding.
pub struct OriginInput<'a> {
    /// Endpoint origin URL, e.g. `https://<account>.r2.cloudflarestorage.com` or
    /// `https://s3.us-east-1.amazonaws.com`.
    pub endpoint: &'a str,
    /// Signing region (`auto` for R2, e.g. `us-east-1` for S3). Defaults to
    /// `auto` when empty.
    pub region: &'a str,
    /// Whether the binding is private (credentialed, read/write) or public
    /// (credential-less, read-only).
    pub private: bool,
}

/// Why [`provision_binding`] could not create a binding.
#[derive(Debug, Error)]
pub enum ProvisionError {
    /// The inputs were structurally invalid (empty field, bad path, missing
    /// endpoint/credentials). The message is safe to show a user.
    #[error("{0}")]
    Invalid(String),
    /// A binding named `{0}` already exists in the org.
    #[error("storage binding '{0}' already exists")]
    AlreadyExists(String),
    /// A database failure.
    #[error(transparent)]
    Backend(#[from] anyhow::Error),
}

/// Creates a storage binding and returns its row id.
///
/// See the [module docs](self) for the per-kind contract.
///
/// # Errors
///
/// Returns [`ProvisionError::Invalid`] for an empty name/root, a `local_fs` root
/// that is not an absolute traversal-free path, an `s3`/`r2` binding missing its
/// HTTPS endpoint;
/// [`ProvisionError::AlreadyExists`] when `(org, name)` is taken; and
/// [`ProvisionError::Backend`] on a sealing or database failure.
pub async fn provision_binding(db: &Database, req: NewBinding<'_>) -> Result<i64, ProvisionError> {
    let name = req.name.trim();
    let root = req.root.trim();
    if name.is_empty() {
        return Err(ProvisionError::Invalid("binding name is required".into()));
    }
    if root.is_empty() {
        return Err(ProvisionError::Invalid(
            "binding root (path or bucket) is required".into(),
        ));
    }

    let owner = db
        .org_by_id(req.org_id)
        .await?
        .ok_or_else(|| ProvisionError::Invalid("binding owner does not exist".into()))?;
    let stable_id = uuid::Uuid::new_v4().simple().to_string();
    let (
        local_root_path,
        object_bucket,
        object_prefix,
        endpoint_scheme,
        endpoint_host_kind,
        endpoint_host_bytes,
        endpoint_port,
        signing_region,
        access_mode,
    ) = match req.kind {
        BindingKind::LocalFs => {
            let path = std::path::Path::new(root);
            if !path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(ProvisionError::Invalid(
                    "local_fs root must be an absolute path with no '..' components".into(),
                ));
            }
            (
                Some(root.to_string()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
        }
        BindingKind::S3 | BindingKind::R2 => {
            let origin = req.origin.as_ref().ok_or_else(|| {
                ProvisionError::Invalid(format!(
                    "{} bindings require an endpoint",
                    req.kind.as_str()
                ))
            })?;
            let endpoint = origin.endpoint.trim();
            if endpoint.is_empty() {
                return Err(ProvisionError::Invalid(
                    "endpoint URL is required for s3/r2 bindings".into(),
                ));
            }
            if !endpoint.starts_with("https://") {
                return Err(ProvisionError::Invalid(
                    "endpoint must start with https://".into(),
                ));
            }
            let parsed = url::Url::parse(endpoint).map_err(|error| {
                ProvisionError::Invalid(format!("invalid endpoint URL: {error}"))
            })?;
            if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
                return Err(ProvisionError::Invalid(
                    "endpoint must be an origin without path, query, or fragment".into(),
                ));
            }
            let host = parsed
                .host_str()
                .ok_or_else(|| ProvisionError::Invalid("endpoint host is required".into()))?;
            let (host_kind, host_bytes) = match parsed.host() {
                Some(url::Host::Domain(_)) => ("dns", host.as_bytes().to_vec()),
                Some(url::Host::Ipv4(address)) => ("ipv4", address.octets().to_vec()),
                Some(url::Host::Ipv6(address)) => ("ipv6", address.octets().to_vec()),
                None => {
                    return Err(ProvisionError::Invalid("endpoint host is required".into()));
                }
            };
            let (bucket, prefix) = root.split_once('/').map_or((root, ""), |parts| parts);
            let region = if origin.region.trim().is_empty() {
                "auto"
            } else {
                origin.region.trim()
            };
            (
                None,
                Some(bucket.to_string()),
                Some(prefix.to_string()),
                Some(parsed.scheme().to_string()),
                Some(host_kind.to_string()),
                Some(host_bytes),
                parsed.port_or_known_default().map(i64::from),
                Some(region.to_string()),
                Some(if origin.private { "private" } else { "public" }.to_string()),
            )
        }
        BindingKind::DeploymentR2 => {
            return Err(ProvisionError::Invalid(
                "deployment_r2 bindings are provisioned only by the serving runtime".into(),
            ));
        }
    };

    // Fail fast with a clean message on a name clash rather than surfacing the
    // raw UNIQUE-constraint error.
    if db
        .storage_binding_by_name(req.org_id, name)
        .await?
        .is_some()
    {
        return Err(ProvisionError::AlreadyExists(name.to_string()));
    }

    let id = db
        .create_topology_storage_binding(
            Some(req.org_id),
            &stable_id,
            &owner.stable_id,
            name,
            req.kind.as_str(),
            local_root_path.as_deref(),
            object_bucket.as_deref(),
            object_prefix.as_deref(),
            endpoint_scheme.as_deref(),
            endpoint_host_kind.as_deref(),
            endpoint_host_bytes.as_deref(),
            endpoint_port,
            signing_region.as_deref(),
            access_mode.as_deref(),
        )
        .await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    async fn db_with_org() -> (Database, i64) {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        (db, org)
    }

    #[tokio::test]
    async fn local_fs_requires_absolute_traversal_free_path() {
        let (db, org) = db_with_org().await;
        let err = provision_binding(
            &db,
            NewBinding {
                org_id: org,
                name: "p",
                kind: BindingKind::LocalFs,
                root: "relative/../x",
                origin: None,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProvisionError::Invalid(_)));
    }

    #[tokio::test]
    async fn private_s3_records_origin_without_inline_credentials() {
        let (db, org) = db_with_org().await;
        let id = provision_binding(
            &db,
            NewBinding {
                org_id: org,
                name: "store",
                kind: BindingKind::R2,
                root: "my-bucket",
                origin: Some(OriginInput {
                    endpoint: "https://acct.r2.cloudflarestorage.com",
                    region: "auto",
                    private: true,
                }),
            },
        )
        .await
        .unwrap();
        let b = db.storage_binding(id).await.unwrap().unwrap();
        assert_eq!(b.kind, "r2");
        assert_eq!(b.access_mode.as_deref(), Some("private"));
        assert_eq!(b.endpoint_scheme.as_deref(), Some("https"));
        assert_eq!(
            b.endpoint_host_bytes.as_deref(),
            Some(&b"acct.r2.cloudflarestorage.com"[..])
        );
    }

    #[tokio::test]
    async fn object_store_rejects_non_https_endpoint() {
        let (db, org) = db_with_org().await;
        let err = provision_binding(
            &db,
            NewBinding {
                org_id: org,
                name: "store",
                kind: BindingKind::S3,
                root: "bucket",
                origin: Some(OriginInput {
                    endpoint: "http://s3.example.com",
                    region: "",
                    private: true,
                }),
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProvisionError::Invalid(_)));
    }

    #[tokio::test]
    async fn public_s3_stores_endpoint_without_credentials() {
        let (db, org) = db_with_org().await;
        let id = provision_binding(
            &db,
            NewBinding {
                org_id: org,
                name: "mirror",
                kind: BindingKind::S3,
                root: "bucket",
                origin: Some(OriginInput {
                    endpoint: "https://cdn.example.com",
                    region: "",
                    private: false,
                }),
            },
        )
        .await
        .unwrap();
        let b = db.storage_binding(id).await.unwrap().unwrap();
        assert_eq!(b.access_mode.as_deref(), Some("public"));
        assert_eq!(b.endpoint_scheme.as_deref(), Some("https"));
    }

    #[tokio::test]
    async fn duplicate_name_is_already_exists() {
        let (db, org) = db_with_org().await;
        let mk = || NewBinding {
            org_id: org,
            name: "dup",
            kind: BindingKind::LocalFs,
            root: "/srv/x",
            origin: None,
        };
        provision_binding(&db, mk()).await.unwrap();
        let err = provision_binding(&db, mk()).await.unwrap_err();
        assert!(matches!(err, ProvisionError::AlreadyExists(_)));
    }
}
