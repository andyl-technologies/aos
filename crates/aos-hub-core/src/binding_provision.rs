//! The single chokepoint for creating a storage binding.
//!
//! Both authoring surfaces — the console `POST .../bindings` handler and the
//! `StorageBindingService.CreateBinding` RPC (and through it the `aos hub` CLI) — funnel
//! into [`provision_binding`]. Centralizing it here means credential sealing,
//! input validation, and the `s3`/`r2` origin contract live in exactly one place,
//! so the WebUI, the Connect API, and the CLI cannot drift apart.
//!
//! # What it does
//!
//! - `local_fs`: validates the root is an absolute, traversal-free host path and
//!   stores it verbatim.
//! - `s3` / `r2`: validates the endpoint and (for a private binding) the
//!   credentials, **seals** `access_key:secret_key:region` through the
//!   [`SecretSealer`], and records the access mode + endpoint so the
//!   [`S3Surface`](crate::s3surface::S3Surface) can later mint presigned URLs.
//!
//! Runtime capability gating (which kinds the *serving* process can actually
//! serve) is the caller's responsibility — see
//! [`RuntimeKind`](crate::binding::RuntimeKind); this module validates only that
//! the inputs form a coherent, persistable binding.

use crate::auth::seal::SecretSealer;
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
    /// Origin + credentials for an object-store binding; `None` (and ignored) for
    /// `local_fs`.
    pub origin: Option<OriginInput<'a>>,
}

/// The endpoint and credentials for an `s3`/`r2` binding.
pub struct OriginInput<'a> {
    /// Endpoint origin URL, e.g. `https://<account>.r2.cloudflarestorage.com` or
    /// `https://s3.us-east-1.amazonaws.com`.
    pub endpoint: &'a str,
    /// Signing region (`auto` for R2, e.g. `us-east-1` for S3). Defaults to
    /// `auto` when empty.
    pub region: &'a str,
    /// Access key id (required when `private`).
    pub access_key_id: &'a str,
    /// Secret access key (required when `private`); sealed at rest, never stored
    /// or logged in the clear.
    pub secret_access_key: &'a str,
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
    /// A database or credential-sealing failure.
    #[error(transparent)]
    Backend(#[from] anyhow::Error),
}

/// Create a storage binding, sealing any credentials, and return its row id.
///
/// See the [module docs](self) for the per-kind contract.
///
/// # Errors
///
/// Returns [`ProvisionError::Invalid`] for an empty name/root, a `local_fs` root
/// that is not an absolute traversal-free path, an `s3`/`r2` binding missing its
/// endpoint, or a private binding missing its access key or secret;
/// [`ProvisionError::AlreadyExists`] when `(org, name)` is taken; and
/// [`ProvisionError::Backend`] on a sealing or database failure.
pub async fn provision_binding(
    db: &Database,
    sealer: &dyn SecretSealer,
    req: NewBinding<'_>,
) -> Result<i64, ProvisionError> {
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

    // Resolve access mode + sealed credential + endpoint per kind.
    let (access, endpoint, credential_ref) = match req.kind {
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
            ("public".to_string(), None, None)
        }
        BindingKind::S3 | BindingKind::R2 => {
            let origin = req.origin.as_ref().ok_or_else(|| {
                ProvisionError::Invalid(format!(
                    "{} bindings require an endpoint and credentials",
                    req.kind.as_str()
                ))
            })?;
            let endpoint = origin.endpoint.trim();
            if endpoint.is_empty() {
                return Err(ProvisionError::Invalid(
                    "endpoint URL is required for s3/r2 bindings".into(),
                ));
            }
            if !(endpoint.starts_with("https://") || endpoint.starts_with("http://")) {
                return Err(ProvisionError::Invalid(
                    "endpoint must start with https:// (or http:// for a local test endpoint)"
                        .into(),
                ));
            }
            if origin.private {
                let access_key = origin.access_key_id.trim();
                let secret_key = origin.secret_access_key.trim();
                if access_key.is_empty() || secret_key.is_empty() {
                    return Err(ProvisionError::Invalid(
                        "a private binding requires an access key id and secret access key".into(),
                    ));
                }
                let region = {
                    let r = origin.region.trim();
                    if r.is_empty() {
                        "auto"
                    } else {
                        r
                    }
                };
                // The sealed plaintext is access_key:secret_key:region; the
                // S3Surface splits on the first and last ':' so a secret may
                // itself contain ':'.
                let sealed = sealer
                    .seal(&format!("{access_key}:{secret_key}:{region}"))
                    .map_err(ProvisionError::Backend)?;
                (
                    "private".to_string(),
                    Some(endpoint.to_string()),
                    Some(sealed),
                )
            } else {
                ("public".to_string(), Some(endpoint.to_string()), None)
            }
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
        .create_storage_binding(req.org_id, name, req.kind.as_str(), root)
        .await?;
    if access != "public" || endpoint.is_some() || credential_ref.is_some() {
        db.set_storage_binding_access(id, &access, endpoint.as_deref(), credential_ref.as_deref())
            .await?;
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::seal::AesGcmSealer;
    use crate::db::Database;

    fn sealer() -> AesGcmSealer {
        AesGcmSealer::new(&[3u8; 32]).unwrap()
    }

    async fn db_with_org() -> (Database, i64) {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("acme", "Acme").await.unwrap();
        (db, org)
    }

    #[tokio::test]
    async fn local_fs_requires_absolute_traversal_free_path() {
        let (db, org) = db_with_org().await;
        let s = sealer();
        let err = provision_binding(
            &db,
            &s,
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
    async fn private_s3_seals_credentials_and_records_origin() {
        let (db, org) = db_with_org().await;
        let s = sealer();
        let id = provision_binding(
            &db,
            &s,
            NewBinding {
                org_id: org,
                name: "store",
                kind: BindingKind::R2,
                root: "my-bucket",
                origin: Some(OriginInput {
                    endpoint: "https://acct.r2.cloudflarestorage.com",
                    region: "auto",
                    access_key_id: "AKID",
                    secret_access_key: "shh",
                    private: true,
                }),
            },
        )
        .await
        .unwrap();
        let b = db.storage_binding(id).await.unwrap().unwrap();
        assert_eq!(b.kind, "r2");
        assert_eq!(b.access, "private");
        assert_eq!(
            b.endpoint.as_deref(),
            Some("https://acct.r2.cloudflarestorage.com")
        );
        // The credential is sealed at rest — the plaintext secret is absent — and
        // unseals to the access_key:secret:region triple.
        let cref = b.credential_ref.unwrap();
        assert!(!cref.contains("shh"));
        assert_eq!(s.unseal(&cref).unwrap(), "AKID:shh:auto");
    }

    #[tokio::test]
    async fn private_s3_without_keys_is_rejected() {
        let (db, org) = db_with_org().await;
        let s = sealer();
        let err = provision_binding(
            &db,
            &s,
            NewBinding {
                org_id: org,
                name: "store",
                kind: BindingKind::S3,
                root: "bucket",
                origin: Some(OriginInput {
                    endpoint: "https://s3.example.com",
                    region: "",
                    access_key_id: "",
                    secret_access_key: "",
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
        let s = sealer();
        let id = provision_binding(
            &db,
            &s,
            NewBinding {
                org_id: org,
                name: "mirror",
                kind: BindingKind::S3,
                root: "bucket",
                origin: Some(OriginInput {
                    endpoint: "https://cdn.example.com",
                    region: "",
                    access_key_id: "",
                    secret_access_key: "",
                    private: false,
                }),
            },
        )
        .await
        .unwrap();
        let b = db.storage_binding(id).await.unwrap().unwrap();
        assert_eq!(b.access, "public");
        assert_eq!(b.endpoint.as_deref(), Some("https://cdn.example.com"));
        assert!(b.credential_ref.is_none());
    }

    #[tokio::test]
    async fn duplicate_name_is_already_exists() {
        let (db, org) = db_with_org().await;
        let s = sealer();
        let mk = || NewBinding {
            org_id: org,
            name: "dup",
            kind: BindingKind::LocalFs,
            root: "/srv/x",
            origin: None,
        };
        provision_binding(&db, &s, mk()).await.unwrap();
        let err = provision_binding(&db, &s, mk()).await.unwrap_err();
        assert!(matches!(err, ProvisionError::AlreadyExists(_)));
    }
}
