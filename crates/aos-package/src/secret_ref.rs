//! The opaque `secretRef` type and its activation resolution contract
//! without embedding secret material in the evaluated manifest.
//!
//! Configuration evaluation does **not** resolve secrets; it fixes the boundary so secret material
//! never enters the value graph and a future secret-management system slots in
//! without reshaping the manifest. The one invariant: *secret material must
//! never appear in any value the evaluator produces.* The manifest is
//! content-addressed into the world-readable `/nix/store`, GC-rooted, and
//! reproducible; plaintext there would be world-readable, deterministically
//! hashed (the hash becomes an oracle), and unrotatable without changing the
//! manifest.
//!
//! # The type (build-spec §2.1)
//!
//! A [`SecretRef`] is a [`CredentialMeta`](crate::types::CredentialMeta) plus an
//! optional [`ResolverKind`] discriminator. Its only inhabitants are stable
//! identifiers:
//!
//! ```text
//! name      : str            # systemd credential id (the handle)
//! source    : str            # credstore PATH (never a value)
//! encrypted : bool           # at-rest sealed (default true)
//! units     : [str]          # units that consume it (restart targets)
//! ref       : ResolverKind?  # resolver discriminator (optional)
//! ciphertext: str?           # inline TPM2/PCR-sealed payload (inert at rest)
//! ```
//!
//! There is **no** `value=`/`text=` constructor — plaintext is structurally
//! unrepresentable. `#[serde(deny_unknown_fields)]` rejects one on deserialize.
//! TPM2/PCR-11-sealed `ciphertext` is permitted (inert without the host TPM in
//! the right measured state); the ban is on plaintext, not ciphertext.
//!
//! # Activation resolution contract (build-spec §2.3)
//!
//! Given a [`SecretRef`], **before the consuming unit starts**, the resolver
//! validates the handle/source, obtains the bytes via the [`ResolverKind`] arm,
//! optionally TPM2-encrypts them (PCR 11), writes them to the credstore path at
//! mode 0600, and marks dependent `units` for restart iff the bytes changed.
//! These steps are **exactly**
//! [`reconcile_desired_credentials`](crate::credential_artifact) for the
//! `desired-toml` resolver — the production reference implementation. This
//! module provides the type, the resolver dispatch, and a mockable
//! [`CredstoreSink`] seam so the contract is unit-testable off-host; the future
//! secret system adds a [`ResolverKind`] arm at step 4 without touching the
//! write/encrypt/restart steps.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::types::{CredentialMeta, validate_credential_name};

/// The resolver backend that supplies a [`SecretRef`]'s bytes (build-spec §2.1).
///
/// A closed-but-extensible discriminator: the first three arms are implemented
/// today; `vault`/`aws-sm` are reserved for the future secret system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolverKind {
    /// Vendored/build-time-sealed `encryptedFile` blob already in the credstore;
    /// resolution is a no-op materialization (bytes come from the image).
    Tpm2Credstore,
    /// `credential_artifact.rs::reconcile_desired_credentials`; bytes come from
    /// the `desired.toml [credentials]` reconciler.
    DesiredToml,
    /// Pass-through from `/run/credentials/@system/<name>` (platform-supplied).
    SystemCredential,
    /// Reserved for the future secret system (HashiCorp Vault). Deferred.
    Vault,
    /// Reserved for the future secret system (AWS Secrets Manager). Deferred.
    AwsSm,
}

/// An opaque reference to secret material the evaluator may produce
/// (build-spec §2.1).
///
/// Serialize-compatible with [`CredentialMeta`]: the credential-bearing fields
/// serialize identically, so the manifest schema is unchanged. The optional
/// `ref` is a resolver hint; when absent the resolver is inferred exactly as
/// `credential_artifact.rs` does today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    /// systemd credential id (the handle). Validated by
    /// [`validate_credential_name`].
    pub name: String,
    /// Credstore path the bytes are placed at — **never** a value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Inline TPM2/PCR-sealed payload (inert at rest). The **only** permitted
    /// payload field; plaintext has no representation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    /// Units that consume the credential (restart targets).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<String>,
    /// Whether the credential is TPM2/systemd encrypted at rest (default true at
    /// the module layer; serialized only when set, mirroring [`CredentialMeta`]).
    #[serde(default, skip_serializing_if = "is_false")]
    pub encrypted: bool,
    /// Optional resolver discriminator. Absent ⇒ inferred (build-spec §2.1).
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub resolver: Option<String>,
}

/// `skip_serializing_if` helper mirroring [`CredentialMeta`]'s.
fn is_false(value: &bool) -> bool {
    !*value
}

impl From<&CredentialMeta> for SecretRef {
    /// Lift an existing [`CredentialMeta`] into a [`SecretRef`] with no explicit
    /// resolver (the resolver is inferred from `source`/`ciphertext`).
    fn from(meta: &CredentialMeta) -> Self {
        Self {
            name: meta.name.clone(),
            source: meta.source.clone(),
            ciphertext: meta.ciphertext.clone(),
            units: meta.units.clone(),
            encrypted: meta.encrypted,
            resolver: None,
        }
    }
}

impl From<&SecretRef> for CredentialMeta {
    /// Project a [`SecretRef`] back to the manifest's [`CredentialMeta`],
    /// dropping the resolver hint. The credential-bearing bytes are identical,
    /// so the manifest schema is unchanged (build-spec §2.1).
    fn from(sr: &SecretRef) -> Self {
        Self {
            name: sr.name.clone(),
            source: sr.source.clone(),
            ciphertext: sr.ciphertext.clone(),
            units: sr.units.clone(),
            encrypted: sr.encrypted,
            optional: false,
        }
    }
}

impl SecretRef {
    /// Validates the stable resolver reference and all handle identifiers.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid credential name, a non-credstore
    /// destination, an unsupported resolver, or plaintext-style resolver data.
    pub fn validate_reference(&self) -> anyhow::Result<()> {
        validate_credential_name(&self.name)?;
        if let Some(source) = self.source.as_deref()
            && !is_credstore_source(source)
        {
            anyhow::bail!(
                "secretRef '{}' source must be beneath /etc, /run, or /usr credstore",
                self.name
            );
        }
        let _ = self.resolver_kind()?;
        Ok(())
    }

    /// The resolver this reference selects, applying the inference rule when no
    /// explicit `ref` is set (build-spec §2.1).
    ///
    /// Inference (matching `credential_artifact.rs`): inline `ciphertext` ⇒
    /// [`ResolverKind::Tpm2Credstore`] (image-sealed); a `source` under
    /// `/etc/credstore*` or `/run/credstore*` ⇒ [`ResolverKind::DesiredToml`];
    /// otherwise [`ResolverKind::SystemCredential`].
    pub fn resolver_kind(&self) -> anyhow::Result<ResolverKind> {
        if let Some(explicit) = self.resolver.as_deref() {
            let discriminator = explicit.split_once(':').map_or(explicit, |(kind, _)| kind);
            return match discriminator {
                "tpm2-credstore" => Ok(ResolverKind::Tpm2Credstore),
                "desired-toml" => Ok(ResolverKind::DesiredToml),
                "system-credential" => Ok(ResolverKind::SystemCredential),
                "vault" => Ok(ResolverKind::Vault),
                "aws-sm" => Ok(ResolverKind::AwsSm),
                other => anyhow::bail!("unsupported secretRef resolver {other:?}"),
            };
        }
        if self.ciphertext.is_some() {
            return Ok(ResolverKind::Tpm2Credstore);
        }
        match self.source.as_deref() {
            Some(source) if is_credstore_source(source) => Ok(ResolverKind::DesiredToml),
            _ => Ok(ResolverKind::SystemCredential),
        }
    }

    /// Returns the optional resolver-local handle after the discriminator.
    pub(crate) fn resolver_handle(&self) -> Option<&str> {
        self.resolver
            .as_deref()?
            .split_once(':')
            .map(|(_, handle)| handle)
    }
}

/// Whether `source` is a credstore path (`/etc/credstore*` or `/run/credstore*`).
fn is_credstore_source(source: &str) -> bool {
    source.starts_with("/etc/credstore")
        || source.starts_with("/run/credstore")
        || source.starts_with("/usr/lib/credstore")
}

/// The mockable activation seam: encrypt, write, and restart (build-spec §2.3
/// steps 4-8).
///
/// The production implementation is `credential_artifact.rs`
/// (`run_systemd_creds_encrypt` → `write_credential_source` →
/// `CredentialReconciliation::apply`); tests inject a recording mock so the
/// dispatch and the no-plaintext invariant are exercised off-host.
pub trait CredstoreSink {
    /// Step 4: obtain the plaintext bytes for `sr` via its resolver. For
    /// [`ResolverKind::Tpm2Credstore`] the bytes are already present and this is
    /// a no-op materialization (returns `Ok(None)`).
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot supply the bytes (missing system
    /// credential, unreachable backend).
    fn obtain(&self, sr: &SecretRef, kind: ResolverKind) -> anyhow::Result<Option<Vec<u8>>>;

    /// Step 5: TPM2/PCR-11-encrypt `plaintext` for credential `name`. Called
    /// only when `sr.encrypted` is set; **fails closed** when the PCR signing
    /// key is absent (never falling back to plaintext at rest).
    ///
    /// # Errors
    ///
    /// Returns an error when encryption cannot be performed.
    fn encrypt(&self, name: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// Step 6: write `bytes` to the credstore `source` at mode 0600 (atomic
    /// temp+rename). Returns whether the on-disk bytes changed.
    ///
    /// # Errors
    ///
    /// Returns an error on any write failure.
    fn write(&self, source: &str, bytes: &[u8]) -> anyhow::Result<bool>;

    /// Step 8: restart every unit in `units` (after all refs resolved).
    ///
    /// # Errors
    ///
    /// Returns an error when a unit fails to restart.
    fn restart(&self, units: &BTreeSet<String>) -> anyhow::Result<()>;
}

/// The outcome of resolving one [`SecretRef`] (build-spec §2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveOutcome {
    /// The resolver that supplied the bytes.
    pub kind: ResolverKind,
    /// Whether the on-disk credstore bytes changed.
    pub changed: bool,
    /// Units to restart because their credential changed.
    pub restart_units: BTreeSet<String>,
}

/// Resolve one [`SecretRef`] (build-spec §2.3 steps 1-7), without restarting.
///
/// Validates the handle and source (step 1-3, reusing
/// [`validate_credential_name`] and
/// `credential_artifact.rs::validate_provisionable_source`), obtains the bytes
/// by resolver arm (step 4), encrypts when `encrypted` (step 5), writes to the
/// credstore (step 6), and records dependent units for restart iff the bytes
/// changed (step 7). The actual restart (step 8) is deferred to
/// [`resolve_secret_refs`] so all refs are placed before any unit bounces.
///
/// `package` scopes the provisionable-source check (the owning package or
/// `"host.nix"` for operator credentials).
///
/// # Errors
///
/// Returns an error when the handle/source is invalid, the source is
/// non-provisionable (an immutable `/usr/lib/credstore*` path, the reserved
/// `/run/credstore.encrypted/aos/*` namespace, or an inline-`ciphertext`
/// override), the bytes cannot be obtained, or encryption/write fails.
/// Resolution is fail-closed: an error places nothing and restarts nothing.
pub fn resolve_secret_ref(
    package: &str,
    sr: &SecretRef,
    sink: &dyn CredstoreSink,
) -> anyhow::Result<ResolveOutcome> {
    // Step 1: validate the handle.
    validate_credential_name(&sr.name)?;

    // Step 2: require a credstore source.
    let source = sr.source.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "secretRef '{}' does not declare a credstore source",
            sr.name
        )
    })?;

    let kind = sr.resolver_kind()?;

    // Step 3: validate writable destinations. Image-sealed references already
    // live in the immutable/generated credstore and are intentionally a no-op.
    let meta = CredentialMeta::from(sr);
    if kind != ResolverKind::Tpm2Credstore {
        crate::credential_artifact::validate_provisionable_source(package, &meta, source)?;
    }

    // Step 4: obtain plaintext by resolver. tpm2-credstore is already present.
    let plaintext = sink.obtain(sr, kind)?;
    let mut restart_units = BTreeSet::new();
    let mut changed = false;
    if let Some(plaintext) = plaintext {
        // Step 5: encrypt when sealed at rest.
        let bytes = if sr.encrypted {
            sink.encrypt(&sr.name, &plaintext)?
        } else {
            plaintext
        };
        // Step 6: write to the credstore.
        changed = sink.write(source, &bytes)?;
        // Step 7: mark dependents for restart iff bytes changed.
        if changed {
            restart_units.extend(sr.units.iter().cloned());
        }
    }

    Ok(ResolveOutcome {
        kind,
        changed,
        restart_units,
    })
}

/// Resolve a batch of [`SecretRef`]s, then restart every affected unit once
/// (build-spec §2.3 step 8).
///
/// Each ref is placed via [`resolve_secret_ref`]; after **all** are resolved,
/// the union of dependent units is restarted exactly once. This is the order the
/// contract requires: bytes are at `source` before any consuming unit starts.
///
/// # Errors
///
/// Returns an error if any ref fails to resolve (fail-closed: nothing is
/// restarted) or if the final restart fails.
pub fn resolve_secret_refs(
    package: &str,
    refs: &[SecretRef],
    sink: &dyn CredstoreSink,
) -> anyhow::Result<BTreeSet<String>> {
    let mut all_restart = BTreeSet::new();
    for sr in refs {
        let outcome = resolve_secret_ref(package, sr, sink)?;
        all_restart.extend(outcome.restart_units);
    }
    if !all_restart.is_empty() {
        sink.restart(&all_restart)?;
    }
    Ok(all_restart)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A recording mock credstore: scripted plaintext, records writes/restarts.
    struct MockSink {
        plaintext: Option<Vec<u8>>,
        encrypt_available: bool,
        writes: RefCell<Vec<(String, Vec<u8>)>>,
        restarts: RefCell<Vec<BTreeSet<String>>>,
    }

    impl MockSink {
        fn new(plaintext: Option<&[u8]>) -> Self {
            Self {
                plaintext: plaintext.map(<[u8]>::to_vec),
                encrypt_available: true,
                writes: RefCell::new(Vec::new()),
                restarts: RefCell::new(Vec::new()),
            }
        }
    }

    impl CredstoreSink for MockSink {
        fn obtain(&self, _sr: &SecretRef, kind: ResolverKind) -> anyhow::Result<Option<Vec<u8>>> {
            match kind {
                // Image-sealed: bytes already present, no-op materialization.
                ResolverKind::Tpm2Credstore => Ok(None),
                _ => Ok(self.plaintext.clone()),
            }
        }

        fn encrypt(&self, _name: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
            if !self.encrypt_available {
                anyhow::bail!("PCR signing key absent; refusing plaintext at rest");
            }
            let mut sealed = b"SEALED:".to_vec();
            sealed.extend_from_slice(plaintext);
            Ok(sealed)
        }

        fn write(&self, source: &str, bytes: &[u8]) -> anyhow::Result<bool> {
            self.writes
                .borrow_mut()
                .push((source.to_string(), bytes.to_vec()));
            Ok(true)
        }

        fn restart(&self, units: &BTreeSet<String>) -> anyhow::Result<()> {
            self.restarts.borrow_mut().push(units.clone());
            Ok(())
        }
    }

    fn secret(name: &str, source: Option<&str>) -> SecretRef {
        SecretRef {
            name: name.to_string(),
            source: source.map(str::to_string),
            ciphertext: None,
            units: vec!["web.service".to_string()],
            encrypted: true,
            resolver: None,
        }
    }

    #[test]
    fn serde_round_trip_with_ref() {
        let sr = SecretRef {
            resolver: Some("desired-toml".to_string()),
            ..secret(
                "join-token",
                Some("/etc/credstore.encrypted/web/join-token"),
            )
        };
        let json = serde_json::to_string(&sr).unwrap();
        assert!(json.contains("\"ref\":\"desired-toml\""), "got {json}");
        let back: SecretRef = serde_json::from_str(&json).unwrap();
        assert_eq!(sr, back);
    }

    #[test]
    fn no_plaintext_field_is_representable() {
        // The no-plaintext invariant is type-level: a `value`/`text` key is an
        // unknown field and deny_unknown_fields rejects it on deserialize.
        let with_value = r#"{"name":"t","source":"/etc/credstore/t","value":"hunter2"}"#;
        assert!(serde_json::from_str::<SecretRef>(with_value).is_err());
        let with_text = r#"{"name":"t","text":"hunter2"}"#;
        assert!(serde_json::from_str::<SecretRef>(with_text).is_err());
    }

    #[test]
    fn manifest_projection_drops_only_the_resolver_hint() {
        let sr = SecretRef {
            resolver: Some("desired-toml".to_string()),
            ..secret(
                "join-token",
                Some("/etc/credstore.encrypted/web/join-token"),
            )
        };
        let meta = CredentialMeta::from(&sr);
        // The credential-bearing fields round-trip identically (no schema change).
        assert_eq!(meta.name, sr.name);
        assert_eq!(meta.source, sr.source);
        assert_eq!(meta.units, sr.units);
        assert_eq!(meta.encrypted, sr.encrypted);
        // And the lifted SecretRef has no resolver (inferred).
        let lifted = SecretRef::from(&meta);
        assert_eq!(lifted.resolver, None);
    }

    #[test]
    fn resolver_inference_matches_credential_artifact() {
        // inline ciphertext ⇒ image-sealed.
        let mut sr = secret("t", None);
        sr.ciphertext = Some("c".to_string());
        assert_eq!(sr.resolver_kind().unwrap(), ResolverKind::Tpm2Credstore);

        // /etc/credstore source ⇒ desired-toml.
        let sr = secret("t", Some("/etc/credstore.encrypted/web/t"));
        assert_eq!(sr.resolver_kind().unwrap(), ResolverKind::DesiredToml);

        // other source ⇒ system-credential.
        let sr = secret("t", Some("/var/lib/web/t"));
        assert_eq!(sr.resolver_kind().unwrap(), ResolverKind::SystemCredential);

        // explicit ref overrides inference.
        let sr = SecretRef {
            resolver: Some("system-credential".to_string()),
            ..secret("t", Some("/etc/credstore.encrypted/web/t"))
        };
        assert_eq!(sr.resolver_kind().unwrap(), ResolverKind::SystemCredential);
    }

    #[test]
    fn resolve_encrypts_writes_and_marks_restart() {
        let sink = MockSink::new(Some(b"raw-token"));
        let sr = secret(
            "join-token",
            Some("/etc/credstore.encrypted/web/join-token"),
        );
        let outcome = resolve_secret_ref("web", &sr, &sink).expect("resolve");

        assert_eq!(outcome.kind, ResolverKind::DesiredToml);
        assert!(outcome.changed);
        assert!(outcome.restart_units.contains("web.service"));
        // The bytes written are the SEALED form, never the plaintext.
        let writes = sink.writes.borrow();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].1, b"SEALED:raw-token");
    }

    #[test]
    fn tpm2_credstore_is_a_noop_materialization() {
        let sink = MockSink::new(None);
        let mut sr = secret("blob", Some("/etc/credstore.encrypted/web/blob"));
        sr.resolver = Some("tpm2-credstore".to_string());
        let outcome = resolve_secret_ref("web", &sr, &sink).expect("resolve");
        assert_eq!(outcome.kind, ResolverKind::Tpm2Credstore);
        assert!(!outcome.changed);
        assert!(sink.writes.borrow().is_empty());
    }

    #[test]
    fn missing_source_fails_closed() {
        let sink = MockSink::new(Some(b"x"));
        let sr = secret("t", None);
        let err = resolve_secret_ref("web", &sr, &sink).unwrap_err();
        assert!(format!("{err}").contains("does not declare a credstore source"));
    }

    #[test]
    fn non_provisionable_source_is_rejected() {
        let sink = MockSink::new(Some(b"x"));
        let sr = secret("t", Some("/usr/lib/credstore.encrypted/t"));
        assert!(resolve_secret_ref("web", &sr, &sink).is_err());
    }

    #[test]
    fn batch_restarts_once_after_all_resolved() {
        let sink = MockSink::new(Some(b"x"));
        let refs = vec![
            secret("a", Some("/etc/credstore.encrypted/web/a")),
            SecretRef {
                units: vec!["db.service".to_string()],
                ..secret("b", Some("/etc/credstore.encrypted/web/b"))
            },
        ];
        let restarted = resolve_secret_refs("web", &refs, &sink).expect("resolve all");
        assert!(restarted.contains("web.service"));
        assert!(restarted.contains("db.service"));
        // Exactly one restart call, with the union of units.
        assert_eq!(sink.restarts.borrow().len(), 1);
    }

    #[test]
    fn encryption_failure_is_fail_closed() {
        let mut sink = MockSink::new(Some(b"x"));
        sink.encrypt_available = false;
        let sr = secret("t", Some("/etc/credstore.encrypted/web/t"));
        // encrypted=true + no PCR key ⇒ error, nothing written.
        assert!(resolve_secret_ref("web", &sr, &sink).is_err());
        assert!(sink.writes.borrow().is_empty());
    }
}
