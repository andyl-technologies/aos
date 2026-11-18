//! Quote identity enrollment and the enrolled identity catalog.
//!
//! Enrollment pins the digests of a TPM's endorsement and attestation key
//! material in a JSON catalog, together with the enrollment method and the
//! digest of the evidence that justified it. Quote verification only accepts
//! attestation keys that appear in this catalog.

use super::*;

/// Enrolls a quote bundle identity in a verifier trust catalog.
///
/// The supplied evidence file is an operator- or privacy-CA-produced proof that
/// the AK/EK identity is acceptable for the fleet. AOS records its digest in
/// the catalog so later quote verification can distinguish enrolled identities
/// from simple identity pins.
///
/// # Errors
///
/// Returns an error if the quote identity files cannot be read, the enrollment
/// method is unsupported, the evidence file is not a regular file, the catalog
/// is malformed, or the label or identity is already enrolled.
pub(crate) fn enroll_quote_identity(
    quote_dir: &Path,
    catalog_path: &Path,
    label: &str,
    method: &str,
    evidence_file: &Path,
) -> Result<PackageQuoteEnrollmentResult> {
    let identity = quote_identity_digests(quote_dir)?;
    let method = validate_quote_enrollment_method(method)?.to_string();
    let anchor = PackageQuoteIdentityPin {
        label: Some(label.to_string()),
        identity: identity.clone(),
        enrollment: Some(PackageQuoteEnrollment {
            method: method.clone(),
            evidence_sha256: enrollment_evidence_digest(evidence_file)?,
        }),
    };
    validate_quote_identity_pin(&anchor)?;

    let mut catalog = read_or_create_quote_identity_catalog(catalog_path)?;
    for existing in &catalog.anchors {
        validate_quote_identity_pin(existing).with_context(|| {
            format!(
                "validating existing package quote identity pin from {}",
                catalog_path.display()
            )
        })?;
    }
    if catalog
        .anchors
        .iter()
        .any(|existing| existing.label.as_deref() == Some(label))
    {
        bail!("package quote identity catalog already contains label '{label}'");
    }
    if catalog
        .anchors
        .iter()
        .any(|existing| existing.identity == identity)
    {
        bail!("package quote identity catalog already contains this AK/EK identity");
    }

    let enrollment = anchor
        .enrollment
        .as_ref()
        .context("enrollment missing after construction")?;
    let result = PackageQuoteEnrollmentResult {
        label: label.to_string(),
        method,
        evidence_sha256: enrollment.evidence_sha256.clone(),
        identity,
    };
    catalog.anchors.push(anchor);
    write_quote_identity_catalog(catalog_path, &catalog)?;
    Ok(result)
}

pub(super) fn read_or_create_quote_identity_catalog(
    path: &Path,
) -> Result<PackageQuoteIdentityCatalog> {
    match fs::read_to_string(path) {
        Ok(content) => parse_quote_identity_catalog(path, &content),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(PackageQuoteIdentityCatalog {
            version: 1,
            anchors: Vec::new(),
        }),
        Err(err) => Err(err)
            .with_context(|| format!("reading package quote identity catalog {}", path.display())),
    }
}

pub(super) fn read_quote_identity_catalog(path: &Path) -> Result<PackageQuoteIdentityCatalog> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading package quote identity catalog {}", path.display()))?;
    let catalog = parse_quote_identity_catalog(path, &content)?;
    if catalog.anchors.is_empty() {
        bail!(
            "package quote identity catalog {} does not contain any anchors",
            path.display()
        );
    }
    Ok(catalog)
}

pub(super) fn parse_quote_identity_catalog(
    path: &Path,
    content: &str,
) -> Result<PackageQuoteIdentityCatalog> {
    let catalog: PackageQuoteIdentityCatalog = serde_json::from_str(content)
        .with_context(|| format!("parsing package quote identity catalog {}", path.display()))?;
    if catalog.version != 1 {
        bail!(
            "package quote identity catalog {} has unsupported version {}",
            path.display(),
            catalog.version
        );
    }
    Ok(catalog)
}

pub(super) fn write_quote_identity_catalog(
    path: &Path,
    catalog: &PackageQuoteIdentityCatalog,
) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let content = serde_json::to_string_pretty(catalog)
        .context("serializing package quote identity catalog")?;
    fs::write(path, format!("{content}\n"))
        .with_context(|| format!("writing package quote identity catalog {}", path.display()))
}

pub(super) fn validate_quote_identity_pin(anchor: &PackageQuoteIdentityPin) -> Result<()> {
    if let Some(label) = &anchor.label
        && (label.is_empty() || label.chars().any(char::is_control))
    {
        bail!("package quote identity pin label must be non-empty printable text");
    }
    if let Some(enrollment) = &anchor.enrollment {
        validate_quote_enrollment_method(&enrollment.method)?;
        parse_prefixed_sha256_hex(
            "quote enrollment evidence_sha256",
            &enrollment.evidence_sha256,
        )?;
    }
    validate_quote_identity_digests(&anchor.identity)
}

pub(super) fn validate_quote_enrollment_method(method: &str) -> Result<&'static str> {
    match method {
        "credential-activation" => Ok("credential-activation"),
        "privacy-ca" => Ok("privacy-ca"),
        "out-of-band" => Ok("out-of-band"),
        _ => bail!(
            "package quote enrollment method must be credential-activation, privacy-ca, or out-of-band"
        ),
    }
}

pub(super) fn enrollment_evidence_digest(path: &Path) -> Result<String> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("reading enrollment evidence metadata {}", path.display()))?;
    if !meta.file_type().is_file() {
        bail!(
            "enrollment evidence {} must be a regular file",
            path.display()
        );
    }
    file_sha256_digest(path)
}

pub(super) fn quote_identity_digests(dir: &Path) -> Result<PackageQuoteIdentityDigests> {
    Ok(PackageQuoteIdentityDigests {
        ek_public_sha256: file_sha256_digest(&dir.join("ek.pub"))?,
        ek_name_sha256: file_sha256_digest(&dir.join("ek.name"))?,
        ek_qualified_name_sha256: file_sha256_digest(&dir.join("ek.qname"))?,
        ak_public_sha256: file_sha256_digest(&dir.join("ak.pub"))?,
        ak_name_sha256: file_sha256_digest(&dir.join("ak.name"))?,
        ak_qualified_name_sha256: file_sha256_digest(&dir.join("ak.qname"))?,
    })
}

pub(super) fn file_sha256_digest(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(format!("sha256:{}", digest_hex(&bytes)))
}

pub(super) fn file_hex(path: &Path) -> Result<String> {
    fs::read(path)
        .with_context(|| format!("reading {}", path.display()))
        .map(hex::encode)
}

pub(super) fn validate_quote_identity_digests(
    identity: &PackageQuoteIdentityDigests,
) -> Result<()> {
    for (kind, digest) in [
        ("ek_public_sha256", &identity.ek_public_sha256),
        ("ek_name_sha256", &identity.ek_name_sha256),
        (
            "ek_qualified_name_sha256",
            &identity.ek_qualified_name_sha256,
        ),
        ("ak_public_sha256", &identity.ak_public_sha256),
        ("ak_name_sha256", &identity.ak_name_sha256),
        (
            "ak_qualified_name_sha256",
            &identity.ak_qualified_name_sha256,
        ),
    ] {
        parse_prefixed_sha256_hex(kind, digest)?;
    }
    Ok(())
}
