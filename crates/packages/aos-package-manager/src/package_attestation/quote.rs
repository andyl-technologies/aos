//! TPM quote production and quote bundle verification.
//!
//! A quote bundle contains a TPM quote over PCRs 7, 11, 12, and 15, the
//! attestation key material, and the package event log. Verification checks
//! the quote signature, compares the quoted PCR 15 with the replayed event
//! log, and matches the attestation key against an enrolled identity.

use super::*;

/// Produces a TPM quote over the AOS package-attestation PCR set.
///
/// The quote covers PCRs 7, 11, 12, and 15 in the SHA-256 bank and writes the
/// EK public/name, AK public/name, quote message, quote signature, and quoted
/// PCR payload into `output_dir`.
///
/// # Errors
///
/// Returns an error if the nonce is not hex, the wrapper did not provide
/// trusted AOS-built tpm2-tools paths, the output directory cannot be written,
/// or any TPM command fails.
pub(crate) fn produce_package_quote(
    nonce_hex: &str,
    output_dir: &Path,
) -> Result<PackageQuoteArtifacts> {
    let nonce = parse_quote_nonce_hex(nonce_hex)?;
    create_private_quote_output_dir(output_dir)?;

    let createek = trusted_tpm2_tool_path(TPM2_CREATEEK_ENV, "tpm2_createek")?;
    let createak = trusted_tpm2_tool_path(TPM2_CREATEAK_ENV, "tpm2_createak")?;
    let readpublic = trusted_tpm2_tool_path(TPM2_READPUBLIC_ENV, "tpm2_readpublic")?;
    let quote = trusted_tpm2_tool_path(TPM2_QUOTE_ENV, "tpm2_quote")?;
    let flushcontext = trusted_tpm2_tool_path(TPM2_FLUSHCONTEXT_ENV, "tpm2_flushcontext")?;
    let tcti = tpm2_tcti()?;

    let work_dir = unique_quote_work_dir(output_dir)?;
    let ek_ctx = work_dir.join("ek.ctx");
    let ak_ctx = work_dir.join("ak.ctx");

    let ek_public = output_dir.join("ek.pub");
    let ek_name = output_dir.join("ek.name");
    let ek_qualified_name = output_dir.join("ek.qname");
    let ak_public = output_dir.join("ak.pub");
    let ak_name = output_dir.join("ak.name");
    let ak_qualified_name = output_dir.join("ak.qname");
    let quote_message = output_dir.join("quote.msg");
    let quote_signature = output_dir.join("quote.sig");
    let quote_pcrs = output_dir.join("quote.pcrs");

    let result = (|| -> Result<()> {
        run_tpm2_tool(
            &createek,
            &[
                os_arg("-c"),
                os_arg(&ek_ctx),
                os_arg("-G"),
                os_arg("rsa"),
                os_arg("-u"),
                os_arg(&ek_public),
            ],
            tcti.as_deref(),
        )
        .context("creating TPM endorsement key")?;
        run_tpm2_tool(
            &readpublic,
            &[
                os_arg("-c"),
                os_arg(&ek_ctx),
                os_arg("-o"),
                os_arg(&ek_public),
                os_arg("-n"),
                os_arg(&ek_name),
                os_arg("-q"),
                os_arg(&ek_qualified_name),
            ],
            tcti.as_deref(),
        )
        .context("recording endorsement-key public identity")?;
        run_tpm2_tool(
            &createak,
            &[
                os_arg("-C"),
                os_arg(&ek_ctx),
                os_arg("-c"),
                os_arg(&ak_ctx),
                os_arg("-G"),
                os_arg("rsa"),
                os_arg("-g"),
                os_arg("sha256"),
                os_arg("-s"),
                os_arg("rsassa"),
                os_arg("-u"),
                os_arg(&ak_public),
                os_arg("-n"),
                os_arg(&ak_name),
                os_arg("-q"),
                os_arg(&ak_qualified_name),
            ],
            tcti.as_deref(),
        )
        .context("creating TPM attestation key below endorsement key")?;
        run_tpm2_tool(
            &quote,
            &[
                os_arg("-c"),
                os_arg(&ak_ctx),
                os_arg("-l"),
                os_arg(QUOTE_PCR_SELECTION),
                os_arg("-q"),
                os_arg(&nonce),
                os_arg("-m"),
                os_arg(&quote_message),
                os_arg("-s"),
                os_arg(&quote_signature),
                os_arg("-o"),
                os_arg(&quote_pcrs),
                os_arg("-F"),
                os_arg("values"),
                os_arg("-g"),
                os_arg("sha256"),
            ],
            tcti.as_deref(),
        )
        .context("producing TPM quote")?;
        Ok(())
    })();

    let flush_warnings = if result.is_ok() {
        flush_quote_contexts(&flushcontext, &ak_ctx, &ek_ctx, tcti.as_deref())
    } else {
        let _ = flush_quote_contexts(&flushcontext, &ak_ctx, &ek_ctx, tcti.as_deref());
        Vec::new()
    };

    match fs::remove_dir_all(&work_dir) {
        Ok(()) => {}
        Err(err) if result.is_err() => {
            let _ = err;
        }
        Err(err) => {
            return Err(err).with_context(|| format!("removing {}", work_dir.display()));
        }
    }

    result?;
    let quoted_pcr15 = quoted_pcr15_from_values_file(&quote_pcrs)?;
    let identity = quote_identity_digests(output_dir)?;

    Ok(PackageQuoteArtifacts {
        nonce,
        pcr_selection: QUOTE_PCR_SELECTION,
        ek_public: display_path(&ek_public),
        ek_name: display_path(&ek_name),
        ek_qualified_name: display_path(&ek_qualified_name),
        ak_public: display_path(&ak_public),
        ak_name: display_path(&ak_name),
        ak_qualified_name: display_path(&ak_qualified_name),
        quote_message: display_path(&quote_message),
        quote_signature: display_path(&quote_signature),
        quote_pcrs: display_path(&quote_pcrs),
        quoted_pcr15,
        identity,
        flush_warnings,
    })
}

/// Verifies a package attestation quote bundle and returns the quoted PCR 15.
///
/// This checks the quote signature, nonce, PCR selection, and event-log replay
/// input binding. When `trust_catalogs` is non-empty, this also requires the
/// bundle identity artifacts to match an explicit verifier-provided pin. This
/// does not replace AK certification or EK credential activation.
///
/// # Errors
///
/// Returns an error if the nonce is malformed, `tpm2_checkquote` is not
/// available through the trusted wrapper environment, quote verification fails,
/// the quote bundle's PCR values file cannot be parsed, or a requested identity
/// pin catalog does not match the quote bundle.
pub(crate) fn verify_attestation_quote_bundle(
    quote_dir: &Path,
    nonce_hex: &str,
    trust_catalogs: &[PathBuf],
) -> Result<PackageQuoteVerification> {
    let nonce = parse_quote_nonce_hex(nonce_hex)?;
    let checkquote = trusted_tpm2_tool_path(TPM2_CHECKQUOTE_ENV, "tpm2_checkquote")?;
    let snapshot_dir = private_quote_bundle_snapshot(quote_dir, !trust_catalogs.is_empty())?;
    let ak_public = snapshot_dir.join("ak.pub");
    let quote_message = snapshot_dir.join("quote.msg");
    let quote_signature = snapshot_dir.join("quote.sig");
    let quote_pcrs = snapshot_dir.join("quote.pcrs");

    let result = run_tpm2_tool(
        &checkquote,
        &[
            os_arg("-u"),
            os_arg(&ak_public),
            os_arg("-m"),
            os_arg(&quote_message),
            os_arg("-s"),
            os_arg(&quote_signature),
            os_arg("-f"),
            os_arg(&quote_pcrs),
            os_arg("-l"),
            os_arg(QUOTE_PCR_SELECTION),
            os_arg("-g"),
            os_arg("sha256"),
            os_arg("-q"),
            os_arg(&nonce),
        ],
        None,
    )
    .with_context(|| {
        format!(
            "verifying package attestation quote {}",
            quote_dir.display()
        )
    })
    .and_then(|()| {
        let quoted = quoted_pcrs_from_values_file(&quote_pcrs)?;
        let trust = verify_quote_bundle_trust(&snapshot_dir, trust_catalogs)?;
        Ok(PackageQuoteVerification {
            quoted_pcr7: quoted.pcr7,
            quoted_pcr11: quoted.pcr11,
            quoted_pcr12: quoted.pcr12,
            quoted_pcr15: quoted.pcr15,
            ak_ek_trusted: trust.as_ref().is_some_and(|anchor| anchor.ak_ek_trusted),
            identity_pinned: trust.is_some(),
            identity_label: trust.map(|anchor| anchor.label),
            bundle: PackageQuoteBundleBinding {
                ak_public: file_hex(&ak_public)?,
                quote_message: file_hex(&quote_message)?,
                quote_signature: file_hex(&quote_signature)?,
                quote_pcrs: file_hex(&quote_pcrs)?,
            },
        })
    });

    match fs::remove_dir_all(&snapshot_dir) {
        Ok(()) => {}
        Err(err) if result.is_err() => {
            let _ = err;
        }
        Err(err) => {
            return Err(err).with_context(|| format!("removing {}", snapshot_dir.display()));
        }
    }

    result
}

pub(super) fn read_current_pcr15() -> Result<String> {
    let pcrread = trusted_tpm2_tool_path(TPM2_PCRREAD_ENV, "tpm2_pcrread")?;
    let tcti = tpm2_tcti()?;
    let mut command = Command::new(&pcrread);
    command.arg(format!("{PCR_BANK}:{PCR_INDEX}"));
    if let Some(tcti) = tcti {
        command.env("TPM2TOOLS_TCTI", tcti);
    }
    let output = command
        .output()
        .with_context(|| format!("running {}", pcrread.display()))?;
    if !output.status.success() {
        bail!(
            "{} failed: {}\nstdout:\n{}\nstderr:\n{}",
            pcrread.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    parse_tpm2_pcrread_pcr15(&String::from_utf8_lossy(&output.stdout))
}

/// Reads the live SHA-256 PCR 11 value used by a generation quote.
///
/// # Errors
///
/// Returns an error when the trusted TPM reader cannot run or its output does
/// not contain a canonical PCR 11 value.
pub(crate) fn current_pcr11() -> Result<String> {
    current_pcr_value(11)
}

pub(super) fn current_pcr_value(index: u8) -> Result<String> {
    let pcrread = trusted_tpm2_tool_path(TPM2_PCRREAD_ENV, "tpm2_pcrread")?;
    let tcti = tpm2_tcti()?;
    let mut command = Command::new(&pcrread);
    command.arg(format!("{PCR_BANK}:{index}"));
    if let Some(tcti) = tcti {
        command.env("TPM2TOOLS_TCTI", tcti);
    }
    let output = command
        .output()
        .with_context(|| format!("running {}", pcrread.display()))?;
    if !output.status.success() {
        bail!(
            "{} failed: {}\nstdout:\n{}\nstderr:\n{}",
            pcrread.display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    parse_tpm2_pcrread_value(&String::from_utf8_lossy(&output.stdout), index)
}

pub(super) fn parse_tpm2_pcrread_pcr15(output: &str) -> Result<String> {
    parse_tpm2_pcrread_value(output, PCR_INDEX)
}

pub(super) fn parse_tpm2_pcrread_value(output: &str, index: u8) -> Result<String> {
    for line in output.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim() != index.to_string() {
            continue;
        }
        let value = value.trim().strip_prefix("0x").unwrap_or(value.trim());
        return Ok(format!(
            "sha256:{}",
            parse_sha256_hex(&format!("PCR {index} value"), value)?
        ));
    }
    bail!("tpm2_pcrread output did not contain PCR {index}");
}

pub(super) fn quoted_pcr15_from_values_file(path: &Path) -> Result<String> {
    Ok(quoted_pcrs_from_values_file(path)?.pcr15)
}

pub(super) struct PackageQuotedPcrs {
    pcr7: String,
    pcr11: String,
    pcr12: String,
    pcr15: String,
}

pub(super) fn quoted_pcrs_from_values_file(path: &Path) -> Result<PackageQuotedPcrs> {
    const SHA256_SIZE: usize = 32;
    const QUOTED_PCR_COUNT: usize = 4;

    let bytes =
        fs::read(path).with_context(|| format!("reading quoted PCR values {}", path.display()))?;
    let expected = SHA256_SIZE * QUOTED_PCR_COUNT;
    if bytes.len() != expected {
        bail!(
            "quoted PCR values file {} is {} bytes, expected {expected}",
            path.display(),
            bytes.len()
        );
    }
    let value = |index: usize| {
        let start = SHA256_SIZE * index;
        hex::encode(&bytes[start..start + SHA256_SIZE])
    };
    Ok(PackageQuotedPcrs {
        pcr7: value(0),
        pcr11: value(1),
        pcr12: value(2),
        pcr15: value(3),
    })
}

pub(super) fn verify_quote_bundle_trust(
    quote_dir: &Path,
    trust_catalogs: &[PathBuf],
) -> Result<Option<PackageQuoteTrustMatch>> {
    if trust_catalogs.is_empty() {
        return Ok(None);
    }

    let identity = quote_identity_digests(quote_dir)?;
    let mut anchors = Vec::new();
    for catalog_path in trust_catalogs {
        let catalog = read_quote_identity_catalog(catalog_path)?;
        for anchor in catalog.anchors {
            validate_quote_identity_pin(&anchor).with_context(|| {
                format!(
                    "validating package quote identity pin from {}",
                    catalog_path.display()
                )
            })?;
            anchors.push(anchor);
        }
    }

    let mut pinned_match = None;
    for anchor in anchors {
        if anchor.identity == identity {
            let label = anchor
                .label
                .unwrap_or_else(|| format!("ak:{}", identity.ak_public_sha256));
            if anchor.enrollment.is_some() {
                return Ok(Some(PackageQuoteTrustMatch {
                    label,
                    ak_ek_trusted: true,
                }));
            }
            pinned_match.get_or_insert(label);
        }
    }

    if let Some(label) = pinned_match {
        return Ok(Some(PackageQuoteTrustMatch {
            label,
            ak_ek_trusted: false,
        }));
    }

    bail!("package attestation quote identity did not match any pinned identity");
}

pub(super) fn flush_quote_contexts(
    flushcontext: &Path,
    ak_ctx: &Path,
    ek_ctx: &Path,
    tcti: Option<&str>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    for (label, context) in [("attestation-key", ak_ctx), ("endorsement-key", ek_ctx)] {
        if !context.exists() {
            continue;
        }
        if let Err(err) = run_tpm2_tool(flushcontext, &[os_arg(context)], tcti) {
            warnings.push(format!("flushing {label} TPM context: {err:#}"));
        }
    }
    warnings
}

pub(super) fn create_private_quote_output_dir(output_dir: &Path) -> Result<()> {
    if !output_dir.is_absolute() {
        bail!(
            "quote output directory must be an absolute path: {}",
            output_dir.display()
        );
    }
    match fs::symlink_metadata(output_dir) {
        Ok(_) => {
            bail!(
                "quote output directory must not already exist: {}",
                output_dir.display()
            );
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| {
                format!("checking quote output directory {}", output_dir.display())
            });
        }
    }

    let parent = output_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .with_context(|| {
            format!(
                "quote output directory has no parent: {}",
                output_dir.display()
            )
        })?;
    let parent_meta = fs::symlink_metadata(parent).with_context(|| {
        format!(
            "checking quote output directory parent {}",
            parent.display()
        )
    })?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        bail!(
            "quote output directory parent must be a real directory: {}",
            parent.display()
        );
    }

    DirBuilder::new()
        .mode(0o700)
        .create(output_dir)
        .with_context(|| {
            format!(
                "creating private quote output directory {}",
                output_dir.display()
            )
        })?;
    fs::set_permissions(output_dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("securing quote output directory {}", output_dir.display()))?;
    let metadata = fs::symlink_metadata(output_dir).with_context(|| {
        format!(
            "checking private quote output directory {}",
            output_dir.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "quote output directory must be a real directory: {}",
            output_dir.display()
        );
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        bail!(
            "quote output directory must have mode 0700: {}",
            output_dir.display()
        );
    }
    Ok(())
}

pub(super) fn parse_quote_nonce_hex(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        bail!("quote nonce must not be empty");
    }
    if value.len() % 2 != 0 {
        bail!("quote nonce must be an even-length hex string");
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("quote nonce must contain only hex characters");
    }
    Ok(value.to_ascii_lowercase())
}

pub(super) fn private_quote_bundle_snapshot(
    quote_dir: &Path,
    include_identity: bool,
) -> Result<PathBuf> {
    let snapshot_dir = unique_temp_dir("aos-attest-verify")?;
    let mut members = vec!["ak.pub", "quote.msg", "quote.sig", "quote.pcrs"];
    if include_identity {
        members.extend(["ek.pub", "ek.name", "ek.qname", "ak.name", "ak.qname"]);
    }
    for name in members {
        let source = quote_dir.join(name);
        let target = snapshot_dir.join(name);
        fs::copy(&source, &target)
            .with_context(|| format!("copying quote bundle member {}", source.display()))?;
    }
    Ok(snapshot_dir)
}

pub(super) fn unique_quote_work_dir(parent: &Path) -> Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    unique_dir_under(
        parent,
        &format!(".aos-attest-quote-{}", std::process::id()),
        nanos,
    )
}
