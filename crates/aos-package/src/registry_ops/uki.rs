//! UKI binary inspection, Secure Boot certificate facts, and recovery bundle validation.

use crate::config::ApmConfig;
use crate::registry_ops::images::ProducerRecoveryInfo;
use crate::registry_ops::images::files::sha256_open_file;
use crate::types::{
    RecoveryBundleComponent, RecoveryBundleComponentId, RecoveryBundleManifest, RecoveryUkiEntry,
    SbatEntry, SysrootUkiEntry, UkiSlot,
};
use anyhow::{Context, Result, bail};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Secure Boot facts extracted from a signed UKI at publish time.
///
/// Every field is derived from the real binary so the registry catalog
/// cannot disagree with what was actually signed (RFC-0006 phase 4,
/// `registry-catalog.md`). A field is `None`/empty when the corresponding
/// fact could not be derived (e.g. `systemd-measure` unavailable).
#[derive(Debug, Default, Clone)]
pub(in crate::registry_ops) struct SbFacts {
    /// Lowercase hex SHA-256 of the signer leaf cert in the PE cert table.
    pub(in crate::registry_ops) signer_cert_sha256: Option<String>,
    /// SBAT component/generation pairs from the PE `.sbat` section.
    pub(in crate::registry_ops) sbat: Vec<SbatEntry>,
    /// `systemd-measure`-predicted PCR-11 over this UKI's measured sections at
    /// the `ready` boot phase (the stable value quoted during activation;
    /// see [`extract_expected_pcr11`]).
    pub(in crate::registry_ops) expected_pcr11: Option<String>,
    /// Deterministically identified per-slot facts for an A/B image payload.
    pub(in crate::registry_ops) ukis: Vec<SysrootUkiEntry>,
    /// Independently verified signed recovery copies for an A/B image payload.
    pub(in crate::registry_ops) recovery_ukis: Vec<RecoveryUkiEntry>,
    /// Complete catalog-authenticated offline recovery bundle manifest.
    pub(in crate::registry_ops) recovery_bundle: Option<RecoveryBundleManifest>,
}

/// Builds a Secure Boot helper command resolved only through the wrapper's
/// hermetic AOS runtime `PATH`.
///
/// `pkgs.aos` includes AOS-built `sbsigntools` and `systemd` in
/// that path. Internal verification must never consult `AOS_HOST_PATH`.
fn sb_tool_command(program: &str) -> Command {
    Command::new(program)
}

/// Hash the signer leaf certificate of a UKI's Authenticode signature.
///
/// Confirms the binary is signed with `sbverify --list <uki>`, then reads
/// the PE security directory directly to recover the Authenticode PKCS#7
/// blob and returns the lowercase hex SHA-256 of its first (leaf)
/// certificate. Returns `Ok(None)` when the binary carries no Authenticode
/// signature (an unsigned image), so unsigned dev builds do not break
/// publishing.
///
/// # Errors
///
/// Returns an error if `sbverify` cannot be spawned, exits with a failure
/// other than "no signature", or the PE/PKCS#7 structure cannot be parsed
/// into a leaf certificate.
fn extract_sb_signer_cert_sha256(uki: &Path) -> Result<Option<String>> {
    let output = sb_tool_command("sbverify")
        .arg("--list")
        .arg(uki)
        .output()
        .with_context(|| format!("running sbverify --list {}", uki.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        // sbverify reports an unsigned binary; treat that as "no facts"
        // rather than a publish failure.
        if stderr.contains("No signature")
            || stdout.contains("No signature")
            || stderr.contains("no signature")
        {
            return Ok(None);
        }
        bail!(
            "sbverify --list {} failed: {}",
            uki.display(),
            combine_output(&stdout, &stderr)
        );
    }

    let bytes = fs::read(uki).with_context(|| format!("reading {}", uki.display()))?;
    let leaf = leaf_cert_from_pe(&bytes)
        .with_context(|| format!("extracting signer cert from {}", uki.display()))?;
    Ok(leaf.map(sha256_hex))
}

/// Return the first (leaf) X.509 certificate DER bytes from a signed PE's
/// Authenticode certificate table.
///
/// Locates the PE security directory (the `WIN_CERTIFICATE` blob holding a
/// PKCS#7 `SignedData`), then walks the DER structure to the embedded
/// certificate set and returns the first certificate's complete DER
/// encoding.
///
/// # Errors
///
/// Returns an error when the PE headers, the security directory, or the
/// PKCS#7 certificate set cannot be parsed.
fn leaf_cert_from_pe(pe: &[u8]) -> Result<Option<&[u8]>> {
    let Some((cert_off, cert_len)) = pe_security_dir(pe)? else {
        return Ok(None);
    };
    let cert_table = pe
        .get(cert_off..cert_off + cert_len)
        .ok_or_else(|| anyhow::anyhow!("security directory extends past end of file"))?;
    // WIN_CERTIFICATE header: dwLength(4) + wRevision(2) + wCertificateType(2).
    let pkcs7 = cert_table
        .get(8..)
        .ok_or_else(|| anyhow::anyhow!("WIN_CERTIFICATE blob too short"))?;
    first_certificate_der(pkcs7).map(Some)
}

/// Parse the PE optional-header data directory entry for the
/// `IMAGE_DIRECTORY_ENTRY_SECURITY` (index 4) certificate table, returning
/// its `(file_offset, size)`.
///
/// # Errors
///
/// Returns an error when the DOS/PE signatures, the optional-header magic,
/// or the data directory cannot be read. An unsigned PE returns `None`.
fn pe_security_dir(pe: &[u8]) -> Result<Option<(usize, usize)>> {
    let read_u16 = |off: usize| -> Option<u16> {
        pe.get(off..off + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let read_u32 = |off: usize| -> Option<u32> {
        pe.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    if read_u16(0) != Some(0x5a4d) {
        bail!("not a PE image (missing MZ signature)");
    }
    let pe_off = read_u32(0x3c).context("reading e_lfanew")? as usize;
    if read_u32(pe_off) != Some(0x0000_4550) {
        bail!("missing PE signature");
    }
    let coff_off = pe_off
        .checked_add(4)
        .context("PE header offset overflowed")?;
    let optional_size = read_u16(coff_off + 16).context("reading optional-header size")? as usize;
    // COFF header is 20 bytes; the optional header follows.
    let opt_off = coff_off
        .checked_add(20)
        .context("optional-header offset overflowed")?;
    let opt_end = opt_off
        .checked_add(optional_size)
        .context("optional-header size overflowed")?;
    if opt_end > pe.len() {
        bail!("optional header extends past end of PE image");
    }
    let magic = read_u16(opt_off).context("reading optional-header magic")?;
    // The data directory array starts after the windows-specific fields:
    // 96 bytes for PE32 (0x10b), 112 bytes for PE32+ (0x20b).
    let (dir_off, count_off) = match magic {
        0x10b => (opt_off + 96, opt_off + 92),
        0x20b => (opt_off + 112, opt_off + 108),
        other => bail!("unexpected optional-header magic {other:#x}"),
    };
    if count_off.checked_add(4).is_none_or(|end| end > opt_end) {
        bail!("data-directory count is outside the declared optional header");
    }
    let directory_count =
        read_u32(count_off).context("reading optional-header data-directory count")?;
    if directory_count <= 4 {
        return Ok(None);
    }
    // Security directory is entry index 4 (8 bytes each: RVA/offset + size).
    let entry = dir_off + 4 * 8;
    if entry.checked_add(8).is_none_or(|end| end > opt_end) {
        bail!("security directory is outside the declared optional header");
    }
    let offset = read_u32(entry).context("reading security dir offset")? as usize;
    let size = read_u32(entry + 4).context("reading security dir size")? as usize;
    if offset == 0 && size == 0 {
        return Ok(None);
    }
    if offset == 0 || size == 0 {
        bail!("PE security directory has an incomplete certificate table");
    }
    Ok(Some((offset, size)))
}

/// Walk a PKCS#7 `SignedData` DER blob and return the *signer* certificate's
/// complete DER encoding from the `[0] IMPLICIT certificates` field.
///
/// The signer is identified by matching the first `SignerInfo`'s
/// `issuerAndSerialNumber` against each embedded certificate's issuer name
/// and serial number. This correctly picks the leaf even when the embedded
/// cert set is unordered or carries intermediate CA certs.
///
/// # Fallback caveat
///
/// If the `SignerInfo` cannot be located (for example a CMS variant that
/// uses `subjectKeyIdentifier` instead of `issuerAndSerialNumber`, which
/// Authenticode does not use in practice), this falls back to the first
/// certificate in the set. Authenticode signers produced by `sbsign`/`ukify`
/// embed a single end-entity certificate identified by issuer+serial, so the
/// matched path is the one exercised in production; the fallback exists only
/// so an unusual blob degrades to the previous behavior rather than failing.
///
/// # Errors
///
/// Returns an error when the DER structure does not match the expected
/// PKCS#7 `ContentInfo` → `SignedData` → certificates layout, or the
/// certificates field is absent.
fn first_certificate_der(pkcs7: &[u8]) -> Result<&[u8]> {
    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
    let content_info = der_expect_seq(pkcs7).context("PKCS#7 ContentInfo")?;
    let (_oid, rest) = der_take(content_info).context("ContentInfo.contentType")?;
    // content [0] EXPLICIT
    let (tag, explicit, _) = der_tlv(rest).context("ContentInfo.content")?;
    if tag != 0xA0 {
        bail!("PKCS#7 content is not context-tag [0]");
    }
    // SignedData ::= SEQUENCE { version, digestAlgorithms, contentInfo,
    //   certificates [0] IMPLICIT, ..., signerInfos SET }
    let signed_data = der_expect_seq(explicit).context("SignedData")?;

    let mut certificates: Option<&[u8]> = None;
    let mut signer_infos: Option<&[u8]> = None;
    let mut cursor = signed_data;
    while !cursor.is_empty() {
        let (tag, value, after) = der_tlv(cursor).context("scanning SignedData fields")?;
        match tag {
            // certificates [0] IMPLICIT SET OF Certificate.
            0xA0 => certificates = Some(value),
            // signerInfos SET OF SignerInfo (the final SET in SignedData).
            0x31 => signer_infos = Some(value),
            _ => {}
        }
        cursor = after;
    }

    let certificates = certificates
        .ok_or_else(|| anyhow::anyhow!("PKCS#7 SignedData has no certificates field"))?;

    // Try to pick the cert whose issuer+serial matches the first SignerInfo.
    if let Some(signer_infos) = signer_infos
        && let Some((issuer, serial)) = signer_issuer_and_serial(signer_infos)
        && let Some(cert) = certificate_matching(certificates, issuer, serial)?
    {
        return Ok(cert);
    }

    // Fallback: the first certificate in the set (see caveat).
    der_full_tlv(certificates).context("leaf certificate TLV")
}

/// Extract `(issuerName, serialNumber)` DER slices from the first
/// `SignerInfo`'s `issuerAndSerialNumber`, or `None` if not in that form.
///
/// `SignerInfo ::= SEQUENCE { version, sid IssuerAndSerialNumber, ... }` and
/// `IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }`.
fn signer_issuer_and_serial(signer_infos_set: &[u8]) -> Option<(&[u8], &[u8])> {
    // First SignerInfo in the SET.
    let (_tag, signer_info, _) = der_tlv(signer_infos_set).ok()?;
    if _tag != 0x30 {
        return None;
    }
    // version INTEGER, then sid IssuerAndSerialNumber SEQUENCE.
    let (vtag, _version, rest) = der_tlv(signer_info).ok()?;
    if vtag != 0x02 {
        return None;
    }
    let (stag, ias, _) = der_tlv(rest).ok()?;
    if stag != 0x30 {
        return None;
    }
    // issuer Name (full TLV), serialNumber INTEGER (full TLV).
    let issuer = der_full_tlv(ias).ok()?;
    let (_itag, _ivalue, after_issuer) = der_tlv(ias).ok()?;
    let serial = der_full_tlv(after_issuer).ok()?;
    Some((issuer, serial))
}

/// Find the certificate in `certificates_set` whose issuer Name and serial
/// number equal `issuer`/`serial`, returning its complete DER TLV.
///
/// `Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ... }, ... }` and
/// `TBSCertificate ::= SEQUENCE { [0] version?, serialNumber INTEGER,
/// signature, issuer Name, ... }`.
///
/// # Errors
///
/// Returns an error if a certificate element is malformed DER.
fn certificate_matching<'a>(
    certificates_set: &'a [u8],
    issuer: &[u8],
    serial: &[u8],
) -> Result<Option<&'a [u8]>> {
    let mut cursor = certificates_set;
    while !cursor.is_empty() {
        let cert = der_full_tlv(cursor).context("certificate TLV")?;
        if cert_issuer_and_serial(cert).is_some_and(|(ci, cs)| ci == issuer && cs == serial) {
            return Ok(Some(cert));
        }
        let consumed = cert.len();
        cursor = &cursor[consumed..];
    }
    Ok(None)
}

/// Extract `(issuerName, serialNumber)` DER slices from a `Certificate`.
fn cert_issuer_and_serial(cert: &[u8]) -> Option<(&[u8], &[u8])> {
    let tbs_outer = der_expect_seq(cert).ok()?; // Certificate value
    let tbs = der_expect_seq(tbs_outer).ok()?; // TBSCertificate value
    // Optional [0] EXPLICIT version, then serialNumber INTEGER.
    let (tag, _v, rest) = der_tlv(tbs).ok()?;
    let (serial, after_serial) = if tag == 0xA0 {
        let (stag, _sv, after) = der_tlv(rest).ok()?;
        if stag != 0x02 {
            return None;
        }
        (der_full_tlv(rest).ok()?, after)
    } else if tag == 0x02 {
        (der_full_tlv(tbs).ok()?, rest)
    } else {
        return None;
    };
    // signature AlgorithmIdentifier SEQUENCE, then issuer Name SEQUENCE.
    let (_sigtag, _sig, after_sig) = der_tlv(after_serial).ok()?;
    let issuer = der_full_tlv(after_sig).ok()?;
    Some((issuer, serial))
}

/// Split a DER TLV at `data`, returning `(tag, value, remaining)`.
fn der_tlv(data: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    if data.len() < 2 {
        bail!("truncated DER element");
    }
    let tag = data[0];
    let (len, header_len) = der_len(&data[1..])?;
    let start = 1 + header_len;
    let end = start
        .checked_add(len)
        .filter(|&e| e <= data.len())
        .ok_or_else(|| anyhow::anyhow!("DER length {len} exceeds buffer"))?;
    Ok((tag, &data[start..end], &data[end..]))
}

/// Like [`der_tlv`] but returns the *complete* leading TLV (tag + length +
/// value) of the first element in `data`.
fn der_full_tlv(data: &[u8]) -> Result<&[u8]> {
    let total = der_element_len(data)?;
    Ok(&data[..total])
}

/// Return the total byte length of the leading DER element in `data`.
fn der_element_len(data: &[u8]) -> Result<usize> {
    if data.len() < 2 {
        bail!("truncated DER element");
    }
    let (len, header_len) = der_len(&data[1..])?;
    Ok(1 + header_len + len)
}

/// Expect a DER SEQUENCE (`0x30`) at `data` and return its value bytes.
fn der_expect_seq(data: &[u8]) -> Result<&[u8]> {
    let (tag, value, _) = der_tlv(data)?;
    if tag != 0x30 {
        bail!("expected DER SEQUENCE, found tag {tag:#x}");
    }
    Ok(value)
}

/// Take the first DER element from `data`, returning `(element, remaining)`.
fn der_take(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let total = der_element_len(data)?;
    Ok((&data[..total], &data[total..]))
}

/// Decode a DER length field, returning `(length, header_byte_count)`.
fn der_len(data: &[u8]) -> Result<(usize, usize)> {
    let first = *data
        .first()
        .ok_or_else(|| anyhow::anyhow!("missing DER length"))?;
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || data.len() < 1 + n {
        bail!("unsupported DER length encoding");
    }
    let mut len = 0usize;
    for &byte in &data[1..1 + n] {
        len = (len << 8) | byte as usize;
    }
    Ok((len, 1 + n))
}

/// Return the lowercase hex SHA-256 of `bytes`.
pub(in crate::registry_ops) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Read the SBAT component/generation table from a UKI's `.sbat` PE section.
///
/// Reads the section from the PE section table and parses the CSV: each
/// non-empty, non-comment line is `component,generation`
/// (extra columns describing the upstream are ignored). Returns an empty
/// vector when the binary carries no `.sbat` section.
///
/// # Errors
///
/// Returns an error if the PE section table is malformed, the section is not
/// valid UTF-8, or a generation field is not a non-negative integer.
fn extract_sbat_entries(uki: &Path) -> Result<Vec<SbatEntry>> {
    let pe = fs::read(uki).with_context(|| format!("reading UKI {}", uki.display()))?;
    let Some(raw) = pe_section(&pe, ".sbat")? else {
        return Ok(Vec::new());
    };
    let text = std::str::from_utf8(raw).context("decoding .sbat section as UTF-8")?;
    parse_sbat_csv(text)
}

/// Parse the CSV body of a `.sbat` section into [`SbatEntry`] records.
///
/// # Errors
///
/// Returns an error if a data line's generation column is not a
/// non-negative integer.
fn parse_sbat_csv(text: &str) -> Result<Vec<SbatEntry>> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\0').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(',');
        let Some(component) = fields.next() else {
            continue;
        };
        let component = component.trim();
        // The first CSV row is the SBAT format header (`sbat,1,SBAT...`);
        // it is itself a versioned component and is recorded like any other.
        let Some(generation) = fields.next() else {
            continue;
        };
        let generation: u32 = generation.trim().parse().with_context(|| {
            format!("parsing SBAT generation for component '{component}' from '{line}'")
        })?;
        entries.push(SbatEntry {
            component: component.to_string(),
            generation,
        });
    }
    Ok(entries)
}

/// Returns a named PE section's exact on-disk bytes.
///
/// PE section names are fixed-width eight-byte fields. UKI section names fit
/// directly in that field, so string-table indirection is deliberately not
/// accepted. Empty sections are treated as absent.
///
/// # Errors
///
/// Returns an error if the PE/COFF headers, section table, or selected raw-data
/// range is malformed, or if the image contains duplicate selected sections.
pub(crate) fn pe_section<'a>(pe: &'a [u8], section: &str) -> Result<Option<&'a [u8]>> {
    if section.is_empty() || section.len() > 8 || !section.is_ascii() {
        bail!("PE section name must contain one to eight ASCII bytes");
    }
    let read_u16 = |off: usize| -> Option<u16> {
        pe.get(off..off + 2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
    };
    let read_u32 = |off: usize| -> Option<u32> {
        pe.get(off..off + 4)
            .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };

    if read_u16(0) != Some(0x5a4d) {
        bail!("not a PE image (missing MZ signature)");
    }
    let pe_off = read_u32(0x3c).context("reading e_lfanew")? as usize;
    if read_u32(pe_off) != Some(0x0000_4550) {
        bail!("missing PE signature");
    }
    let coff_off = pe_off
        .checked_add(4)
        .context("PE header offset overflowed")?;
    let section_count = read_u16(coff_off + 2).context("reading PE section count")? as usize;
    let optional_size = read_u16(coff_off + 16).context("reading optional-header size")? as usize;
    let section_table = coff_off
        .checked_add(20)
        .and_then(|offset| offset.checked_add(optional_size))
        .context("PE section-table offset overflowed")?;
    let section_table_end = section_count
        .checked_mul(40)
        .and_then(|size| section_table.checked_add(size))
        .context("PE section-table size overflowed")?;
    if section_table_end > pe.len() {
        bail!("PE section table extends past end of image");
    }

    let mut matched = false;
    let mut selected = None;
    for index in 0..section_count {
        let header = section_table + index * 40;
        let raw_name = &pe[header..header + 8];
        let name_len = raw_name.iter().position(|byte| *byte == 0).unwrap_or(8);
        if &raw_name[..name_len] != section.as_bytes() {
            continue;
        }
        if matched {
            bail!("PE image contains duplicate {section} sections");
        }
        matched = true;
        let virtual_size =
            read_u32(header + 8).context("reading PE section virtual size")? as usize;
        let raw_size = read_u32(header + 16).context("reading PE section size")? as usize;
        let raw_offset = read_u32(header + 20).context("reading PE section offset")? as usize;
        // systemd-stub measures only bytes materialized in the PE file. Its
        // loader and ukify both define that range as the smaller of the
        // section's virtual and raw sizes.
        let section_size = virtual_size.min(raw_size);
        if section_size == 0 {
            continue;
        }
        let raw_end = raw_offset
            .checked_add(section_size)
            .context("PE section range overflowed")?;
        selected = Some(
            pe.get(raw_offset..raw_end)
                .with_context(|| format!("PE {section} section extends past end of image"))?,
        );
    }
    Ok(selected)
}

/// Copies a selected PE section to a temporary file for `systemd-measure`.
fn dump_pe_section(pe: &[u8], section: &str) -> Result<Option<tempfile::NamedTempFile>> {
    let Some(bytes) = pe_section(pe, section)? else {
        return Ok(None);
    };
    let mut tmp = tempfile::Builder::new()
        .prefix("aos-uki-section-")
        .tempfile()
        .with_context(|| format!("creating temp file for {section} dump"))?;
    tmp.as_file_mut()
        .write_all(bytes)
        .with_context(|| format!("writing temporary {section} section"))?;
    Ok(Some(tmp))
}

/// Predict the TPM PCR-11 contribution of a UKI via `systemd-measure`.
///
/// Runs `systemd-measure calculate` over the assembled UKI and returns the
/// predicted PCR-11 value as lowercase hex. Returns `Ok(None)` when
/// `systemd-measure` is not available, so a publish never fails merely
/// because the measurement tool is missing.
///
/// # What is measured
///
/// `systemd-measure` must be fed the UKI's individual PE *sections* — the
/// same inputs sd-stub hashes into PCR 11 — not the whole UKI as a kernel
/// image. This dumps each section sd-stub measures (`.linux`, `.osrel`,
/// `.cmdline`, `.initrd`, `.ucode`, `.splash`, `.dtb`, `.uname`, `.sbat`,
/// `.pcrpkey`), skipping any that are absent, and passes the present ones
/// to `systemd-measure calculate --bank=sha256`. The result is the PCR 11
/// value sd-stub + `systemd-pcrextend` reach for the measured sections, which
/// is also the value `ukify` signs into the `.pcrsig` policy — so a machine
/// that boots this UKI and seals against the signed policy is sealing
/// against this digest.
///
/// `systemd-measure calculate` emits one `11:sha256=` line per boot phase
/// (`enter-initrd` → `enter-initrd:leave-initrd:sysinit:ready`); this records
/// the **last** — the stable `ready` phase at which configuration activation takes
/// its generation quote. `aos-eval.service` is explicitly ordered after
/// `systemd-pcrphase.service`, and later operator-driven switches necessarily
/// run in this same phase.
/// TPM-sealed `/var` unlock remains valid because systemd consumes
/// the signed multi-phase `.pcrsig` policy at `enter-initrd`; it does not use
/// this catalog scalar as its unlock policy.
///
/// # Errors
///
/// Returns an error if the UKI section table is malformed, `systemd-measure`
/// exits non-zero, or its output cannot be parsed into a PCR-11 digest.
pub(crate) fn extract_expected_pcr11(uki: &Path) -> Result<Option<String>> {
    // Section name -> systemd-measure flag, in sd-stub measurement order.
    // (systemd-measure applies its own canonical order internally, so the
    // flag order here is not significant.)
    const SECTIONS: &[(&str, &str)] = &[
        (".linux", "--linux"),
        (".osrel", "--osrel"),
        (".cmdline", "--cmdline"),
        (".initrd", "--initrd"),
        (".ucode", "--ucode"),
        (".splash", "--splash"),
        (".dtb", "--dtb"),
        (".uname", "--uname"),
        (".sbat", "--sbat"),
        (".pcrpkey", "--pcrpkey"),
    ];

    let mut cmd = sb_tool_command("systemd-measure");
    cmd.arg("calculate").arg("--bank=sha256");
    // Hold the section temp files alive until systemd-measure has run.
    let mut held = Vec::new();
    let mut any = false;
    let pe = fs::read(uki).with_context(|| format!("reading UKI {}", uki.display()))?;
    for (section, flag) in SECTIONS {
        if let Some(tmp) = dump_pe_section(&pe, section)? {
            cmd.arg(format!("{flag}={}", tmp.path().display()));
            held.push(tmp);
            any = true;
        }
    }
    // No measurable sections (e.g. not actually a UKI) — nothing to record.
    if !any {
        return Ok(None);
    }

    let output = match cmd.output() {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("running systemd-measure on {}", uki.display()));
        }
    };
    if !output.status.success() {
        bail!(
            "systemd-measure on {} failed: {}",
            uki.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_pcr11(&stdout))
}

/// Extract the PCR-11 digest from `systemd-measure calculate` output.
///
/// The tool prints lines such as `11:sha256=<hex>`; this returns the hex of
/// the last PCR-11/sha256 line (`ready`), or `None` when no line is present.
fn parse_pcr11(text: &str) -> Option<String> {
    let mut parsed = None;
    for line in text.lines() {
        let line = line.trim();
        // Accept `11:sha256=<hex>` and `11:<hex>` shapes.
        let Some(rest) = line.strip_prefix("11:") else {
            continue;
        };
        let value = rest.rsplit('=').next().unwrap_or(rest).trim();
        if !value.is_empty() && value.bytes().all(|b| b.is_ascii_hexdigit()) {
            parsed = Some(value.to_ascii_lowercase());
        }
    }
    parsed
}

/// Verify a UKI's embedded Authenticode signature against a db certificate.
///
/// Runs `sbverify --cert <db_cert_pem> <uki>`; the registry refuses to
/// catalog a component it cannot itself verify is signed by the declared
/// db cert (RFC-0006 phase 4).
///
/// # Errors
///
/// Returns an error if `sbverify` cannot be spawned or reports the
/// signature does not verify against `db_cert_pem`.
fn verify_uki_against_db_cert(uki: &Path, db_cert_pem: &Path) -> Result<()> {
    let output = sb_tool_command("sbverify")
        .arg("--cert")
        .arg(db_cert_pem)
        .arg(uki)
        .output()
        .with_context(|| format!("running sbverify --cert on {}", uki.display()))?;
    if !output.status.success() {
        bail!(
            "UKI {} does not verify against db cert {}: {}",
            uki.display(),
            db_cert_pem.display(),
            combine_output(
                &String::from_utf8_lossy(&output.stdout),
                &String::from_utf8_lossy(&output.stderr)
            )
        );
    }
    Ok(())
}

/// Join non-empty stdout/stderr fragments into one diagnostic string.
fn combine_output(stdout: &str, stderr: &str) -> String {
    match (stdout.trim().is_empty(), stderr.trim().is_empty()) {
        (true, true) => "(no output)".to_string(),
        (false, true) => stdout.trim().to_string(),
        (true, false) => stderr.trim().to_string(),
        (false, false) => format!("{}\n{}", stdout.trim(), stderr.trim()),
    }
}

/// Locate a db certificate PEM to verify published UKIs against, if one is
/// provisioned for `registry`.
///
/// Looks for `<registries-storage>/<registry>/sb-certs/db.pem` in the
/// authoring clone. Returns `None` when no db cert is provisioned, in which
/// case `apr publish` records SB facts without the publish-time signature
/// cross-check (the closure signature still covers the recorded facts).
pub(in crate::registry_ops) fn sb_db_cert_path(
    config: &ApmConfig,
    registry: &str,
) -> Option<PathBuf> {
    let path = config
        .scope
        .registries_path()
        .join(registry)
        .join("sb-certs")
        .join("db.pem");
    path.exists().then_some(path)
}

/// Derives the independently measured identities of a deterministic A/B UKI pair.
pub(in crate::registry_ops) fn derive_slot_uki_facts(
    image_store: &Path,
    db_cert: Option<&Path>,
) -> Result<Vec<SysrootUkiEntry>> {
    let slot_paths = [
        (UkiSlot::A, image_store.join("uki-a.efi")),
        (UkiSlot::B, image_store.join("uki-b.efi")),
    ];
    let present = slot_paths.iter().filter(|(_, path)| path.is_file()).count();
    if present == 0 {
        return Ok(Vec::new());
    }
    if present != slot_paths.len() {
        bail!(
            "A/B image output {} must carry both uki-a.efi and uki-b.efi",
            image_store.display()
        );
    }

    let verify_slot_cmdline = image_store.join("root.roothash").is_file();
    let mut entries = Vec::with_capacity(slot_paths.len());
    for (slot, path) in slot_paths {
        let facts = derive_sb_facts(&path, db_cert)
            .with_context(|| format!("deriving slot-specific facts for {}", path.display()))?;
        if verify_slot_cmdline {
            validate_uki_slot_cmdline(&path, slot)?;
        }
        entries.push(SysrootUkiEntry {
            slot,
            path: path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .context("slot UKI filename is not UTF-8")?
                .to_string(),
            sb_signer_cert_sha256: facts.signer_cert_sha256,
            sbat: facts.sbat,
            expected_pcr11: facts.expected_pcr11,
        });
    }
    let signed = entries
        .iter()
        .filter(|entry| entry.sb_signer_cert_sha256.is_some())
        .count();
    if signed != 0 && signed != entries.len() {
        bail!("A/B image must not mix signed and unsigned UKIs");
    }
    Ok(entries)
}

pub(in crate::registry_ops) fn derive_recovery_uki_facts(
    image_store: &Path,
    recovery: Option<&ProducerRecoveryInfo>,
    release: &str,
    db_cert: Option<&Path>,
) -> Result<Vec<RecoveryUkiEntry>> {
    let paths = [
        image_store.join("recovery-a.efi"),
        image_store.join("recovery-b.efi"),
        image_store.join("recovery-a.conf"),
        image_store.join("recovery-b.conf"),
    ];
    let present = paths.iter().filter(|path| path.is_file()).count();
    let Some(recovery) = recovery else {
        if present != 0 {
            bail!("recovery artifacts require recovery metadata in image-info.json");
        }
        return Ok(Vec::new());
    };
    if present != paths.len() {
        bail!("recovery image output must carry two UKIs and two loader entries");
    }
    if recovery.abi == 0 || recovery.release != release {
        bail!("recovery ABI or release identity disagrees with the image release");
    }
    aos_boot_identity::parse_recovery(&recovery.command_line)
        .context("recovery image-info command line is not canonical")?;

    let copies = [
        (
            UkiSlot::A,
            "A",
            "recovery-a.efi",
            "recovery-a.conf",
            "EFI/AOS/recovery-a.efi",
            "loader/entries/recovery-a.conf",
            &recovery.copies.a,
            recovery.entries.a.as_str(),
        ),
        (
            UkiSlot::B,
            "B",
            "recovery-b.efi",
            "recovery-b.conf",
            "EFI/AOS/recovery-b.efi",
            "loader/entries/recovery-b.conf",
            &recovery.copies.b,
            recovery.entries.b.as_str(),
        ),
    ];
    let mut entries = Vec::with_capacity(copies.len());
    for (copy, copy_name, uki_name, entry_name, esp_path, entry_path, metadata, recorded_entry) in
        copies
    {
        if metadata.esp_path != esp_path || recorded_entry != entry_path {
            bail!("recovery copy {copy_name} uses a noncanonical ESP path");
        }
        let uki = image_store.join(uki_name);
        let uki_metadata = fs::symlink_metadata(&uki)?;
        if !uki_metadata.file_type().is_file() || uki_metadata.len() == 0 {
            bail!(
                "recovery UKI {} is not a nonempty regular file",
                uki.display()
            );
        }
        let mut uki_file = fs::File::open(&uki)?;
        let digest = sha256_open_file(&mut uki_file, &uki)?;
        if metadata.byte_size != uki_metadata.len() || metadata.sha256 != digest {
            bail!("recovery copy {copy_name} size or digest disagrees with image-info.json");
        }

        let facts = derive_sb_facts(&uki, db_cert)?;
        let signer = facts
            .signer_cert_sha256
            .context("recovery UKIs must carry a db-verifiable Authenticode signature")?;
        let cmdline = read_bounded_pe_text(&uki, ".cmdline", 64 * 1024)?;
        if cmdline != recovery.command_line {
            bail!("recovery copy {copy_name} command line disagrees with image-info.json");
        }
        aos_boot_identity::parse_recovery(&cmdline)
            .with_context(|| format!("recovery copy {copy_name} command line is not canonical"))?;
        let uki_bytes = fs::read(&uki)?;
        if dump_pe_section(&uki_bytes, ".pcrsig")?.is_some_and(|file| {
            file.as_file()
                .metadata()
                .is_ok_and(|metadata| metadata.len() != 0)
        }) {
            bail!("recovery copy {copy_name} carries forbidden normal PCR authorization");
        }
        let os_release = read_bounded_pe_text(&uki, ".osrel", 64 * 1024)?;
        validate_recovery_os_release(&os_release, copy_name, &recovery.release, recovery.abi)?;

        let entry = image_store.join(entry_name);
        let entry_metadata = fs::symlink_metadata(&entry)?;
        if !entry_metadata.file_type().is_file() || entry_metadata.len() > 4096 {
            bail!("recovery loader entry {entry_name} is not a bounded regular file");
        }
        let expected_entry = format!(
            "title AOS Recovery {copy_name} ({})\nefi /{esp_path}\n",
            recovery.release
        );
        if fs::read_to_string(&entry)? != expected_entry {
            bail!("recovery loader entry {entry_name} is not canonical");
        }

        entries.push(RecoveryUkiEntry {
            copy,
            path: uki_name.to_string(),
            entry_path: entry_name.to_string(),
            byte_size: metadata.byte_size,
            sha256: digest,
            release: recovery.release.clone(),
            recovery_abi: recovery.abi,
            sb_signer_cert_sha256: signer,
            sbat: facts.sbat,
        });
    }
    Ok(entries)
}

fn read_bounded_pe_text(uki: &Path, section: &str, maximum: u64) -> Result<String> {
    let bytes = fs::read(uki).with_context(|| format!("reading UKI {}", uki.display()))?;
    let extracted = dump_pe_section(&bytes, section)?
        .with_context(|| format!("recovery UKI {} has no {section} section", uki.display()))?;
    let metadata = extracted.as_file().metadata()?;
    if metadata.len() == 0 || metadata.len() > maximum {
        bail!("recovery UKI {section} section is outside its size bound");
    }
    let bytes = fs::read(extracted.path())?;
    let text = String::from_utf8(bytes)
        .with_context(|| format!("recovery UKI {section} section is not UTF-8"))?;
    Ok(text.trim_end_matches('\0').to_string())
}

fn validate_recovery_os_release(
    os_release: &str,
    copy: &str,
    release: &str,
    recovery_abi: u32,
) -> Result<()> {
    let expected = [
        ("AOS_RELEASE_ID", release.to_string()),
        ("AOS_RECOVERY_ABI", recovery_abi.to_string()),
        ("AOS_RECOVERY_COPY", copy.to_string()),
    ];
    for (key, expected_value) in expected {
        let values = os_release
            .lines()
            .filter_map(|line| line.split_once('='))
            .filter_map(|(found, value)| (found == key).then_some(value.trim_matches('"')))
            .collect::<Vec<_>>();
        if values.as_slice() != [expected_value.as_str()] {
            bail!("recovery signed os-release has invalid {key}");
        }
    }
    Ok(())
}

pub(in crate::registry_ops) fn derive_recovery_bundle_manifest(
    image_store: &Path,
    recovery: Option<&ProducerRecoveryInfo>,
    module_abi: Option<u32>,
    release: &str,
    architecture: &str,
    platform: &str,
) -> Result<Option<RecoveryBundleManifest>> {
    let Some(recovery) = recovery else {
        return Ok(None);
    };
    let module_abi = module_abi
        .filter(|abi| *abi != 0)
        .context("recovery image-info.json must carry a positive moduleAbi")?;
    let specifications = [
        (RecoveryBundleComponentId::RootImage, "root.img"),
        (RecoveryBundleComponentId::RootVerity, "root.verity"),
        (RecoveryBundleComponentId::RootHash, "root.roothash"),
        (RecoveryBundleComponentId::NormalUkiA, "uki-a.efi"),
        (RecoveryBundleComponentId::NormalUkiB, "uki-b.efi"),
        (RecoveryBundleComponentId::RecoveryUkiA, "recovery-a.efi"),
        (RecoveryBundleComponentId::RecoveryUkiB, "recovery-b.efi"),
        (RecoveryBundleComponentId::RecoveryEntryA, "recovery-a.conf"),
        (RecoveryBundleComponentId::RecoveryEntryB, "recovery-b.conf"),
        (RecoveryBundleComponentId::ImageMetadata, "image-info.json"),
    ];
    let mut components = Vec::with_capacity(specifications.len());
    for (id, path) in specifications {
        let artifact = image_store.join(path);
        let metadata = fs::symlink_metadata(&artifact)
            .with_context(|| format!("reading recovery bundle component {path}"))?;
        if !metadata.file_type().is_file() || metadata.len() == 0 {
            bail!("recovery bundle component {path} is not a nonempty regular file");
        }
        let mut file = fs::File::open(&artifact)?;
        let digest = sha256_open_file(&mut file, &artifact)?;
        components.push(RecoveryBundleComponent {
            id,
            path: path.to_string(),
            byte_size: metadata.len(),
            sha256: digest,
        });
    }
    Ok(Some(RecoveryBundleManifest {
        schema: "aos.recovery-bundle/v1".to_string(),
        release: release.to_string(),
        architecture: architecture.to_string(),
        platform: platform.to_string(),
        module_abi,
        recovery_abi: recovery.abi,
        components,
    }))
}

pub(crate) fn verify_detached_db_signature(
    manifest: &Path,
    signature: &Path,
    db_cert: &Path,
) -> Result<()> {
    let public_key =
        tempfile::NamedTempFile::new().context("creating temporary recovery bundle public key")?;
    let output = Command::new("openssl")
        .args(["x509", "-pubkey", "-noout", "-in"])
        .arg(db_cert)
        .output()
        .context("extracting the recovery bundle verification key")?;
    if !output.status.success() {
        bail!(
            "extracting recovery bundle verification key failed: {}",
            combine_output(
                &String::from_utf8_lossy(&output.stdout),
                &String::from_utf8_lossy(&output.stderr)
            )
        );
    }
    fs::write(public_key.path(), output.stdout)?;
    let output = Command::new("openssl")
        .args(["dgst", "-sha256", "-verify"])
        .arg(public_key.path())
        .arg("-signature")
        .arg(signature)
        .arg(manifest)
        .output()
        .context("verifying the recovery bundle manifest signature")?;
    if !output.status.success() {
        bail!(
            "recovery bundle manifest signature rejected: {}",
            combine_output(
                &String::from_utf8_lossy(&output.stdout),
                &String::from_utf8_lossy(&output.stderr)
            )
        );
    }
    Ok(())
}

#[cfg(test)]
fn find_ukis_in_store_path(store_path: &str) -> Result<Vec<(Option<UkiSlot>, PathBuf)>> {
    let root = Path::new(store_path);
    let a = root.join("uki-a.efi");
    let b = root.join("uki-b.efi");
    if a.is_file() || b.is_file() {
        if !(a.is_file() && b.is_file()) {
            bail!("A/B image artifact {store_path} must carry both uki-a.efi and uki-b.efi");
        }
        return Ok(vec![(Some(UkiSlot::A), a), (Some(UkiSlot::B), b)]);
    }
    let mut found = fs::read_dir(root)
        .with_context(|| format!("reading image artifact {}", root.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("efi"))
        })
        .collect::<Vec<_>>();
    found.sort();
    match found.len() {
        0 => Ok(Vec::new()),
        1 => Ok(vec![(None, found.remove(0))]),
        count => bail!(
            "image artifact {store_path} carries {count} UKIs but no deterministic uki-a.efi/uki-b.efi pair"
        ),
    }
}

fn validate_uki_slot_cmdline(uki: &Path, slot: UkiSlot) -> Result<()> {
    let pe = fs::read(uki).with_context(|| format!("reading UKI {}", uki.display()))?;
    let section = pe_section(&pe, ".cmdline")?
        .with_context(|| format!("A/B UKI {} has no measured .cmdline section", uki.display()))?;
    let cmdline = std::str::from_utf8(section)
        .with_context(|| format!("UKI {} .cmdline is not UTF-8", uki.display()))?;
    let cmdline = cmdline.trim_end_matches('\0');
    let suffix = match slot {
        UkiSlot::A => "a",
        UkiSlot::B => "b",
    };
    let data = format!("systemd.verity_root_data=/dev/disk/by-partlabel/root-{suffix}");
    let hash = format!("systemd.verity_root_hash=/dev/disk/by-partlabel/root-{suffix}-hash");
    if !cmdline.split_ascii_whitespace().any(|word| word == data)
        || !cmdline.split_ascii_whitespace().any(|word| word == hash)
    {
        bail!(
            "A/B UKI {} slot {:?} does not select its matching root and verity partitions",
            uki.display(),
            slot
        );
    }
    Ok(())
}

/// Derives Secure Boot facts from the exact UKI named by `image-info.json`.
///
/// Extracts the signer cert digest and SBAT table without searching an
/// artifact tree. A predicted PCR-11 value is included only when the UKI
/// carries a signed `.pcrsig` policy; Secure Boot signing alone does not make
/// an image a measured-boot image. Optionally enforces the publish-time
/// rule that an image's embedded signature must verify against `db_cert`
/// before it can be cataloged.
///
/// Returns an empty [`SbFacts`] for an explicitly associated unsigned UKI,
/// preserving unsigned development images without losing byte identity.
///
/// # Errors
///
/// Returns an error when a signed UKI fact cannot be derived, or when
/// `db_cert` is given and the signature does not verify against it.
pub(in crate::registry_ops) fn derive_sb_facts(
    uki: &Path,
    db_cert: Option<&Path>,
) -> Result<SbFacts> {
    let signer = extract_sb_signer_cert_sha256(uki)?;
    // An image with no embedded signature carries no SB facts to catalog.
    if signer.is_none() {
        return Ok(SbFacts::default());
    }

    if let Some(db_cert) = db_cert {
        verify_uki_against_db_cert(uki, db_cert).with_context(|| {
            "refusing to catalog a component whose signature does not verify \
             against the declared db cert"
                .to_string()
        })?;
    }

    let pe = fs::read(uki).with_context(|| format!("reading UKI {}", uki.display()))?;
    let expected_pcr11 = if pe_section(&pe, ".pcrsig")?.is_some() {
        extract_expected_pcr11(uki)?
    } else {
        None
    };

    Ok(SbFacts {
        signer_cert_sha256: signer,
        sbat: extract_sbat_entries(uki)?,
        expected_pcr11,
        ukis: Vec::new(),
        recovery_ukis: Vec::new(),
        recovery_bundle: None,
    })
}

#[cfg(test)]
mod tests;
