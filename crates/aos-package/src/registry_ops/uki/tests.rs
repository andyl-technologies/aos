//! Tests for uKI binary inspection, Secure Boot certificate facts, and recovery bundle validation.

use super::{
    der_len, find_ukis_in_store_path, first_certificate_der, leaf_cert_from_pe, parse_pcr11,
    parse_sbat_csv, pe_section, sha256_hex,
};
use crate::registry_ops::test_support::{der_wrap, synthetic_pe_section};
use crate::types::{SbatEntry, UkiSlot};

#[test]
fn parse_sbat_csv_reads_component_generations() {
    let csv = "sbat,1,SBAT Version,sbat,1,https://x\naos,2,AOS,aos,2,https://aos\n# comment\n\nsystemd,1,systemd,systemd,1,https://systemd\n";
    let entries = parse_sbat_csv(csv).unwrap();
    assert_eq!(
        entries,
        vec![
            SbatEntry {
                component: "sbat".into(),
                generation: 1
            },
            SbatEntry {
                component: "aos".into(),
                generation: 2
            },
            SbatEntry {
                component: "systemd".into(),
                generation: 1
            },
        ]
    );
}

#[test]
fn parse_sbat_csv_rejects_non_numeric_generation() {
    assert!(parse_sbat_csv("aos,notanumber,AOS\n").is_err());
}

#[test]
fn pe_section_returns_virtual_bytes_without_file_padding() {
    let pe = synthetic_pe_section(b".cmdline", 5, b"root\0padding");
    assert_eq!(pe_section(&pe, ".cmdline").unwrap(), Some(&b"root\0"[..]));
    assert!(pe_section(&pe, ".sbat").unwrap().is_none());

    let zero_virtual = synthetic_pe_section(b".cmdline", 0, b"ignored");
    assert!(pe_section(&zero_virtual, ".cmdline").unwrap().is_none());

    let larger_virtual = synthetic_pe_section(b".cmdline", 32, b"materialized");
    assert_eq!(
        pe_section(&larger_virtual, ".cmdline").unwrap(),
        Some(&b"materialized"[..])
    );
}

#[test]
fn pe_section_rejects_malformed_and_duplicate_ranges() {
    let mut malformed = synthetic_pe_section(b".sbat", 5, b"short");
    let pe_offset = 0x40_usize;
    let coff = pe_offset + 4;
    let section_table = coff + 20 + 112;
    malformed[section_table + 20..section_table + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(pe_section(&malformed, ".sbat").is_err());

    let mut duplicate_pe = synthetic_pe_section(b".sbat", 5, b"short");
    duplicate_pe[coff + 2..coff + 4].copy_from_slice(&2_u16.to_le_bytes());
    let duplicate = duplicate_pe[section_table..section_table + 40].to_vec();
    duplicate_pe.splice(section_table + 40..section_table + 40, duplicate);
    assert!(pe_section(&duplicate_pe, ".sbat").is_err());
}

#[test]
fn parse_pcr11_extracts_sha256_digest() {
    let out = "11:sha256=abcdef0123\n12:sha256=ffff\n";
    assert_eq!(parse_pcr11(out).as_deref(), Some("abcdef0123"));
    assert_eq!(parse_pcr11("no pcr lines here"), None);
}

#[test]
fn parse_pcr11_takes_ready_phase_line() {
    // `systemd-measure calculate` prints one 11: line per boot phase
    // (enter-initrd first and ready last). Runtime activation happens after
    // the ready barrier, so the catalog pins the final line.
    let out = "# PCR[11] Phase <enter-initrd>\n\
               # PCR[11] Phase <enter-initrd:leave-initrd>\n\
               11:sha256=aaaa\n\
               11:sha256=bbbb\n";
    assert_eq!(parse_pcr11(out).as_deref(), Some("bbbb"));
}

#[test]
fn uki_discovery_uses_explicit_ab_slot_names() {
    let temp = tempfile::TempDir::new().unwrap();
    std::fs::write(temp.path().join("uki-b.efi"), b"b").unwrap();
    std::fs::write(temp.path().join("uki-a.efi"), b"a").unwrap();
    std::fs::write(temp.path().join("other.txt"), b"not a UKI").unwrap();

    let found = find_ukis_in_store_path(temp.path().to_str().unwrap()).unwrap();
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].0, Some(UkiSlot::A));
    assert_eq!(found[0].1.file_name().unwrap(), "uki-a.efi");
    assert_eq!(found[1].0, Some(UkiSlot::B));
    assert_eq!(found[1].1.file_name().unwrap(), "uki-b.efi");
}

#[test]
fn uki_discovery_rejects_ambiguous_or_partial_payloads() {
    let partial = tempfile::TempDir::new().unwrap();
    std::fs::write(partial.path().join("uki-a.efi"), b"a").unwrap();
    let error = find_ukis_in_store_path(partial.path().to_str().unwrap()).unwrap_err();
    assert!(error.to_string().contains("both uki-a.efi and uki-b.efi"));

    let ambiguous = tempfile::TempDir::new().unwrap();
    std::fs::write(ambiguous.path().join("one.efi"), b"one").unwrap();
    std::fs::write(ambiguous.path().join("two.efi"), b"two").unwrap();
    let error = find_ukis_in_store_path(ambiguous.path().to_str().unwrap()).unwrap_err();
    assert!(error.to_string().contains("deterministic"));
}

#[test]
fn der_len_handles_short_and_long_forms() {
    assert_eq!(der_len(&[0x05]).unwrap(), (5, 1));
    // 0x82 => two length octets follow: 0x01 0x00 = 256.
    assert_eq!(der_len(&[0x82, 0x01, 0x00]).unwrap(), (256, 3));
}

#[test]
fn leaf_cert_from_pe_extracts_first_certificate() {
    // Build a tiny synthetic PE32+ with a security directory whose
    // WIN_CERTIFICATE blob holds a PKCS#7 ContentInfo wrapping a
    // SignedData with two certificates; assert we return the first.
    let leaf: &[u8] = &[0x30, 0x03, 0x01, 0x02, 0x03]; // SEQUENCE len 3
    let second: &[u8] = &[0x30, 0x02, 0x09, 0x08]; // SEQUENCE len 2
    let mut certs_value = Vec::new();
    certs_value.extend_from_slice(leaf);
    certs_value.extend_from_slice(second);
    // certificates [0] IMPLICIT (tag 0xA0).
    let mut certs_field = vec![0xA0, certs_value.len() as u8];
    certs_field.extend_from_slice(&certs_value);
    // SignedData SEQUENCE wrapping the certificates field.
    let mut signed_data = vec![0x30, certs_field.len() as u8];
    signed_data.extend_from_slice(&certs_field);
    // content [0] EXPLICIT wrapping SignedData.
    let mut content = vec![0xA0, signed_data.len() as u8];
    content.extend_from_slice(&signed_data);
    // ContentInfo SEQUENCE { OID, content [0] }.
    let oid: &[u8] = &[0x06, 0x01, 0x2A]; // OBJECT IDENTIFIER len 1
    let mut ci_value = Vec::new();
    ci_value.extend_from_slice(oid);
    ci_value.extend_from_slice(&content);
    let mut pkcs7 = vec![0x30, ci_value.len() as u8];
    pkcs7.extend_from_slice(&ci_value);

    let extracted = first_certificate_der(&pkcs7).unwrap();
    assert_eq!(extracted, leaf);

    // Wrap the PKCS#7 in a WIN_CERTIFICATE blob and a minimal PE32+ so
    // leaf_cert_from_pe finds it via the security directory.
    let mut win_cert = vec![0u8; 8]; // dwLength/wRevision/wCertificateType
    win_cert.extend_from_slice(&pkcs7);

    // Assemble: DOS header (e_lfanew at 0x3c), PE sig, COFF, optional
    // header (PE32+ magic), data directories with security entry.
    let mut pe = vec![0u8; 0x40];
    pe[0] = b'M';
    pe[1] = b'Z';
    let pe_off: u32 = 0x40;
    pe[0x3c..0x40].copy_from_slice(&pe_off.to_le_bytes());
    // PE signature + COFF header (20 bytes) + optional header.
    let mut tail = Vec::new();
    tail.extend_from_slice(&0x0000_4550u32.to_le_bytes()); // "PE\0\0"
    tail.extend_from_slice(&[0u8; 20]); // COFF header
    tail[20..22].copy_from_slice(&(112_u16 + 16 * 8).to_le_bytes());
    let opt_start = pe.len() + tail.len();
    tail.extend_from_slice(&0x020bu16.to_le_bytes()); // PE32+ magic
    // Pad optional header up to the data directory (112 bytes from magic).
    tail.resize(tail.len() + (112 - 2), 0);
    let count_in_tail = (opt_start - pe.len()) + 108;
    tail[count_in_tail..count_in_tail + 4].copy_from_slice(&16_u32.to_le_bytes());
    let dir_start = opt_start + 112;
    // Security dir is entry index 4 (each entry 8 bytes).
    let cert_off = dir_start + 16 * 8; // place blob after all 16 entries
    tail.resize(tail.len() + 16 * 8, 0);
    // Write security entry (index 4): offset + size.
    let entry_in_tail = (dir_start - pe.len()) + 4 * 8;
    tail[entry_in_tail..entry_in_tail + 4].copy_from_slice(&(cert_off as u32).to_le_bytes());
    tail[entry_in_tail + 4..entry_in_tail + 8]
        .copy_from_slice(&(win_cert.len() as u32).to_le_bytes());
    pe.extend_from_slice(&tail);
    assert_eq!(pe.len(), cert_off);
    pe.extend_from_slice(&win_cert);

    let from_pe = leaf_cert_from_pe(&pe).unwrap().unwrap();
    assert_eq!(from_pe, leaf);

    let mut unsigned = pe;
    let entry_in_pe = 0x40 + entry_in_tail;
    unsigned[entry_in_pe..entry_in_pe + 8].fill(0);
    assert!(leaf_cert_from_pe(&unsigned).unwrap().is_none());

    let mut malformed = unsigned;
    malformed[entry_in_pe..entry_in_pe + 4].copy_from_slice(&(cert_off as u32).to_le_bytes());
    assert!(leaf_cert_from_pe(&malformed).is_err());

    let mut truncated_optional_header = malformed;
    let coff_optional_size = 0x40 + 4 + 16;
    truncated_optional_header[coff_optional_size..coff_optional_size + 2]
        .copy_from_slice(&64_u16.to_le_bytes());
    assert!(leaf_cert_from_pe(&truncated_optional_header).is_err());
}

/// M3: with a real SignerInfo present, the signer cert is selected by
/// issuer+serial even when it is NOT first in the certificate SET. A
/// naive "take element [0]" would return the intermediate and fail.
#[test]
fn first_certificate_der_selects_signer_by_issuer_and_serial() {
    // Build a minimal Certificate: SEQUENCE { TBSCertificate SEQUENCE {
    //   serialNumber INTEGER, signature SEQUENCE{}, issuer Name SEQUENCE
    // } }. We omit signatureAlgorithm/signatureValue siblings — only the
    // TBS prefix is parsed by cert_issuer_and_serial.
    fn make_cert(serial: u8, issuer_byte: u8) -> Vec<u8> {
        let serial_int = vec![0x02, 0x01, serial]; // INTEGER serial
        let sig_alg = der_wrap(0x30, &[]); // empty AlgorithmIdentifier
        let issuer = der_wrap(0x30, &[0x05, 0x01, issuer_byte]); // Name
        let mut tbs_value = Vec::new();
        tbs_value.extend_from_slice(&serial_int);
        tbs_value.extend_from_slice(&sig_alg);
        tbs_value.extend_from_slice(&issuer);
        let tbs = der_wrap(0x30, &tbs_value);
        der_wrap(0x30, &tbs) // Certificate wraps the TBS
    }

    // Intermediate (serial 1, issuer 0xAA) and signer (serial 9, issuer
    // 0xBB). Place the signer second.
    let intermediate = make_cert(1, 0xAA);
    let signer = make_cert(9, 0xBB);
    let mut certs_value = Vec::new();
    certs_value.extend_from_slice(&intermediate);
    certs_value.extend_from_slice(&signer);
    let certs_field = der_wrap(0xA0, &certs_value);

    // SignerInfo SEQUENCE { version INTEGER 1, IssuerAndSerialNumber
    //   SEQUENCE { issuer Name(0xBB), serialNumber INTEGER 9 } }.
    let issuer_bb = der_wrap(0x30, &[0x05, 0x01, 0xBB]);
    let serial_9 = vec![0x02, 0x01, 0x09];
    let mut ias_value = Vec::new();
    ias_value.extend_from_slice(&issuer_bb);
    ias_value.extend_from_slice(&serial_9);
    let ias = der_wrap(0x30, &ias_value);
    let mut signer_info_value = vec![0x02, 0x01, 0x01]; // version 1
    signer_info_value.extend_from_slice(&ias);
    let signer_info = der_wrap(0x30, &signer_info_value);
    let signer_infos = der_wrap(0x31, &signer_info); // SET OF SignerInfo

    // SignedData SEQUENCE { certificates [0], signerInfos SET }.
    let mut signed_data_value = Vec::new();
    signed_data_value.extend_from_slice(&certs_field);
    signed_data_value.extend_from_slice(&signer_infos);
    let signed_data = der_wrap(0x30, &signed_data_value);
    let content = der_wrap(0xA0, &signed_data); // content [0] EXPLICIT
    let mut ci_value = vec![0x06, 0x01, 0x2A]; // contentType OID
    ci_value.extend_from_slice(&content);
    let pkcs7 = der_wrap(0x30, &ci_value);

    let extracted = first_certificate_der(&pkcs7).unwrap();
    assert_eq!(
        extracted,
        signer.as_slice(),
        "signer cert (issuer 0xBB / serial 9) must be selected, not the first cert"
    );

    // Sanity: the SHA-256 of the selected cert is the signer's digest.
    assert_eq!(sha256_hex(extracted), sha256_hex(&signer));
}
