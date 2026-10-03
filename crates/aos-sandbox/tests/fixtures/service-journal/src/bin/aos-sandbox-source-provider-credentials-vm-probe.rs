//! Provisions the fixed, role-separated SourceProvider credentials for a VM.
//!
//! This fixture uses deterministic identities and signing seeds so the VM's
//! signed protocol graph can name them. It is compiled only as a test probe.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    ProviderHeldSnapshotCatalogV1, ProviderHeldSnapshotRowV1, SourceProviderAuthorityTrustStateV1,
    SourceProviderAuthorityTrustV1, SourceProviderAuthorityV1, SourceProviderKeyTrustStateV1,
    SourceProviderKeyTrustV1, SourceProviderKeyUsageV1, SourceProviderSigningKeyV1,
    SourceProviderTrustSetV1, ZfsHeldSnapshotProofV1, source_provider_trust_set_digest_v1,
};
use aos_sandbox_source_provider_security::manifest::{
    SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES, SourceProviderSecurityManifestV1,
    SourceProviderSecurityRoleV1,
};
use aos_sandbox_source_provider_security::route_file::{
    SOURCE_PROVIDER_ROUTE_FILE_BYTES, SourceProviderRouteFileV1,
};
use aos_sandbox_source_provider_security::trust_file::{
    SOURCE_PROVIDER_TRUST_AUTHORITY_BYTES, SOURCE_PROVIDER_TRUST_HEAD_LINK_BYTES,
    SOURCE_PROVIDER_TRUST_HEADER_BYTES, SOURCE_PROVIDER_TRUST_KEY_BYTES, SourceProviderTrustFileV1,
};
use aos_sandbox_source_provider_security::{
    validate_fixed_provider_authority_v1, validate_fixed_root_mount_authority_v1,
};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

const ROOT_DIRECTORY: &str = "/var/lib/aos/sandbox-mount/source-provider-authority";
const PROVIDER_DIRECTORY: &str = "/var/lib/aos/source-provider/authority";
const BACKEND_DIRECTORY: &str = "/var/lib/aos/source-provider/backend-authority";
const BACKEND_MANIFEST_BYTES: usize = 16 + 6 * 152;
const VALID_UNTIL: i64 = 4_102_444_800; // 2100-01-01 UTC.
const CGROUP_DOMAIN: &[u8] = b"aos-source-provider-cgroup-v2-path-v1\0";

struct CredentialBundle {
    manifest: [u8; SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES],
    trust: Vec<u8>,
    route: [u8; SOURCE_PROVIDER_ROUTE_FILE_BYTES],
    secrets: [[u8; 48]; 4],
    publisher: SourceProviderSigningKeyV1,
    trust_digest: ObjectDigest,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("SourceProvider credential VM provision failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = std::env::args_os().collect();
    if rustix::process::geteuid().as_raw() != 0 {
        return Err("credential provisioner requires UID 0".into());
    }
    let cgroup = fs::read("/proc/self/cgroup")?;
    let cgroup_digest = current_cgroup_digest(&cgroup)?;
    let credentials = render(cgroup_digest)?;
    match arguments.as_slice() {
        [_] => provision(&credentials),
        [_, operation] if operation == "install" => provision(&credentials),
        [_, operation, binding, publication, held_rows] if operation == "catalog" => {
            publish_catalog(
                &credentials,
                binding.to_str().ok_or("binding digest is not UTF-8")?,
                Path::new(publication),
                Path::new(held_rows),
            )
        }
        _ => Err(
            "usage: aos-sandbox-source-provider-credentials-vm-probe install|catalog BINDING_DIGEST_HEX PUBLICATION HELD_ROWS"
                .into(),
        ),
    }
}

fn provision(credentials: &CredentialBundle) -> Result<(), Box<dyn Error>> {
    // Both fixed journal openers require their final state directory to be
    // root-owned mode 0700, independently of the role-local custody mode.
    for root in [
        Path::new("/var/lib/aos/sandbox-mount"),
        Path::new("/var/lib/aos/source-provider"),
    ] {
        fs::create_dir_all(root)?;
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.file_type().is_dir() || metadata.uid() != 0 {
            return Err("fixed state directory is not root-owned ordinary directory".into());
        }
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        let metadata = fs::symlink_metadata(root)?;
        if metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
            return Err("fixed state directory has incorrect ownership or mode".into());
        }
    }

    install_role(
        Path::new(ROOT_DIRECTORY),
        SourceProviderSecurityRoleV1::RootMount,
        credentials,
    )?;
    install_role(
        Path::new(PROVIDER_DIRECTORY),
        SourceProviderSecurityRoleV1::Provider,
        credentials,
    )?;
    install_backend_verifiers(Path::new(BACKEND_DIRECTORY))?;

    // The fixed entry points check root ownership, exact directory contents,
    // file modes, canonical records, key material, and current process custody.
    validate_fixed_root_mount_authority_v1()?;
    validate_fixed_provider_authority_v1()?;
    println!("source-provider-fixed-credentials:PASS");
    Ok(())
}

fn current_cgroup_digest(bytes: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
    let mut lines = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty());
    let line = lines.next().ok_or("missing unified cgroup record")?;
    if lines.next().is_some() {
        return Err("multiple cgroup records".into());
    }
    let path = line
        .strip_prefix(b"0::")
        .ok_or("expected one unified cgroup-v2 record")?;
    if path.len() > 4096
        || !path.starts_with(b"/")
        || path.contains(&0)
        || (path != b"/"
            && (path.ends_with(b"/")
                || path[1..]
                    .split(|byte| *byte == b'/')
                    .any(|part| part.is_empty() || matches!(part, b"." | b".."))))
    {
        return Err("noncanonical unified cgroup path".into());
    }
    let mut digest = Sha256::new();
    digest.update(CGROUP_DOMAIN);
    digest.update(u32::try_from(path.len())?.to_be_bytes());
    digest.update(path);
    Ok(digest.finalize().into())
}

fn render(cgroup_digest: [u8; 32]) -> Result<CredentialBundle, Box<dyn Error>> {
    let root_authority = authority(1, 7)?;
    let provider_authority = authority(2, 8)?;
    let authorities = vec![
        authority_trust(root_authority.clone())?,
        authority_trust(provider_authority.clone())?,
    ];

    let seeds = [[11; 32], [13; 32], [12; 32], [14; 32]];
    let usages = [
        SourceProviderKeyUsageV1::RootMountHello,
        SourceProviderKeyUsageV1::ProviderHello,
        SourceProviderKeyUsageV1::RootMountRecord,
        SourceProviderKeyUsageV1::ProviderOutcome,
    ];
    let key_ids = [21, 23, 22, 24];
    let signers = [0, 1, 2, 3].map(|index| {
        let authority = if index == 0 || index == 2 {
            &root_authority
        } else {
            &provider_authority
        };
        let signing_key = SigningKey::from_bytes(&seeds[index]);
        SourceProviderSigningKeyV1::for_signing_key(
            authority.authority_id(),
            authority.authority_generation(),
            authority.authority_digest(),
            [key_ids[index]; 16],
            1,
            usages[index],
            &signing_key,
        )
    });
    let signers: [SourceProviderSigningKeyV1; 4] = signers
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "four signer references were required")?;
    let publisher_key = SigningKey::from_bytes(&[17; 32]);
    let publisher = SourceProviderSigningKeyV1::for_signing_key(
        provider_authority.authority_id(),
        provider_authority.authority_generation(),
        provider_authority.authority_digest(),
        [25; 16],
        1,
        SourceProviderKeyUsageV1::CatalogPublisher,
        &publisher_key,
    )?;

    let mut keys = [0, 2, 1, 3]
        .into_iter()
        .map(|index| {
            SourceProviderKeyTrustV1::new(
                signers[index].clone(),
                SigningKey::from_bytes(&seeds[index])
                    .verifying_key()
                    .to_bytes(),
                0,
                VALID_UNTIL,
                SourceProviderKeyTrustStateV1::Eligible,
                0,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    keys.push(SourceProviderKeyTrustV1::new(
        publisher.clone(),
        publisher_key.verifying_key().to_bytes(),
        0,
        VALID_UNTIL,
        SourceProviderKeyTrustStateV1::Eligible,
        0,
    )?);
    let revocation_digest = ObjectDigest::from_bytes([15; 32]);
    let trust_digest =
        source_provider_trust_set_digest_v1(1, 1, revocation_digest, &authorities, &keys);
    let trust_set =
        SourceProviderTrustSetV1::new(1, trust_digest, 1, revocation_digest, authorities, keys)?;

    let trust = encode_trust(&trust_set);
    let route = encode_route(cgroup_digest);
    let manifest = encode_manifest(
        &signers,
        trust_digest,
        revocation_digest,
        Sha256::digest(&trust).into(),
        Sha256::digest(route).into(),
    );
    let secrets = std::array::from_fn(|index| {
        let mut secret = [0; 48];
        secret[..16].copy_from_slice(&signers[index].key_id());
        secret[16..].copy_from_slice(&seeds[index]);
        secret
    });

    let decoded_manifest = SourceProviderSecurityManifestV1::decode(&manifest)?;
    let decoded_trust = SourceProviderTrustFileV1::decode(&trust)?;
    let decoded_route = SourceProviderRouteFileV1::decode(&route)?;
    if decoded_manifest.to_canonical_bytes() != manifest
        || decoded_trust.to_canonical_bytes() != trust
        || decoded_route.to_canonical_bytes() != route
    {
        return Err("SourceProvider credentials did not round trip canonically".into());
    }
    Ok(CredentialBundle {
        manifest,
        trust,
        route,
        secrets,
        publisher,
        trust_digest,
    })
}

fn authority(id: u8, digest: u8) -> Result<SourceProviderAuthorityV1, Box<dyn Error>> {
    Ok(SourceProviderAuthorityV1::new(
        [id; 16],
        1,
        ObjectDigest::from_bytes([digest; 32]),
    )?)
}

fn authority_trust(
    authority: SourceProviderAuthorityV1,
) -> Result<SourceProviderAuthorityTrustV1, Box<dyn Error>> {
    Ok(SourceProviderAuthorityTrustV1::new(
        authority,
        0,
        VALID_UNTIL,
        SourceProviderAuthorityTrustStateV1::Trusted,
    )?)
}

fn encode_trust(trust: &SourceProviderTrustSetV1) -> Vec<u8> {
    let length = SOURCE_PROVIDER_TRUST_HEADER_BYTES
        + trust.authorities().len() * SOURCE_PROVIDER_TRUST_AUTHORITY_BYTES
        + trust.keys().len() * SOURCE_PROVIDER_TRUST_KEY_BYTES
        + SOURCE_PROVIDER_TRUST_HEAD_LINK_BYTES;
    let mut output = vec![0; length];
    output[..8].copy_from_slice(b"AOSPTRS2");
    put_u16(&mut output, 8, 2);
    put_u64(&mut output, 16, trust.trust_generation());
    output[24..56].copy_from_slice(trust.trust_digest().as_bytes());
    put_u64(&mut output, 56, trust.revocation_generation());
    output[64..96].copy_from_slice(trust.revocation_digest().as_bytes());
    put_u16(&mut output, 96, trust.authorities().len() as u16);
    put_u16(&mut output, 98, trust.keys().len() as u16);
    put_u16(&mut output, 100, 1);

    let mut offset = SOURCE_PROVIDER_TRUST_HEADER_BYTES;
    for entry in trust.authorities() {
        let authority = entry.authority();
        output[offset..offset + 16].copy_from_slice(&authority.authority_id());
        put_u64(&mut output, offset + 16, authority.authority_generation());
        output[offset + 24..offset + 56].copy_from_slice(authority.authority_digest().as_bytes());
        put_i64(&mut output, offset + 56, entry.valid_from_seconds());
        put_i64(&mut output, offset + 64, entry.valid_until_seconds());
        output[offset + 72] = entry.state() as u8;
        encode_head(&mut output, offset + 80, trust);
        offset += SOURCE_PROVIDER_TRUST_AUTHORITY_BYTES;
    }
    for entry in trust.keys() {
        encode_signer(&mut output[offset..offset + 120], entry.signer());
        output[offset + 120..offset + 152].copy_from_slice(entry.public_key());
        put_i64(&mut output, offset + 152, entry.valid_from_seconds());
        put_i64(&mut output, offset + 160, entry.valid_until_seconds());
        output[offset + 168] = entry.state() as u8;
        put_u64(
            &mut output,
            offset + 176,
            entry.superseded_by_key_generation(),
        );
        encode_head(&mut output, offset + 184, trust);
        encode_head(&mut output, offset + 264, trust);
        offset += SOURCE_PROVIDER_TRUST_KEY_BYTES;
    }
    encode_head(&mut output, offset, trust);
    output
}

fn encode_head(output: &mut [u8], offset: usize, trust: &SourceProviderTrustSetV1) {
    put_u64(output, offset, trust.trust_generation());
    output[offset + 8..offset + 40].copy_from_slice(trust.trust_digest().as_bytes());
    put_u64(output, offset + 40, trust.revocation_generation());
    output[offset + 48..offset + 80].copy_from_slice(trust.revocation_digest().as_bytes());
}

fn encode_route(cgroup_digest: [u8; 32]) -> [u8; SOURCE_PROVIDER_ROUTE_FILE_BYTES] {
    let mut output = [0; SOURCE_PROVIDER_ROUTE_FILE_BYTES];
    output[..8].copy_from_slice(b"AOSPRTE1");
    put_u16(&mut output, 8, 1);
    output[16..32].copy_from_slice(&[6; 16]);
    put_u64(&mut output, 32, 1);
    output[40..72].copy_from_slice(&[9; 32]);
    output[72..88].copy_from_slice(&[2; 16]);
    output[88..120].copy_from_slice(&[10; 32]);
    output[120] = 0x0f;
    output[168..184].copy_from_slice(&[1; 16]);
    output[136..168].copy_from_slice(&cgroup_digest);
    output[192..224].copy_from_slice(&cgroup_digest);
    output
}

fn encode_manifest(
    signers: &[SourceProviderSigningKeyV1; 4],
    trust_digest: ObjectDigest,
    revocation_digest: ObjectDigest,
    trust_sha256: [u8; 32],
    route_sha256: [u8; 32],
) -> [u8; SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES] {
    let mut output = [0; SOURCE_PROVIDER_SECURITY_MANIFEST_BYTES];
    output[..8].copy_from_slice(b"AOSPSEC1");
    put_u16(&mut output, 8, 1);
    output[10] = SourceProviderSecurityRoleV1::RootMount as u8;
    output[16..32].copy_from_slice(&[5; 16]);
    output[32..48].copy_from_slice(&[16; 16]);
    put_u16(&mut output, 48, 1);
    put_u64(&mut output, 52, 1);
    put_u64(&mut output, 60, 1);
    output[68..100].copy_from_slice(trust_digest.as_bytes());
    put_u64(&mut output, 100, 1);
    output[108..140].copy_from_slice(revocation_digest.as_bytes());
    output[140..156].copy_from_slice(&[6; 16]);
    put_u64(&mut output, 156, 1);
    output[164..196].copy_from_slice(&[9; 32]);
    output[196] = 0x0f;
    for (index, signer) in signers.iter().enumerate() {
        encode_signer(&mut output[204 + index * 120..324 + index * 120], signer);
    }
    output[684..716].copy_from_slice(&trust_sha256);
    output[716..748].copy_from_slice(&route_sha256);
    output
}

fn encode_signer(output: &mut [u8], signer: &SourceProviderSigningKeyV1) {
    output[..16].copy_from_slice(&signer.authority_id());
    put_u64(output, 16, signer.authority_generation());
    output[24..56].copy_from_slice(signer.authority_digest().as_bytes());
    output[56..72].copy_from_slice(&signer.key_id());
    put_u64(output, 72, signer.key_generation());
    output[80..112].copy_from_slice(signer.public_key_digest().as_bytes());
    output[112] = signer.usage() as u8;
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn put_i64(output: &mut [u8], offset: usize, value: i64) {
    output[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn install_role(
    directory: &Path,
    role: SourceProviderSecurityRoleV1,
    credentials: &CredentialBundle,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(directory.parent().ok_or("missing role parent")?)?;
    fs::create_dir(directory)?;

    let mut manifest = credentials.manifest;
    manifest[10] = role as u8;
    write_protected(directory, "source-provider-manifest", &manifest)?;
    write_protected(directory, "source-provider-trust", &credentials.trust)?;
    write_protected(directory, "current-route", &credentials.route)?;

    let local = match role {
        SourceProviderSecurityRoleV1::RootMount => [
            ("root-mount-hello-signing-key", 0),
            ("root-mount-record-signing-key", 2),
        ],
        SourceProviderSecurityRoleV1::Provider => [
            ("provider-hello-signing-key", 1),
            ("provider-outcome-signing-key", 3),
        ],
    };
    for (name, index) in local {
        write_protected(directory, name, &credentials.secrets[index])?;
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o550))?;
    let metadata = fs::metadata(directory)?;
    if metadata.uid() != 0
        || metadata.gid() != rustix::process::getegid().as_raw()
        || metadata.mode() & 0o7777 != 0o550
    {
        return Err("role directory has incorrect ownership or mode".into());
    }
    Ok(())
}

fn write_protected(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let path = directory.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o440))?;
    let metadata = file.metadata()?;
    if metadata.uid() != 0
        || metadata.gid() != rustix::process::getegid().as_raw()
        || metadata.mode() & 0o7777 != 0o440
        || metadata.nlink() != 1
    {
        return Err("credential file has incorrect ownership or mode".into());
    }
    Ok(())
}

fn install_backend_verifiers(directory: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(directory.parent().ok_or("missing backend parent")?)?;
    fs::create_dir(directory)?;
    write_protected(directory, "current-verifiers", &backend_verifier_manifest())?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o550))?;
    let metadata = fs::metadata(directory)?;
    if metadata.uid() != 0
        || metadata.gid() != rustix::process::getegid().as_raw()
        || metadata.mode() & 0o7777 != 0o550
    {
        return Err("backend verifier directory has incorrect ownership or mode".into());
    }
    Ok(())
}

fn backend_verifier_manifest() -> [u8; BACKEND_MANIFEST_BYTES] {
    let mut output = [0; BACKEND_MANIFEST_BYTES];
    output[..8].copy_from_slice(b"AOSSPBV1");
    put_u16(&mut output, 8, 1);
    output[10] = 6;

    for index in 0..6 {
        let offset = 16 + index * 152;
        let identity = index as u8 + 31;
        let signing_key = SigningKey::from_bytes(&[identity; 32]);
        let public_key = signing_key.verifying_key().to_bytes();

        output[offset] = index as u8 + 1;
        output[offset + 8..offset + 24].copy_from_slice(&[identity; 16]);
        put_u64(&mut output, offset + 24, 1);
        output[offset + 32..offset + 64].copy_from_slice(&[identity + 20; 32]);
        output[offset + 64..offset + 80].copy_from_slice(&[identity + 10; 16]);
        put_u64(&mut output, offset + 80, 1);
        output[offset + 88..offset + 120].copy_from_slice(&public_key);
        output[offset + 120..offset + 152].copy_from_slice(&Sha256::digest(public_key));
    }
    output
}

fn publish_catalog(
    credentials: &CredentialBundle,
    binding_hex: &str,
    publication_path: &Path,
    held_rows_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let binding = parse_binding_digest(binding_hex)?;
    let (publication, held_rows) = catalog_artifacts(credentials, binding)?;
    write_output(publication_path, &publication)?;
    write_output(held_rows_path, &held_rows)?;
    println!("source-provider-native-catalog:PASS");
    Ok(())
}

fn parse_binding_digest(value: &str) -> Result<ObjectDigest, Box<dyn Error>> {
    if value.len() != 64 || !value.is_ascii() {
        return Err("binding digest must be exactly 64 hexadecimal characters".into());
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    if bytes == [0; 32] {
        return Err("binding digest cannot be zero".into());
    }
    Ok(ObjectDigest::from_bytes(bytes))
}

fn catalog_artifacts(
    credentials: &CredentialBundle,
    binding: ObjectDigest,
) -> Result<([u8; 520], Vec<u8>), Box<dyn Error>> {
    let snapshot = ZfsHeldSnapshotProofV1::new(
        [70; 32],
        1,
        11,
        12,
        13,
        [71; 16],
        1,
        ObjectDigest::from_bytes([72; 32]),
        ObjectDigest::from_bytes([73; 32]),
        ObjectDigest::from_bytes([74; 32]),
    )?;
    let row = ProviderHeldSnapshotRowV1::new(
        binding,
        [75; 32],
        1,
        ObjectDigest::from_bytes([76; 32]),
        1,
        ObjectDigest::from_bytes([77; 32]),
        snapshot,
    )?;
    let catalog =
        ProviderHeldSnapshotCatalogV1::new(1, ObjectDigest::from_bytes([10; 32]), vec![row])?;
    let held_rows = catalog.to_canonical_bytes();
    if ProviderHeldSnapshotCatalogV1::from_canonical_bytes(&held_rows)? != catalog {
        return Err("held snapshot catalog did not round trip canonically".into());
    }
    catalog.select_under_head(
        1,
        catalog.digest(),
        ObjectDigest::from_bytes([10; 32]),
        binding,
    )?;

    let mut publication = [0; 520];
    publication[..8].copy_from_slice(b"AOSPCP01");
    put_u16(&mut publication, 8, 2);
    publication[16..32].copy_from_slice(&[2; 16]);
    put_u64(&mut publication, 32, 1);
    publication[40..72].copy_from_slice(&[8; 32]);
    publication[72..104].copy_from_slice(&[10; 32]);
    put_u64(&mut publication, 104, 1);
    publication[112..144].copy_from_slice(catalog.digest().as_bytes());
    publication[144..160].copy_from_slice(&credentials.publisher.authority_id());
    put_u64(&mut publication, 160, 1);
    put_u64(&mut publication, 208, 1);
    publication[216..248].copy_from_slice(catalog.digest().as_bytes());
    put_i64(&mut publication, 248, 1);
    put_u64(&mut publication, 256, 1);
    publication[264..296].copy_from_slice(credentials.trust_digest.as_bytes());
    put_u64(&mut publication, 296, 1);
    publication[304..336].copy_from_slice(&[15; 32]);
    encode_signer(&mut publication[336..456], &credentials.publisher);

    let mut message = b"aos.sandbox.source-provider.catalog-publication.v1\0".to_vec();
    message.extend_from_slice(&publication[..456]);
    let signature = SigningKey::from_bytes(&[17; 32]).sign(&message);
    publication[456..520].copy_from_slice(&signature.to_bytes());
    Ok((publication, held_rows))
}

fn write_output(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o440))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_role_records_decode_without_root() {
        let credentials =
            render(current_cgroup_digest(b"0::/vm/qualification\n").unwrap()).unwrap();
        let mut root_manifest = credentials.manifest;
        root_manifest[10] = SourceProviderSecurityRoleV1::RootMount as u8;
        let mut provider_manifest = credentials.manifest;
        provider_manifest[10] = SourceProviderSecurityRoleV1::Provider as u8;

        assert_eq!(
            SourceProviderSecurityManifestV1::decode(&root_manifest)
                .unwrap()
                .role(),
            SourceProviderSecurityRoleV1::RootMount,
        );
        assert_eq!(
            SourceProviderSecurityManifestV1::decode(&provider_manifest)
                .unwrap()
                .role(),
            SourceProviderSecurityRoleV1::Provider,
        );
        assert_eq!(
            SourceProviderTrustFileV1::decode(&credentials.trust)
                .unwrap()
                .trust_set()
                .keys()
                .len(),
            5,
        );
        assert!(
            SourceProviderTrustFileV1::decode(&credentials.trust)
                .unwrap()
                .trust_set()
                .keys()
                .iter()
                .any(|key| key.signer() == &credentials.publisher
                    && key.state() == SourceProviderKeyTrustStateV1::Eligible)
        );
        assert!(SourceProviderRouteFileV1::decode(&credentials.route).is_ok());
        assert_ne!(credentials.secrets[0], credentials.secrets[2]);
        assert_ne!(credentials.secrets[1], credentials.secrets[3]);
        let backend = backend_verifier_manifest();
        assert_eq!(&backend[..8], b"AOSSPBV1");
        assert_eq!(backend.len(), BACKEND_MANIFEST_BYTES);
        assert!((0..6).all(|index| backend[16 + index * 152] == index as u8 + 1));

        let binding = ObjectDigest::from_bytes([81; 32]);
        let (publication, held_rows) = catalog_artifacts(&credentials, binding).unwrap();
        let catalog = ProviderHeldSnapshotCatalogV1::from_canonical_bytes(&held_rows).unwrap();
        assert_eq!(&publication[..8], b"AOSPCP01");
        assert_eq!(&publication[112..144], catalog.digest().as_bytes());
        let mut message = b"aos.sandbox.source-provider.catalog-publication.v1\0".to_vec();
        message.extend_from_slice(&publication[..456]);
        let signature =
            ed25519_dalek::Signature::from_bytes(&publication[456..520].try_into().unwrap());
        SigningKey::from_bytes(&[17; 32])
            .verifying_key()
            .verify_strict(&message, &signature)
            .unwrap();
        assert!(
            catalog
                .select_under_head(
                    1,
                    catalog.digest(),
                    ObjectDigest::from_bytes([10; 32]),
                    binding
                )
                .is_ok()
        );
    }
}
