//! Authenticated native reference reads shared by release admission and browsing.
//!
//! Catalog metadata originates in a verified release tree. Every object read
//! rechecks the signed directory NAR and the exact `options.json` byte identity.

use anyhow::{Context, Result, ensure};
use aos_doc_model::runtime::RuntimeDocument;
use aos_registry_surface::manifest::{NativeArtifactMeta, PackageToml};
use sha2::{Digest, Sha256};

use crate::fetch::SurfaceFetch;

/// Fetches a native reference bound to an exact authenticated release coordinate.
///
/// # Errors
/// Returns an error for missing objects, invalid transport or archive hashes,
/// mismatched references, malformed native declarations, or identity drift.
pub async fn fetch_native_documentation_content(
    fetch: &dyn SurfaceFetch,
    package: &str,
    version: &str,
    platform: &str,
    artifact: &NativeArtifactMeta,
) -> Result<(Vec<u8>, RuntimeDocument)> {
    artifact.validate()?;
    let hash = aos_registry_surface::store::store_path_hash(&artifact.store_path)?;
    let key = format!("{hash}.narinfo");
    let bytes = fetch
        .fetch_bounded(&key, super::MAX_IMAGE_NARINFO_BYTES)
        .await?
        .context("native documentation narinfo is unavailable")?;
    let narinfo = super::parse_documentation_narinfo(std::str::from_utf8(&bytes)?)?;
    let mut references = narinfo.references.clone();
    references.sort();
    ensure!(
        narinfo.store_path == artifact.store_path
            && narinfo.compression == "none"
            && references == artifact.references
            && narinfo.nar_size == artifact.nar_size
            && aos_registry_surface::store::canonical_digest_hex(&narinfo.nar_hash)?
                == aos_registry_surface::store::canonical_digest_hex(&artifact.nar_hash)?,
        "native documentation narinfo differs from its authenticated locator"
    );
    ensure!(
        narinfo.url.starts_with("nar/")
            && narinfo.url.ends_with(".nar")
            && narinfo
                .url
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != ".."),
        "native documentation narinfo URL is unsafe"
    );
    ensure!(
        artifact.nar_size <= 32 * 1024 * 1024,
        "native documentation NAR exceeds its size limit"
    );
    let nar = fetch
        .fetch_bounded(&narinfo.url, usize::try_from(artifact.nar_size)?)
        .await?
        .context("native documentation NAR is unavailable")?;
    let digest = hex::encode(Sha256::digest(&nar));
    ensure!(
        nar.len() as u64 == artifact.nar_size
            && nar.len() as u64 == narinfo.file_size
            && digest == aos_registry_surface::store::canonical_digest_hex(&artifact.nar_hash)?
            && digest == aos_registry_surface::store::canonical_digest_hex(&narinfo.file_hash)?,
        "native documentation archive byte identity differs"
    );
    let document_bytes = aos_doc_model::decode_native_documentation_nar(&nar)?;
    ensure!(
        document_bytes.len() as u64 == artifact.document_size
            && hex::encode(Sha256::digest(document_bytes))
                == aos_registry_surface::store::canonical_digest_hex(&artifact.document_sha256)?,
        "native documentation document byte identity differs"
    );
    let document = RuntimeDocument::from_json(document_bytes)?;
    document.verify_package_identity(package, version, platform)?;
    Ok((document_bytes.to_vec(), document))
}

/// Fetches and checks a native release reference for rendering.
///
/// # Errors
/// Returns the same archive, document, and coordinate errors as the content reader.
pub async fn fetch_native_documentation(
    fetch: &dyn SurfaceFetch,
    package: &str,
    version: &str,
    platform: &str,
    artifact: &NativeArtifactMeta,
) -> Result<RuntimeDocument> {
    Ok(
        fetch_native_documentation_content(fetch, package, version, platform, artifact)
            .await?
            .1,
    )
}

pub(super) async fn verify_native_documentation(
    fetch: &dyn SurfaceFetch,
    packages: &[PackageToml],
) -> Result<Vec<crate::db::NativeDocumentationIndex>> {
    let mut documents = Vec::new();
    for package in packages {
        for version in &package.versions {
            for (platform, entry) in &version.platforms {
                if let Some(artifact) = &entry.module_documentation {
                    let document = fetch_native_documentation(
                        fetch,
                        &package.package.name,
                        &version.version,
                        platform,
                        artifact,
                    )
                    .await?;
                    documents.push(crate::db::NativeDocumentationIndex {
                        package: package.package.name.clone(),
                        version: version.version.clone(),
                        platform: platform.clone(),
                        document_sha256: artifact.document_sha256.clone(),
                        store_path: artifact.store_path.clone(),
                        search: document.search_documents(),
                    });
                }
            }
        }
    }
    Ok(documents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct Fetch(BTreeMap<String, Vec<u8>>);

    #[async_trait::async_trait]
    impl SurfaceFetch for Fetch {
        async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.0.get(path).cloned())
        }

        fn describe(&self) -> String {
            "native-documentation-test".into()
        }
    }

    fn string(nar: &mut Vec<u8>, bytes: &[u8]) {
        nar.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        nar.extend_from_slice(bytes);
        while nar.len() % 8 != 0 {
            nar.push(0);
        }
    }

    #[tokio::test]
    async fn native_admission_rechecks_directory_document_and_release_coordinates() {
        let bytes = br#"{"schema":"aos.module.documentation","scope":["package","sample"],"system":"x86_64-linux","packages":[{"name":"sample","version":"1"}],"options":[],"abilities":{}}"#;
        let mut nar = Vec::new();
        for token in [
            b"nix-archive-1".as_slice(),
            b"(",
            b"type",
            b"directory",
            b"entry",
            b"(",
            b"name",
            b"options.json",
            b"node",
            b"(",
            b"type",
            b"regular",
            b"contents",
            bytes,
            b")",
            b")",
            b")",
        ] {
            string(&mut nar, token);
        }
        let nar_digest = hex::encode(Sha256::digest(&nar));
        let artifact = NativeArtifactMeta {
            store_path: "/nix/store/11111111111111111111111111111111-options".into(),
            nar_hash: format!("sha256:{nar_digest}"),
            nar_size: nar.len() as u64,
            references: Vec::new(),
            document_sha256: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
            document_size: bytes.len() as u64,
        };
        let narinfo = format!(
            "StorePath: {}\nURL: nar/options.nar\nCompression: none\nFileHash: {}\nFileSize: {}\nNarHash: {}\nNarSize: {}\nReferences: \n",
            artifact.store_path,
            artifact.nar_hash,
            artifact.nar_size,
            artifact.nar_hash,
            artifact.nar_size
        );
        let mut fetch = Fetch(BTreeMap::from([
            (
                "11111111111111111111111111111111.narinfo".into(),
                narinfo.into_bytes(),
            ),
            ("nar/options.nar".into(), nar),
        ]));

        let document = fetch_native_documentation(&fetch, "sample", "1", "x86_64-linux", &artifact)
            .await
            .unwrap();
        assert_eq!(document.reference().unwrap().packages[0].version, "1");
        assert!(
            fetch_native_documentation(&fetch, "sample", "2", "x86_64-linux", &artifact)
                .await
                .is_err()
        );
        assert!(
            fetch_native_documentation(&fetch, "sample", "1", "aarch64-linux", &artifact)
                .await
                .is_err()
        );

        fetch.0.get_mut("nar/options.nar").unwrap().push(0);
        assert!(
            fetch_native_documentation(&fetch, "sample", "1", "x86_64-linux", &artifact)
                .await
                .is_err()
        );
    }
}
