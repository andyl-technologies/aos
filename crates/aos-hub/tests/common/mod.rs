//! Fixture registry surfaces for integration tests.
//!
//! Builds a complete, *correctly signed* registry surface on disk — loose
//! objects, refs, channel partitions, and nix-cache files — using only the
//! hub's own primitives plus `ed25519-dalek`. This is the seed of the
//! parser-divergence fixture set from RFC-0004's testing story: the same
//! directories are valid input for `apm` (they are exactly what
//! `apr origin upload` would have written).

use std::fs;
use std::path::{Path, PathBuf};

use aos_hub::surface::object::{
    encode_loose, encode_tree, hash_object, ObjectKind, Oid, TreeEntry,
};
use aos_hub::surface::sshsig;
use aos_hub::surface::tag::render_tag_payload;
use ed25519_dalek::SigningKey;

/// A registry fixture being assembled on disk.
pub struct Fixture {
    /// Surface root directory.
    pub root: PathBuf,
    /// The maintainer signing key.
    pub key: SigningKey,
    /// The trust anchor line for the key.
    pub trust_key: String,
}

impl Fixture {
    /// Create an empty fixture rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let trust_key = sshsig::trusted_key_line("demo", &key.verifying_key());
        Self {
            root: root.into(),
            key,
            trust_key,
        }
    }

    /// Write one loose object and return its oid.
    pub fn put_object(&self, kind: ObjectKind, content: &[u8]) -> Oid {
        let oid = hash_object(kind, content);
        let path = self.root.join(oid.loose_path());
        fs::create_dir_all(path.parent().expect("loose path has parent")).unwrap();
        fs::write(path, encode_loose(kind, content).unwrap()).unwrap();
        oid
    }

    /// Write a blob and return its oid.
    pub fn put_blob(&self, content: &str) -> Oid {
        self.put_object(ObjectKind::Blob, content.as_bytes())
    }

    /// Write a tree from `(mode, name, oid)` entries and return its oid.
    pub fn put_tree(&self, entries: &[(&str, &str, Oid)]) -> Oid {
        let entries: Vec<TreeEntry> = entries
            .iter()
            .map(|(mode, name, oid)| TreeEntry {
                mode: (*mode).to_string(),
                name: (*name).to_string(),
                oid: *oid,
            })
            .collect();
        self.put_object(ObjectKind::Tree, &encode_tree(&entries))
    }

    /// Write a signed commit over `tree` and return its oid.
    pub fn put_signed_commit(&self, tree: Oid, message: &str) -> Oid {
        let ident = "AOS Test <test@aos> 1770000000 +0000";
        let unsigned = format!("tree {tree}\nauthor {ident}\ncommitter {ident}\n\n{message}\n");
        let armor = sshsig::sign_armored(unsigned.as_bytes(), &self.key);
        // The armored signature becomes a multi-line gpgsig-sha256 header
        // (the SHA-256-repo form real git writes) with
        // continuation lines prefixed by one space.
        let mut armor_lines = armor.lines();
        let first = armor_lines.next().expect("armor has lines");
        let mut gpgsig = format!("gpgsig-sha256 {first}\n");
        for line in armor_lines {
            gpgsig.push(' ');
            gpgsig.push_str(line);
            gpgsig.push('\n');
        }
        let signed =
            format!("tree {tree}\nauthor {ident}\ncommitter {ident}\n{gpgsig}\n{message}\n");
        self.put_object(ObjectKind::Commit, signed.as_bytes())
    }

    /// Render and sign a tag payload; returns the raw payload bytes.
    pub fn signed_tag_payload(&self, name: &str, target: Oid, target_type: &str) -> Vec<u8> {
        let body =
            render_tag_payload(name, &target.to_hex(), target_type, "fixture", 1770000000).unwrap();
        let armor = sshsig::sign_armored(body.as_bytes(), &self.key);
        format!("{body}{armor}\n").into_bytes()
    }

    /// Write a signed release tag as a loose tag object; returns its oid.
    pub fn put_release_tag(&self, semver: &str, commit: Oid) -> Oid {
        let payload = self.signed_tag_payload(semver, commit, "commit");
        self.put_object(ObjectKind::Tag, &payload)
    }

    /// Write all 256 channel partition payloads pointing at one release tag.
    pub fn put_channel(&self, channel: &str, release_tag: Oid) {
        let payload = self.signed_tag_payload(channel, release_tag, "tag");
        let dir = self.root.join("channels").join(channel);
        fs::create_dir_all(&dir).unwrap();
        for bucket in 0u16..=255 {
            fs::write(dir.join(format!("{bucket:02x}")), &payload).unwrap();
        }
    }

    /// Write `HEAD` and `info/refs` for the given branches and tags.
    pub fn put_refs(
        &self,
        default_branch: &str,
        branches: &[(&str, Oid)],
        tags: &[(&str, Oid, Oid)],
    ) {
        fs::write(
            self.root.join("HEAD"),
            format!("ref: refs/heads/{default_branch}\n"),
        )
        .unwrap();
        let mut refs = String::new();
        for (name, oid) in branches {
            refs.push_str(&format!("{oid}\trefs/heads/{name}\n"));
        }
        for (name, tag_oid, peeled) in tags {
            refs.push_str(&format!("{tag_oid}\trefs/tags/{name}\n"));
            refs.push_str(&format!("{peeled}\trefs/tags/{name}^{{}}\n"));
        }
        fs::create_dir_all(self.root.join("info")).unwrap();
        fs::write(self.root.join("info/refs"), refs).unwrap();
    }

    /// Write the static nix-cache surface (`nix-cache-info`, one narinfo,
    /// one NAR file).
    ///
    /// The narinfo is **correctly Ed25519-signed** by the fixture's key under
    /// the registry name `demo` (the same key the roster pins), and the NAR is
    /// an uncompressed payload whose `FileHash`/`NarHash` match its bytes — so
    /// the mirror's mandatory narinfo-signature + NAR-hash verification accepts
    /// it. The `Sig:` is over the Nix narinfo fingerprint, matching
    /// `aos_core`'s narinfo signer.
    pub fn put_nix_cache(&self) {
        fs::write(
            self.root.join("nix-cache-info"),
            "StoreDir: /var/lib/store\nPriority: 40\n",
        )
        .unwrap();

        // A real (tiny) uncompressed NAR payload; FileHash == NarHash over
        // these exact bytes, so the hash check passes.
        use sha2::Digest as _;
        let nar_bytes = b"fixture-nar-bytes-for-curl-8.5.0";
        let digest = sha2::Sha256::digest(nar_bytes);
        let hash = format!("sha256:{}", hex::encode(digest));
        let store_path = "/var/lib/store/h7j3k8l2m9n4-curl-8.5.0";
        // The conventional `nar/<store-hash>-<nar-hash>.<ext>` layout, so the
        // pull-through can derive the narinfo path from the NAR path.
        let nar_url = "nar/h7j3k8l2m9n4-fixturehash.nar";

        let body = self.signed_narinfo(store_path, nar_url, &hash, nar_bytes.len() as u64, &[]);
        fs::write(self.root.join("h7j3k8l2m9n4.narinfo"), body).unwrap();

        fs::create_dir_all(self.root.join("nar")).unwrap();
        fs::write(self.root.join(nar_url), nar_bytes).unwrap();
    }

    /// Write a *zstd-compressed* nix-cache entry: a signed narinfo declaring
    /// `Compression: zstd` whose signed `NarHash` is over the **uncompressed**
    /// NAR, plus the compressed NAR file on disk.
    ///
    /// `tamper_compressed` injects the CR-1 attack: when set, the on-disk NAR is
    /// replaced with `tampered_plain` compressed with zstd, and the narinfo's
    /// (unsigned) `FileHash` is set to match those malicious *compressed* bytes —
    /// so a verifier that trusted `FileHash` would accept it, but the decompressed
    /// bytes do not match the signed `NarHash`. The signed fields (`NarHash`,
    /// `StorePath`, `NarSize`, `Sig:`) are unchanged, exactly as a MITM upstream
    /// would keep them.
    ///
    /// Returns `(narinfo_relative_path, nar_relative_path)`.
    ///
    /// The store hash is unique per `tag` so multiple entries can coexist.
    // Not every test binary that compiles this shared module calls this builder
    // (the same pre-existing pattern as the other fixture helpers).
    #[allow(dead_code)]
    pub fn put_zstd_nix_entry(
        &self,
        tag: &str,
        plain: &[u8],
        tamper_compressed: Option<&[u8]>,
    ) -> (String, String) {
        use base64::Engine as _;
        use sha2::Digest as _;

        let store_hash = format!("zstdhash{tag}");
        let store_path = format!("/var/lib/store/{store_hash}-pkg-1.0");
        let nar_url = format!("nar/{store_hash}-fixturehash.nar.zst");

        // The signed NarHash is over the UNCOMPRESSED bytes.
        let nar_hash = format!("sha256:{}", hex::encode(sha2::Sha256::digest(plain)));
        let nar_size = plain.len() as u64;

        // The bytes actually written to disk (and the compressed bytes FileHash
        // is computed over): the honest compression of `plain`, unless tampering.
        let honest_compressed = zstd::encode_all(plain, 0).unwrap();
        let (on_disk, file_source): (Vec<u8>, Vec<u8>) = match tamper_compressed {
            Some(evil_plain) => {
                let evil = zstd::encode_all(evil_plain, 0).unwrap();
                (evil.clone(), evil)
            }
            None => (honest_compressed.clone(), honest_compressed),
        };
        let file_hash = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&file_source)));
        let file_size = on_disk.len() as u64;

        // Sign the fingerprint over the (uncompressed) NarHash, as a real signer
        // would — the signature is independent of the compressed payload.
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(&self.key.to_bytes());
        secret.extend_from_slice(self.key.verifying_key().as_bytes());
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(&secret);
        let signer =
            aos_core::nar::cache::NarInfoSigner::from_key_content(&format!("demo:{secret_b64}"))
                .unwrap();
        let fingerprint = aos_core::nar::cache::NarInfoSigner::fingerprint(
            &store_path,
            &nar_hash,
            nar_size as i64,
            &[],
        );
        let sig = signer.sign(&fingerprint).unwrap();

        let narinfo = format!(
            "StorePath: {store_path}\nURL: {nar_url}\nCompression: zstd\n\
             FileHash: {file_hash}\nFileSize: {file_size}\nNarHash: {nar_hash}\nNarSize: {nar_size}\n\
             References: \nSig: {sig}\n",
        );
        let narinfo_path = format!("{store_hash}.narinfo");
        fs::write(self.root.join(&narinfo_path), narinfo).unwrap();
        fs::create_dir_all(self.root.join("nar")).unwrap();
        fs::write(self.root.join(&nar_url), &on_disk).unwrap();
        (narinfo_path, nar_url)
    }

    /// Render a narinfo for an *uncompressed* NAR and sign it with the
    /// fixture's key under the registry name (so its `Sig:` verifies against
    /// the roster).
    ///
    /// `hash` is the `sha256:<hex>` digest of the NAR bytes, used for both
    /// `NarHash` and `FileHash` (uncompressed, so they coincide). `refs` are
    /// full store paths referenced by this path.
    pub fn signed_narinfo(
        &self,
        store_path: &str,
        nar_url: &str,
        hash: &str,
        size: u64,
        refs: &[String],
    ) -> String {
        use base64::Engine as _;

        // The Nix narinfo signing key is name:base64(seed||pubkey); the signer
        // uses the first 32 bytes (the seed) to reproduce the Ed25519 key.
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(&self.key.to_bytes());
        secret.extend_from_slice(self.key.verifying_key().as_bytes());
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(&secret);
        let signer =
            aos_core::nar::cache::NarInfoSigner::from_key_content(&format!("demo:{secret_b64}"))
                .unwrap();

        let fingerprint =
            aos_core::nar::cache::NarInfoSigner::fingerprint(store_path, hash, size as i64, refs);
        let sig = signer.sign(&fingerprint).unwrap();

        let refs_basenames: Vec<&str> = refs
            .iter()
            .map(|r| r.rsplit('/').next().unwrap_or(r))
            .collect();
        format!(
            "StorePath: {store_path}\nURL: {nar_url}\nCompression: none\n\
             FileHash: {hash}\nFileSize: {size}\nNarHash: {hash}\nNarSize: {size}\n\
             References: {}\nSig: {sig}\n",
            refs_basenames.join(" "),
        )
    }
}

/// Build a complete single-package, single-channel registry fixture.
///
/// Layout: `curl 8.5.0` for `x86_64-linux`, release `1.0.0`, channel
/// `stable` fully rolled out, roster with one active key, one committed
/// cache, plus the nix-cache files.
// Not every test binary that compiles this shared module calls this builder
// (the same pre-existing pattern as `standard_registry_versioned`).
#[allow(dead_code)]
pub fn standard_registry(root: &Path) -> Fixture {
    standard_registry_versioned(root, "1.0.0")
}

/// [`standard_registry`] with a configurable release semver, so tests can
/// build surfaces at different (e.g. older) release versions.
// Not every test crate that compiles this module uses the fixture
// builders (the same pre-existing pattern as the rest of this file).
#[allow(dead_code)]
pub fn standard_registry_versioned(root: &Path, semver: &str) -> Fixture {
    standard_registry_with_commit_message(root, semver, &format!("release {semver}"))
}

/// [`standard_registry_versioned`] with an explicit HEAD commit message, so a
/// test can embed an `AOS-Change-Id` trailer (for the indexer's change-request
/// cross-referencing) or otherwise control the committed message.
#[allow(dead_code)]
pub fn standard_registry_with_commit_message(
    root: &Path,
    semver: &str,
    commit_message: &str,
) -> Fixture {
    let fixture = Fixture::new(root);

    let registry_toml = fixture.put_blob(
        "[registry]\nname = \"demo\"\ndescription = \"Fixture registry\"\n\n\
         [caches]\nendpoint = \"https://cache.example.com/\"\n",
    );
    let keys_toml = fixture.put_blob(&format!(
        "schema = 1\n\n[[keys]]\nid = \"maintainer\"\nkey = \"{}\"\n",
        fixture.trust_key,
    ));
    let curl_toml = fixture.put_blob(
        "[package]\nname = \"curl\"\ndescription = \"URL transfers\"\nlicense = \"MIT\"\n\
         maintainer = \"aos\"\n\n[[versions]]\nversion = \"8.5.0\"\n\n\
         [versions.platforms.x86_64-linux]\nstore_path = \"/var/lib/store/h7j3k8l2m9n4-curl-8.5.0\"\n\
         nar_hash = \"sha256:aa\"\nnar_size = 10\nclosure_size = 20\n\
         source_drv = \"/var/lib/store/h7j3k8l2m9n4-curl-8.5.0.drv\"\n\
         source_nar_hash = \"sha256:bb\"\nreferences = []\n",
    );
    let closure_blob = fixture.put_blob("h7j3k8l2m9n4\n");

    let bucket_c = fixture.put_tree(&[("100644", "curl.toml", curl_toml)]);
    let packages = fixture.put_tree(&[("40000", "c", bucket_c)]);
    let closures = fixture.put_tree(&[("100644", "h7j3k8l2m9n4", closure_blob)]);
    let root_tree = fixture.put_tree(&[
        ("100644", "keys.toml", keys_toml),
        ("100644", "registry.toml", registry_toml),
        ("40000", "closures", closures),
        ("40000", "packages", packages),
    ]);

    let commit = fixture.put_signed_commit(root_tree, commit_message);
    let release_tag = fixture.put_release_tag(semver, commit);
    fixture.put_channel("stable", release_tag);
    fixture.put_refs(
        "stable",
        &[("stable", commit)],
        &[(semver, release_tag, commit)],
    );
    fixture.put_nix_cache();
    fixture
}
