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

use aos_registry_hub::surface::object::{
    encode_loose, encode_tree, hash_object, ObjectKind, Oid, TreeEntry,
};
use aos_registry_hub::surface::sshsig;
use aos_registry_hub::surface::tag::render_tag_payload;
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
    pub fn put_nix_cache(&self) {
        fs::write(
            self.root.join("nix-cache-info"),
            "StoreDir: /var/lib/store\nPriority: 40\n",
        )
        .unwrap();
        fs::write(
            self.root.join("h7j3k8l2m9n4.narinfo"),
            "StorePath: /var/lib/store/h7j3k8l2m9n4-curl-8.5.0\nURL: nar/h7j3k8l2m9n4.nar.zst\n\
             Compression: zstd\nNarHash: sha256:aa\nNarSize: 10\nReferences: \n",
        )
        .unwrap();
        fs::create_dir_all(self.root.join("nar")).unwrap();
        fs::write(
            self.root.join("nar/h7j3k8l2m9n4.nar.zst"),
            b"not-a-real-nar",
        )
        .unwrap();
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
    let fixture = Fixture::new(root);

    let registry_toml = fixture.put_blob(
        "[registry]\nname = \"demo\"\ndescription = \"Fixture registry\"\n\n\
         [[caches]]\nurl = \"https://cache.example.com/\"\npriority = 40\n",
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

    let commit = fixture.put_signed_commit(root_tree, &format!("release {semver}"));
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
