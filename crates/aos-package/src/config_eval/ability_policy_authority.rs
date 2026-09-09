//! Protected operator authorization for native physical-resource policy.
//!
//! A package or evaluator may produce planning policy bytes, but native
//! execution additionally requires an exact sidecar descriptor in this
//! machine-global, root-owned authority store. Authorization is loaded afresh
//! before activation or recovery, and dispatchers must recheck it before every
//! later operation admission. Removing a record does not interrupt an operation
//! that has already crossed its durable admission boundary.
//!
//! ```json
//! {"policy_set":{"document":"policy.json","document_sha256":"sha256:<64-hex>","document_size":1,"nar_hash":"sha256:<52-nix-base32>","nar_size":1,"store_path":"/nix/store/...-policy"},"schema":"aos.ability.operator-policy-authority/v1"}
//! ```

use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use aos_ability_model::ABILITY_LIMITS_V1;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::materialize::PinnedAbilitySidecar;
use super::native_ability_fs::RootedDirectory;

/// Machine-global directory containing independently provisioned policy grants.
pub const OPERATOR_POLICY_AUTHORITY_ROOT: &str = "/var/lib/aos/ability-authority/policy-sets";

/// Binds operator authorization to one exact immutable policy-set sidecar.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorPolicyAuthorityRecord {
    /// Carries [`Self::SCHEMA`].
    pub schema: String,
    /// Pins the complete independently approved policy-set store object.
    pub policy_set: PinnedAbilitySidecar,
}

impl OperatorPolicyAuthorityRecord {
    /// Current protected operator-authority record schema.
    pub const SCHEMA: &'static str = "aos.ability.operator-policy-authority/v1";

    /// Constructs and validates an authority record for an exact sidecar.
    ///
    /// # Errors
    ///
    /// Returns an error when the sidecar descriptor is not canonical and
    /// bounded.
    pub fn new(policy_set: PinnedAbilitySidecar) -> Result<Self> {
        policy_set.validate("operator-authorized policy set")?;
        Ok(Self {
            schema: Self::SCHEMA.to_string(),
            policy_set,
        })
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == Self::SCHEMA,
            "unsupported operator policy-authority schema {:?}",
            self.schema
        );
        self.policy_set.validate("operator-authorized policy set")
    }

    fn file_name(&self) -> Result<String> {
        Ok(format!(
            "{}.json",
            Sha256Digest::parse(&self.policy_set.document_sha256)
                .context("decoding operator-authorized policy document identity")?
                .hex()
        ))
    }

    /// Encodes the exact canonical record bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or canonical encoding fails.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        aos_contract::canonical::to_vec(self).context("encoding operator policy authority")
    }
}

/// Reads and provisions records beneath one protected authority root.
pub struct OperatorPolicyAuthorityStore {
    root_path: PathBuf,
    trusted_owner: u32,
}

impl OperatorPolicyAuthorityStore {
    /// Opens the machine-global root-owned authority store.
    ///
    /// # Errors
    ///
    /// Returns an error when the authority root or any ancestor is missing,
    /// linked, writable by another identity, or not owned by root.
    pub fn open() -> Result<Self, io::Error> {
        Self::open_at(Path::new(OPERATOR_POLICY_AUTHORITY_ROOT), 0)
    }

    fn open_at(path: &Path, trusted_owner: u32) -> Result<Self, io::Error> {
        RootedDirectory::open(path, trusted_owner, "operator policy authority root")?;
        Ok(Self {
            root_path: path.to_path_buf(),
            trusted_owner,
        })
    }

    /// Loads fresh operator authorization for the candidate policy descriptor.
    ///
    /// The record is addressed by the candidate document digest and the full
    /// descriptor must then match. Removal or replacement therefore takes
    /// effect at the next activation or recovery load.
    ///
    /// # Errors
    ///
    /// Returns an error when the candidate digest is invalid, the protected
    /// record is absent or unsafe, its JSON is noncanonical or malformed, or
    /// it authorizes a different descriptor.
    pub fn authorize(
        &self,
        candidate: &PinnedAbilitySidecar,
    ) -> Result<OperatorPolicyAuthorityRecord> {
        candidate.validate("candidate policy set")?;
        let expected = OperatorPolicyAuthorityRecord::new(candidate.clone())?;
        let root = RootedDirectory::open(
            &self.root_path,
            self.trusted_owner,
            "operator policy authority root",
        )?;
        let path = root.resolve(Path::new(&expected.file_name()?))?;
        let bytes = path.read(ABILITY_LIMITS_V1.max_document_bytes)?;
        let record: OperatorPolicyAuthorityRecord = aos_contract::limits::JsonLimits {
            max_bytes: ABILITY_LIMITS_V1.max_document_bytes as usize,
            max_depth: ABILITY_LIMITS_V1.max_structural_depth as usize + 2,
            max_items: ABILITY_LIMITS_V1.max_collection_items as usize,
            max_string_bytes: ABILITY_LIMITS_V1.max_string_bytes as usize,
        }
        .decode(&bytes, OperatorPolicyAuthorityRecord::SCHEMA)?;
        record.validate()?;
        ensure!(
            record.canonical_bytes()? == bytes,
            "operator policy authority is not exact canonical JSON"
        );
        ensure!(
            record == expected,
            "operator policy authority does not match the candidate policy-set descriptor"
        );
        Ok(record)
    }

    /// Atomically and durably provisions one explicit operator authorization.
    ///
    /// The protected authority directory must already exist; creating that
    /// machine-global trust root remains an installation responsibility.
    ///
    /// # Errors
    ///
    /// Returns an error when the record is invalid, a target or ancestor is
    /// unsafe, or durable atomic publication fails.
    pub fn provision(&self, record: &OperatorPolicyAuthorityRecord) -> Result<()> {
        let bytes = record.canonical_bytes()?;
        let root = RootedDirectory::open(
            &self.root_path,
            self.trusted_owner,
            "operator policy authority root",
        )?;
        let target = root.resolve(Path::new(&record.file_name()?))?;
        target.atomic_write(&bytes, false)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;

    #[test]
    fn protected_authority_requires_exact_full_descriptor_and_fresh_presence() {
        let root = tempfile::tempdir().expect("temporary authority root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("authority root protected");
        let owner = std::fs::metadata(root.path()).expect("root metadata").uid();
        let store = OperatorPolicyAuthorityStore::open_at(root.path(), owner)
            .expect("protected test authority opens");
        let candidate = sidecar("a");
        let record = OperatorPolicyAuthorityRecord::new(candidate.clone()).expect("valid record");
        store.provision(&record).expect("record provisioned");
        assert_eq!(
            store.authorize(&candidate).expect("candidate authorized"),
            record
        );

        let mut changed = candidate.clone();
        changed.store_path = "/nix/store/11111111111111111111111111111111-policy".to_string();
        assert!(store.authorize(&changed).is_err());

        std::fs::remove_file(root.path().join(record.file_name().expect("file name")))
            .expect("authorization revoked");
        assert!(store.authorize(&candidate).is_err());
    }

    #[test]
    fn authorization_reopens_the_current_authority_namespace() {
        let parent = tempfile::tempdir().expect("temporary authority parent");
        let authority = parent.path().join("policy-sets");
        std::fs::create_dir(&authority).expect("authority root created");
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o700))
            .expect("authority root protected");
        let owner = std::fs::metadata(&authority).expect("root metadata").uid();
        let store = OperatorPolicyAuthorityStore::open_at(&authority, owner)
            .expect("protected test authority opens");
        let candidate = sidecar("b");
        let record = OperatorPolicyAuthorityRecord::new(candidate.clone()).expect("valid record");
        store.provision(&record).expect("record provisioned");

        let detached = parent.path().join("detached-policy-sets");
        std::fs::rename(&authority, &detached).expect("old namespace detached");
        std::fs::create_dir(&authority).expect("replacement namespace created");
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o777))
            .expect("replacement namespace made unsafe");

        let error = store
            .authorize(&candidate)
            .expect_err("detached authorized tree must not remain usable");
        assert!(error.to_string().contains("operator policy authority root"));
    }

    fn sidecar(document_byte: &str) -> PinnedAbilitySidecar {
        PinnedAbilitySidecar {
            store_path: "/nix/store/00000000000000000000000000000000-policy".to_string(),
            nar_hash: format!("sha256:{}", "0".repeat(52)),
            nar_size: 1,
            references: Vec::new(),
            document: "policy.json".to_string(),
            document_sha256: format!("sha256:{}", document_byte.repeat(64)),
            document_size: 1,
        }
    }
}
