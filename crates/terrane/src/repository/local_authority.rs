//! Persists local signing authority outside the registered bucket namespace.
//!
//! The private sibling directory contains raw Ed25519 `issuer.seed` and
//! `terminal.seed` files, a canonical public `token.cbor`, and private retained
//! administrative configuration. The retention modules preserve original
//! physical bindings and policy independently of mutable credentials. No keys
//! are added to the role, store, or exposure grammar.

use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use terrane_core::auth::{self, Authority, IssuerKey, Token};

use crate::store::LocalFs;

use super::Error;

pub(crate) mod import_binding;
mod native;
pub(crate) mod public_trust;
pub(crate) mod retention;

pub(super) use native::NativeRetention;

/// Supplies explicit identity and ownership for a new local authority.
pub struct LocalAuthorityParameters {
    /// Existing v1 authority fields, including grants and validity interval.
    pub authority: Authority,
    /// Expected Unix owner of the private directory and its credential files.
    pub owner_uid: u32,
}

/// Supplies trusted identity and ownership when reopening local authority.
pub struct LocalAuthorityIdentity {
    /// Configured issuer name, independent of the token's claims.
    pub issuer: String,
    /// Configured issuer rotation key identifier.
    pub key_id: String,
    /// Expected Unix owner of the authority directory and credential files.
    pub owner_uid: u32,
}

/// Holds a validated local capability and its private terminal signing seed.
///
/// This object is repository authority, never a surface credential. It does
/// not implement `Debug` because its signing seed must not enter diagnostics.
pub struct LocalAuthority {
    issuer: IssuerKey,
    token: Vec<u8>,
    terminal_secret: [u8; 32],
    directory: PathBuf,
}

impl LocalAuthority {
    /// Creates a private sibling authority directory without replacing files.
    ///
    /// Failure can leave a private incomplete directory. A subsequent initialize
    /// call refuses it, and [`Self::open`] refuses missing or incompatible files.
    ///
    /// # Errors
    /// Rejects overlapping or nonsibling paths, symlink ancestors, existing
    /// authority state, wrong ownership, invalid token fields, entropy failures,
    /// and failed durable filesystem operations.
    pub async fn initialize<F: LocalFs + Sync>(
        fs: &F,
        bucket: &Path,
        directory: &Path,
        parameters: LocalAuthorityParameters,
    ) -> Result<Self, Error> {
        validate_siblings(bucket, directory)?;
        validate_ancestors(fs, directory).await?;
        validate_bucket(fs, bucket).await?;

        let issuer_secret = random_seed(fs).await?;
        let terminal_secret = random_seed(fs).await?;
        let issuer = IssuerKey {
            issuer: parameters.authority.issuer.clone(),
            key_id: parameters.authority.key_id.clone(),
            public_key: auth::public_key_from_secret(&issuer_secret),
            retirement: None,
        };
        let token = Token::issue(
            parameters.authority,
            &issuer_secret,
            auth::public_key_from_secret(&terminal_secret),
        )
        .map_err(|_| Error::Denied)?
        .encode();

        fs.create_dir_new(directory).await?;
        validate_private_directory(fs, directory, parameters.owner_uid).await?;
        write_private(fs, &directory.join("issuer.seed"), &issuer_secret).await?;
        write_private(fs, &directory.join("terminal.seed"), &terminal_secret).await?;
        // The canonical token is installed last. Reopen requires all three
        // files and validates their cryptographic relationship.
        write_private(fs, &directory.join("token.cbor"), &token).await?;
        fs.sync_directory(directory).await?;
        fs.sync_directory(directory.parent().ok_or(Error::PathEscape)?)
            .await?;

        Ok(Self {
            issuer,
            token,
            terminal_secret,
            directory: directory.to_path_buf(),
        })
    }

    /// Reopens existing private credentials and authenticates their exact token.
    ///
    /// The issuer name and key identifier are trusted caller configuration;
    /// token claims do not choose which issuer the repository trusts.
    ///
    /// # Errors
    /// Rejects incompatible paths, absent or unsafe files, wrong ownership or
    /// permissions, malformed seeds, mismatched signing keys, invalid canonical
    /// tokens, expired authority, and filesystem failures.
    pub async fn open<F: LocalFs + Sync>(
        fs: &F,
        bucket: &Path,
        directory: &Path,
        identity: &LocalAuthorityIdentity,
        now: u64,
    ) -> Result<Self, Error> {
        validate_siblings(bucket, directory)?;
        validate_ancestors(fs, directory).await?;
        validate_bucket(fs, bucket).await?;
        validate_private_directory(fs, directory, identity.owner_uid).await?;
        let issuer_secret =
            read_seed(fs, &directory.join("issuer.seed"), identity.owner_uid).await?;
        let terminal_secret =
            read_seed(fs, &directory.join("terminal.seed"), identity.owner_uid).await?;
        let token_path = directory.join("token.cbor");
        validate_private_file(fs, &token_path, identity.owner_uid).await?;
        let token = fs.read_nofollow(&token_path).await?;
        let issuer = IssuerKey {
            issuer: identity.issuer.clone(),
            key_id: identity.key_id.clone(),
            public_key: auth::public_key_from_secret(&issuer_secret),
            retirement: None,
        };
        let decoded = Token::decode(&token).map_err(|_| Error::Denied)?;
        decoded
            .verify(std::slice::from_ref(&issuer), now)
            .map_err(|_| Error::Denied)?;
        if decoded.signing_public_key() != auth::public_key_from_secret(&terminal_secret) {
            return Err(Error::Denied);
        }

        Ok(Self {
            issuer,
            token,
            terminal_secret,
            directory: directory.to_path_buf(),
        })
    }

    /// Returns the configured public issuer key for the repository guard.
    pub fn issuer_key(&self) -> &IssuerKey {
        &self.issuer
    }

    /// Returns the canonical exposure capability without any private seed.
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// Returns the token file referenced by the existing exposure grammar.
    pub fn token_path(&self) -> PathBuf {
        self.directory.join("token.cbor")
    }

    /// Creates an unsigned proposal carrying this authority's signing proof.
    ///
    /// The proposal has no staged uploads or existing-object disclosure proofs.
    /// Repository publication still performs complete current-policy admission;
    /// creating a proposal does not authorize or publish any content.
    pub fn commit_request(
        &self,
        commit: terrane_core::refs::Commit,
        surface: String,
    ) -> crate::ref_advance::CommitRequest {
        crate::ref_advance::CommitRequest {
            commit,
            uploads: Vec::new(),
            token: self.token.clone(),
            terminal_secret: self.terminal_secret,
            surface,
            reference_records: Vec::new(),
            disclosures: Vec::new(),
        }
    }
}

fn validate_siblings(bucket: &Path, authority: &Path) -> Result<(), Error> {
    if bucket == authority
        || !bucket.is_absolute()
        || !authority.is_absolute()
        || bucket.file_name().is_none()
        || authority.file_name().is_none()
        || bucket.parent() != authority.parent()
        || [bucket, authority].iter().any(|path| {
            path.components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        })
    {
        return Err(Error::PathEscape);
    }
    Ok(())
}

async fn validate_ancestors<F: LocalFs + Sync>(fs: &F, path: &Path) -> Result<(), Error> {
    let parent = path.parent().ok_or(Error::PathEscape)?;
    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component.as_os_str());
        let metadata = fs.symlink_metadata(&current).await?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::PathEscape);
        }
    }
    Ok(())
}

async fn validate_private_directory<F: LocalFs + Sync>(
    fs: &F,
    directory: &Path,
    owner_uid: u32,
) -> Result<(), Error> {
    let metadata = fs.symlink_metadata(directory).await?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(Error::Denied);
    }
    Ok(())
}

async fn validate_bucket<F: LocalFs + Sync>(fs: &F, bucket: &Path) -> Result<(), Error> {
    match fs.symlink_metadata(bucket).await {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(Error::PathEscape),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn validate_private_file<F: LocalFs + Sync>(
    fs: &F,
    path: &Path,
    owner_uid: u32,
) -> Result<(), Error> {
    let metadata = fs.symlink_metadata(path).await?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(Error::Denied);
    }
    Ok(())
}

async fn random_seed<F: LocalFs + Sync>(fs: &F) -> Result<[u8; 32], Error> {
    fs.random_bytes(32)
        .await?
        .try_into()
        .map_err(|_| Error::Denied)
}

async fn write_private<F: LocalFs + Sync>(fs: &F, path: &Path, bytes: &[u8]) -> Result<(), Error> {
    fs.write_new(path, bytes).await?;
    fs.set_permissions_and_sync(path, std::fs::Permissions::from_mode(0o600))
        .await?;
    Ok(())
}

async fn read_seed<F: LocalFs + Sync>(
    fs: &F,
    path: &Path,
    owner_uid: u32,
) -> Result<[u8; 32], Error> {
    validate_private_file(fs, path, owner_uid).await?;
    fs.read_nofollow(path)
        .await?
        .try_into()
        .map_err(|_| Error::Denied)
}
