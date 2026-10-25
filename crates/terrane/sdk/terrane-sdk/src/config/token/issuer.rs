//! Loads bounded public issuer files from explicitly trusted local locators.
//!
//! Each file supplies one rotation key. The format contains no signing seed,
//! capability or repository authority; original signatures are still verified
//! independently against the resulting keyring.
//!
//! ```toml
//! version = 1
//! issuer = "operator"
//! key_id = "2026-10"
//! public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
//! retirement = 1800000000
//! ```

use std::{collections::BTreeSet, fmt, path::Path};

use serde::Deserialize;
use terrane_format::auth::IssuerKey;

use super::Tokens;

mod native;

/// Reports invalid public trust configuration or an actual native file failure.
#[derive(Debug)]
pub enum IssuerKeyError {
    /// Rejects missing, ambiguous, malformed or unsafe public trust inputs.
    Invalid(&'static str),
    /// Preserves a descriptor opening, metadata or bounded read failure.
    Io(std::io::Error),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyFile {
    version: u32,
    issuer: String,
    key_id: String,
    public_key: String,
    retirement: Option<u64>,
}

impl Tokens {
    /// Loads the configured public issuer keyring without opening token locators.
    ///
    /// At most 256 files of 16 KiB each are accepted. Each path is traversed
    /// through nofollow directory descriptors owned by root or `owner_uid`,
    /// without group or other write permission. The final single-link regular
    /// file must have the same ownership policy and be read-only to other users.
    /// Duplicate issuer/key identifiers are rejected even for identical keys.
    ///
    /// # Errors
    /// Rejects missing or excessive keys, invalid owners or locators, unsafe
    /// paths or files, malformed key records, duplicate identities and actual
    /// native I/O failures. Error messages never include loaded file contents.
    pub fn load_issuer_keys(&self, owner_uid: u32) -> Result<Vec<IssuerKey>, IssuerKeyError> {
        if owner_uid == u32::MAX
            || self.issuer_public_keys.is_empty()
            || self.issuer_public_keys.len() > 256
        {
            return Err(IssuerKeyError::Invalid(
                "invalid issuer keyring size or owner",
            ));
        }

        let paths =
            self.issuer_public_keys
                .iter()
                .map(|locator| {
                    let path = locator.strip_prefix("file:").map(Path::new).ok_or(
                        IssuerKeyError::Invalid("issuer key requires a file locator"),
                    )?;
                    native::validate_path(path)?;
                    Ok(path)
                })
                .collect::<Result<Vec<_>, IssuerKeyError>>()?;

        let mut identities = BTreeSet::new();
        let mut keys = Vec::with_capacity(paths.len());
        for path in paths {
            let key = decode(&native::read(path, owner_uid)?)?;
            if !identities.insert((key.issuer.clone(), key.key_id.clone())) {
                return Err(IssuerKeyError::Invalid("duplicate issuer key identity"));
            }
            keys.push(key);
        }
        Ok(keys)
    }
}

fn decode(bytes: &[u8]) -> Result<IssuerKey, IssuerKeyError> {
    let invalid = || IssuerKeyError::Invalid("malformed public issuer key file");
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let record: PublicKeyFile = toml::from_str(text).map_err(|_| invalid())?;
    if record.version != 1
        || record.issuer.is_empty()
        || record.key_id.is_empty()
        || record.public_key.len() != 64
        || !record
            .public_key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }

    let mut public_key = [0; 32];
    let (pairs, _) = record.public_key.as_bytes().as_chunks::<2>();
    for (destination, pair) in public_key.iter_mut().zip(pairs) {
        let digits = std::str::from_utf8(pair).map_err(|_| invalid())?;
        *destination = u8::from_str_radix(digits, 16).map_err(|_| invalid())?;
    }
    Ok(IssuerKey {
        issuer: record.issuer,
        key_id: record.key_id,
        public_key,
        retirement: record.retirement,
    })
}

impl fmt::Display for IssuerKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => formatter.write_str(reason),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for IssuerKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(_) => None,
            Self::Io(error) => Some(error),
        }
    }
}
