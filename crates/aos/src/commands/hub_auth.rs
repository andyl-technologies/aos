//! Persistent Hub CLI profiles and rotating OAuth credentials.
//!
//! The profile file contains bearer material and is therefore created with
//! user-only permissions. Commands resolve explicit flags and environment
//! values first; otherwise they use the active normalized Hub origin prepared
//! here at process startup.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const PROFILE_SCHEMA: &str = "aos.hub.profiles/v1";
const REFRESH_SKEW_SECS: i64 = 60;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredProfile {
    access_token: String,
    access_expires_at: i64,
    refresh_token: String,
    refresh_expires_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileStore {
    schema_version: String,
    active_origin: Option<String>,
    profiles: BTreeMap<String, StoredProfile>,
}

impl Default for ProfileStore {
    fn default() -> Self {
        Self {
            schema_version: PROFILE_SCHEMA.into(),
            active_origin: None,
            profiles: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct ResolvedProfile {
    origin: String,
    access_token: String,
}

static ACTIVE_PROFILE: OnceLock<Mutex<Option<ResolvedProfile>>> = OnceLock::new();

fn active_slot() -> &'static Mutex<Option<ResolvedProfile>> {
    ACTIVE_PROFILE.get_or_init(|| Mutex::new(None))
}

/// Loads the active profile and refreshes it when its access JWT is near expiry.
///
/// # Errors
///
/// Returns an error when the profile file is malformed, its origin is invalid,
/// credential refresh fails, or the rotated profile cannot be persisted.
pub async fn prepare_active_profile() -> Result<()> {
    let Some(path) = profile_path()? else {
        replace_active(None)?;
        return Ok(());
    };
    let mut store = load_store(&path)?;
    let Some(origin) = store.active_origin.clone() else {
        replace_active(None)?;
        return Ok(());
    };
    let Some(mut profile) = store.profiles.get(&origin).cloned() else {
        anyhow::bail!("active Hub profile '{origin}' is missing");
    };
    let now = now_secs();
    if profile.access_expires_at <= now.saturating_add(REFRESH_SKEW_SECS) {
        let grant = aos_remote::refresh_token(&origin, &profile.refresh_token)
            .await
            .with_context(|| format!("refreshing Hub profile {origin}"))?;
        update_profile_from_grant(&mut profile, grant, now)?;
        store.profiles.insert(origin.clone(), profile.clone());
        save_store(&path, &store)?;
    }
    replace_active(Some(ResolvedProfile {
        origin,
        access_token: profile.access_token,
    }))
}

/// Persists an interactive device grant and makes its origin active.
///
/// # Errors
///
/// Returns an error when the origin is invalid, the grant lacks a refresh
/// credential, or the user-only profile file cannot be written atomically.
pub fn install_device_grant(origin: &str, grant: aos_remote::TokenGrant) -> Result<i64> {
    let origin = normalize_origin(origin)?;
    let path = required_profile_path()?;
    let mut store = load_store(&path)?;
    let now = now_secs();
    let mut profile = StoredProfile {
        access_token: String::new(),
        access_expires_at: 0,
        refresh_token: String::new(),
        refresh_expires_at: 0,
    };
    update_profile_from_grant(&mut profile, grant, now)?;
    let expires_at = profile.access_expires_at;
    store.profiles.insert(origin.clone(), profile.clone());
    store.active_origin = Some(origin.clone());
    save_store(&path, &store)?;
    replace_active(Some(ResolvedProfile {
        origin,
        access_token: profile.access_token,
    }))?;
    Ok(expires_at)
}

/// Revokes and removes one stored profile, or the active profile when omitted.
///
/// # Errors
///
/// Returns an error when no selected profile exists, revocation fails, or the
/// updated profile store cannot be persisted.
pub async fn logout(origin: Option<&str>) -> Result<String> {
    let path = required_profile_path()?;
    let mut store = load_store(&path)?;
    let selected = match origin {
        Some(origin) => normalize_origin(origin)?,
        None => store
            .active_origin
            .clone()
            .context("no active Hub profile")?,
    };
    let profile = store
        .profiles
        .get(&selected)
        .cloned()
        .with_context(|| format!("no stored Hub profile for {selected}"))?;
    aos_remote::revoke_refresh_token(&selected, &profile.refresh_token)
        .await
        .with_context(|| format!("revoking Hub profile {selected}"))?;

    store.profiles.remove(&selected);
    if store.active_origin.as_deref() == Some(selected.as_str()) {
        store.active_origin = store.profiles.keys().next().cloned();
    }
    save_store(&path, &store)?;
    replace_active(store.active_origin.as_ref().and_then(|origin| {
        store.profiles.get(origin).map(|profile| ResolvedProfile {
            origin: origin.clone(),
            access_token: profile.access_token.clone(),
        })
    }))?;
    Ok(selected)
}

/// Resolves explicit connection flags against the prepared active profile.
///
/// Explicit `hub` and `token` values win independently. A matching active
/// profile supplies a missing token; omitting the Hub selects the active
/// profile completely.
///
/// # Errors
///
/// Returns an error when no Hub was supplied and no active profile exists, the
/// explicit origin is invalid, or the in-process profile lock is poisoned.
pub fn resolve_access(hub: Option<&str>, token: Option<&str>) -> Result<(String, Option<String>)> {
    let active = active_slot()
        .lock()
        .map_err(|_| anyhow::anyhow!("Hub profile lock is poisoned"))?
        .clone();
    match hub {
        Some(hub) => {
            let origin = normalize_origin(hub)?;
            let resolved_token = token.map(str::to_owned).or_else(|| {
                active
                    .as_ref()
                    .filter(|profile| profile.origin == origin)
                    .map(|profile| profile.access_token.clone())
            });
            Ok((origin, resolved_token))
        }
        None => {
            let profile = active.context("provide --hub or run `aos hub login --hub URL`")?;
            Ok((
                profile.origin,
                token.map(str::to_owned).or(Some(profile.access_token)),
            ))
        }
    }
}

fn update_profile_from_grant(
    profile: &mut StoredProfile,
    grant: aos_remote::TokenGrant,
    now: i64,
) -> Result<()> {
    let refresh_token = grant
        .refresh_token
        .context("Hub token grant did not include a refresh credential")?;
    let refresh_ttl = grant
        .refresh_token_expires_in
        .context("Hub token grant did not include refresh expiry")?;
    anyhow::ensure!(grant.expires_in > 0, "Hub returned an expired access grant");
    anyhow::ensure!(refresh_ttl > 0, "Hub returned an expired refresh grant");
    profile.access_token = grant.access_token;
    profile.access_expires_at = now.saturating_add(grant.expires_in);
    profile.refresh_token = refresh_token;
    profile.refresh_expires_at = now.saturating_add(refresh_ttl);
    Ok(())
}

fn replace_active(profile: Option<ResolvedProfile>) -> Result<()> {
    *active_slot()
        .lock()
        .map_err(|_| anyhow::anyhow!("Hub profile lock is poisoned"))? = profile;
    Ok(())
}

fn normalize_origin(value: &str) -> Result<String> {
    let mut url = url::Url::parse(value).context("Hub URL is invalid")?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "Hub URL must use HTTP or HTTPS"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "Hub URL cannot contain credentials"
    );
    anyhow::ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "Hub URL cannot contain a query or fragment"
    );
    anyhow::ensure!(
        url.path() == "/" || url.path().is_empty(),
        "Hub URL must be an origin without a path"
    );
    url.set_path("");
    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn profile_path() -> Result<Option<PathBuf>> {
    if let Some(root) = std::env::var_os("AOS_CONFIG_HOME") {
        return Ok(Some(PathBuf::from(root).join("hub-profiles.json")));
    }
    if let Some(root) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(Some(PathBuf::from(root).join("aos/hub-profiles.json")));
    }
    Ok(std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".config/aos/hub-profiles.json")))
}

fn required_profile_path() -> Result<PathBuf> {
    profile_path()?
        .context("HOME, XDG_CONFIG_HOME, or AOS_CONFIG_HOME is required for Hub profiles")
}

fn load_store(path: &Path) -> Result<ProfileStore> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ProfileStore::default());
        }
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let store: ProfileStore =
        serde_json::from_slice(&bytes).with_context(|| format!("decoding {}", path.display()))?;
    anyhow::ensure!(
        store.schema_version == PROFILE_SCHEMA,
        "unsupported Hub profile schema '{}'; expected {PROFILE_SCHEMA}",
        store.schema_version
    );
    Ok(store)
}

fn save_store(path: &Path, store: &ProfileStore) -> Result<()> {
    let parent = path.parent().context("Hub profile path has no parent")?;
    create_private_dir(parent)?;
    let bytes = serde_json::to_vec_pretty(store)?;
    let temp = parent.join(format!(".hub-profiles.{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .with_context(|| format!("creating {}", temp.display()))?;
    let write_result = (|| -> Result<()> {
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        set_private_file_permissions(path)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    write_result.with_context(|| format!("writing {}", path.display()))
}

fn create_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path)?;
    Ok(())
}

fn set_private_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_canonical_and_reject_non_origin_components() {
        assert_eq!(
            normalize_origin("https://hub.example/").unwrap(),
            "https://hub.example"
        );
        assert!(normalize_origin("ftp://hub.example").is_err());
        assert!(normalize_origin("https://user@hub.example").is_err());
        assert!(normalize_origin("https://hub.example/path").is_err());
    }

    #[test]
    fn profile_schema_is_strict_and_versioned() {
        let encoded = serde_json::to_vec(&ProfileStore::default()).unwrap();
        let decoded: ProfileStore = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.schema_version, PROFILE_SCHEMA);
        assert!(
            serde_json::from_str::<ProfileStore>(
                r#"{"schema_version":"other","active_origin":null,"profiles":{},"extra":true}"#
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn profile_store_is_written_with_user_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("aos/hub-profiles.json");
        save_store(&path, &ProfileStore::default()).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}
