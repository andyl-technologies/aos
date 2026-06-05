use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::types::{
    ApmConfFile, ApmSettings, ProfileScope, RegistryConfig, RegistryFile, RegistryState,
};

/// Loaded APM configuration for the current session.
#[derive(Debug)]
pub struct ApmConfig {
    pub settings: ApmSettings,
    pub registries: Vec<(RegistryConfig, Option<RegistryState>)>,
    pub scope: ProfileScope,
}

impl ApmConfig {
    /// Load configuration for the given scope.
    ///
    /// - User scope: `~/.config/apm/` first, `/etc/apm/` fallback.
    /// - System scope: `/etc/apm/` only.
    pub fn load(scope: ProfileScope) -> Result<Self> {
        let (primary, fallback) = match scope {
            ProfileScope::User => {
                let user_dir = scope.config_dir();
                let system_dir = ProfileScope::System.config_dir();
                (user_dir, Some(system_dir))
            }
            ProfileScope::System => (scope.config_dir(), None),
        };

        let settings = Self::load_settings(&primary, fallback.as_deref())?;
        let registries = Self::load_registries(&primary, fallback.as_deref())?;

        Ok(Self {
            settings,
            registries,
            scope,
        })
    }

    /// Load `apm.conf`, trying `primary/apm.conf` first, then `fallback/apm.conf`.
    fn load_settings(primary: &Path, fallback: Option<&Path>) -> Result<ApmSettings> {
        let primary_conf = primary.join("apm.conf");
        if primary_conf.exists() {
            let content = std::fs::read_to_string(&primary_conf)
                .with_context(|| format!("reading {}", primary_conf.display()))?;
            let conf: ApmConfFile = toml::from_str(&content)
                .with_context(|| format!("parsing {}", primary_conf.display()))?;
            return Ok(conf.settings);
        }

        if let Some(fb) = fallback {
            let fb_conf = fb.join("apm.conf");
            if fb_conf.exists() {
                let content = std::fs::read_to_string(&fb_conf)
                    .with_context(|| format!("reading {}", fb_conf.display()))?;
                let conf: ApmConfFile = toml::from_str(&content)
                    .with_context(|| format!("parsing {}", fb_conf.display()))?;
                return Ok(conf.settings);
            }
        }

        Ok(ApmSettings::default())
    }

    /// Scan `registries.d/` directories and parse each `.toml` file.
    ///
    /// User-level files with the same registry `name` override system-level.
    fn load_registries(
        primary: &Path,
        fallback: Option<&Path>,
    ) -> Result<Vec<(RegistryConfig, Option<RegistryState>)>> {
        let mut by_name: std::collections::HashMap<
            String,
            (RegistryConfig, Option<RegistryState>),
        > = std::collections::HashMap::new();

        // Load fallback (system) registries first so user ones override
        if let Some(fb) = fallback {
            let fb_dir = fb.join("registries.d");
            if fb_dir.is_dir() {
                Self::load_registry_dir(&fb_dir, &mut by_name)?;
            }
        }

        // Load primary (user) registries — overrides fallback by name
        let primary_dir = primary.join("registries.d");
        if primary_dir.is_dir() {
            Self::load_registry_dir(&primary_dir, &mut by_name)?;
        }

        let mut registries: Vec<_> = by_name.into_values().collect();
        // Sort by priority descending (highest priority first)
        registries.sort_by(|a, b| b.0.priority.cmp(&a.0.priority));

        Ok(registries)
    }

    /// Load all `.toml` files from a `registries.d/` directory.
    fn load_registry_dir(
        dir: &Path,
        map: &mut std::collections::HashMap<String, (RegistryConfig, Option<RegistryState>)>,
    ) -> Result<()> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "toml")
                    .unwrap_or(false)
            })
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            let (config, state) = Self::parse_registry_file(&path)?;
            map.insert(config.name.clone(), (config, state));
        }

        Ok(())
    }

    /// Parse a single registry TOML file, extracting config and optional state.
    fn parse_registry_file(path: &Path) -> Result<(RegistryConfig, Option<RegistryState>)> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let rf: RegistryFile =
            toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;

        let config = RegistryConfig {
            name: rf.registry.name,
            url: rf.registry.url,
            priority: rf.registry.priority,
            enabled: rf.registry.enabled,
            commit: rf.registry.commit,
            branch: rf.registry.branch,
            channel: rf.registry.channel,
            tag: rf.registry.tag,
            version: rf.registry.version,
            pin: rf.registry.pin,
            max_staleness_seconds: rf.registry.max_staleness_seconds,
            caches: rf.registry.caches,
            upload_auth: rf.registry.upload_auth,
            signing: rf.registry.signing,
        };

        Ok((config, rf.registry.state))
    }

    /// Return the profile base path for this session's scope.
    pub fn profile_path(&self) -> PathBuf {
        self.scope.profile_path()
    }

    /// Return the registry cache path for this session's scope.
    pub fn cache_path(&self) -> PathBuf {
        self.scope.cache_path()
    }

    /// Return the NAR download cache path.
    pub fn nar_cache_path(&self) -> PathBuf {
        self.scope.nar_cache_path()
    }

    /// Return registries sorted by priority (highest first), only enabled ones.
    pub fn enabled_registries(&self) -> Vec<&RegistryConfig> {
        self.registries
            .iter()
            .filter(|(cfg, _)| cfg.enabled)
            .map(|(cfg, _)| cfg)
            .collect()
    }

    /// Find a registry by name.
    pub fn find_registry(&self, name: &str) -> Option<&(RegistryConfig, Option<RegistryState>)> {
        self.registries.iter().find(|(cfg, _)| cfg.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_file(dir: &Path, name: &str, content: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    #[test]
    fn load_settings_from_primary() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "apm.conf",
            r#"
[settings]
assume_yes = true
parallel_downloads = 16
"#,
        );
        let settings = ApmConfig::load_settings(tmp.path(), None).unwrap();
        assert!(settings.assume_yes);
        assert_eq!(settings.parallel_downloads, 16);
    }

    #[test]
    fn load_settings_fallback_to_system() {
        let user_dir = TempDir::new().unwrap();
        let system_dir = TempDir::new().unwrap();
        // No user apm.conf
        write_file(
            system_dir.path(),
            "apm.conf",
            r#"
[settings]
parallel_downloads = 2
"#,
        );
        let settings = ApmConfig::load_settings(user_dir.path(), Some(system_dir.path())).unwrap();
        assert_eq!(settings.parallel_downloads, 2);
    }

    #[test]
    fn load_settings_defaults_when_missing() {
        let tmp = TempDir::new().unwrap();
        let settings = ApmConfig::load_settings(tmp.path(), None).unwrap();
        assert!(!settings.assume_yes);
        assert_eq!(settings.parallel_downloads, 4);
    }

    #[test]
    fn load_registries_from_dir() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
priority = 500
"#,
        );
        write_file(
            tmp.path(),
            "registries.d/aos-extra.toml",
            r#"
[registry]
name = "aos-extra"
url = "https://registry.aos.dev/extra"
priority = 400
"#,
        );

        let registries = ApmConfig::load_registries(tmp.path(), None).unwrap();
        assert_eq!(registries.len(), 2);
        // Sorted by priority descending
        assert_eq!(registries[0].0.name, "aos-core");
        assert_eq!(registries[1].0.name, "aos-extra");
    }

    #[test]
    fn user_registry_overrides_system() {
        let user_dir = TempDir::new().unwrap();
        let system_dir = TempDir::new().unwrap();

        write_file(
            system_dir.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
priority = 500
"#,
        );

        // User overrides with higher priority
        write_file(
            user_dir.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
name = "aos-core"
url = "https://mirror.example.com/core"
priority = 600
"#,
        );

        let registries =
            ApmConfig::load_registries(user_dir.path(), Some(system_dir.path())).unwrap();
        assert_eq!(registries.len(), 1);
        assert_eq!(registries[0].0.url, "https://mirror.example.com/core");
        assert_eq!(registries[0].0.priority, 600);
    }

    #[test]
    fn parse_registry_with_state() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test.toml");
        fs::write(
            &path,
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"

[registry.signing]
required = true
public_key = "aos-core:Ed25519:abc123"

[registry.upload_auth]
view = "prod"
s3_region = "us-west-2"

[registry.state]
last_commit = "deadbeef"
floor = "1.2.0"
bucket = 10
retained = ["1.0.0", "1.2.0"]
last_update = "2026-02-13T10:30:00Z"
"#,
        )
        .unwrap();

        let (config, state) = ApmConfig::parse_registry_file(&path).unwrap();
        assert_eq!(config.name, "aos-core");
        assert!(config.signing.is_some());
        let upload_auth = config.upload_auth.unwrap();
        assert_eq!(upload_auth.view.as_deref(), Some("prod"));
        assert_eq!(upload_auth.s3_region.as_deref(), Some("us-west-2"));
        let s = state.unwrap();
        assert_eq!(s.last_commit.unwrap(), "deadbeef");
        assert_eq!(s.floor.unwrap(), "1.2.0");
        assert_eq!(s.bucket.unwrap(), 10);
        assert_eq!(s.retained, vec!["1.0.0", "1.2.0"]);
    }

    #[test]
    fn parse_registry_with_channel() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("channel.toml");
        fs::write(
            &path,
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
channel = "stable"
max_staleness_seconds = 604800
"#,
        )
        .unwrap();

        let (config, state) = ApmConfig::parse_registry_file(&path).unwrap();
        assert_eq!(config.name, "aos-core");
        assert_eq!(config.channel.as_deref(), Some("stable"));
        assert_eq!(config.max_staleness_seconds, Some(604800));
        assert!(state.is_none());
    }

    #[test]
    fn enabled_registries_filter() {
        let config = ApmConfig {
            settings: ApmSettings::default(),
            registries: vec![
                (
                    RegistryConfig {
                        name: "enabled".into(),
                        url: "https://a.dev".into(),
                        priority: 500,
                        enabled: true,
                        commit: None,
                        branch: None,
                        channel: None,
                        tag: None,
                        version: None,
                        pin: None,
                        max_staleness_seconds: None,
                        caches: Vec::new(),
                        upload_auth: None,
                        signing: None,
                    },
                    None,
                ),
                (
                    RegistryConfig {
                        name: "disabled".into(),
                        url: "https://b.dev".into(),
                        priority: 400,
                        enabled: false,
                        commit: None,
                        branch: None,
                        channel: None,
                        tag: None,
                        version: None,
                        pin: None,
                        max_staleness_seconds: None,
                        caches: Vec::new(),
                        upload_auth: None,
                        signing: None,
                    },
                    None,
                ),
            ],
            scope: ProfileScope::User,
        };
        let enabled = config.enabled_registries();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].name, "enabled");
    }
}
