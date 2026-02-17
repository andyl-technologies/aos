# Phase 1: Foundation & Config

## Goal

Establish the data types, configuration system, CLI scaffolding, and registry
TOML parsing that every subsequent phase builds on. After this phase, `aos
package` (and `apm` alias) accepts subcommands and can parse registry config
files and package TOML metadata.

## Prerequisites

None — this is the first phase.

## Design References

- [cli.md](../cli.md) — CLI structure, subcommands, config file format
- [packages.md](../packages.md) — TOML package metadata schema
- [registry.md](../registry.md) — Registry structure, directory layout
- [convergence.md](../convergence.md) — Metadata JSON schema

---

## Chunk 1A: Core Types & Config Parsing

### Files to Create

**`src/package/types.rs`** (~200 lines)

Core data types used across all APM modules.

```rust
/// A package as described in a registry TOML file.
pub struct PackageMeta {
    pub name: String,
    pub version: String,
    pub description: String,
    pub homepage: Option<String>,
    pub license: Option<String>,
    pub platform: String,
    pub store_path: String,
    pub nar_hash: String,          // "sha256:..."
    pub nar_size: u64,
    pub download_hash: String,     // "sha256:..."
    pub download_size: u64,
    pub references: Vec<String>,   // store path hashes
    pub source_drv: Option<String>,
    pub source_nar_hash: Option<String>,
    pub maintainer: Option<String>,
    pub closure_size: Option<u64>,
}

/// Installed package metadata (meta/{hash}.json).
pub struct InstalledMeta {
    pub store_path: String,
    pub pushed_at: i64,
    pub pushed_by: String,
    pub expires_at: Option<i64>,
    pub is_root: bool,
    pub last_accessed: i64,
    pub access_count: u64,
    pub apm: Option<ApmMeta>,
}

pub struct ApmMeta {
    pub name: String,
    pub version: String,
    pub explicit: bool,
    pub registry: String,
    pub installed_at: String,     // ISO 8601
    pub held: bool,
}

/// Registry configuration (from registries.d/*.toml).
pub struct RegistryConfig {
    pub name: String,
    pub url: String,              // determines transport
    pub priority: u32,
    pub enabled: bool,
    pub pin: Option<String>,      // tag pin (both transports)
    pub branch: Option<String>,   // git-only
    pub signing: Option<SigningConfig>,
}

pub struct SigningConfig {
    pub required: bool,
    pub public_key: String,       // "name:Ed25519:base64key"
}

/// Registry update state (appended to registries.d/*.toml by apm).
pub struct RegistryState {
    pub last_commit: Option<String>,
    pub last_creation_token: Option<u64>,
    pub last_update: Option<String>,
}

/// APM settings (from apm.conf).
pub struct ApmSettings {
    pub assume_yes: bool,
    pub parallel_downloads: u32,
    pub auto_autoremove: bool,
    pub auto_gc: bool,
}

/// Transport type derived from URL scheme.
pub enum Transport {
    HttpBundle,     // https:// or http://
    Git,            // git://, git+https://, git+ssh://
}

impl RegistryConfig {
    pub fn transport(&self) -> Transport { /* parse URL scheme */ }
}

/// Profile scope.
pub enum ProfileScope {
    User,           // /var/lib/profiles/per-user/$USER/
    System,         // /var/lib/profiles/system/
}
```

**`src/package/config.rs`** (~250 lines)

Configuration loading with system/user fallback.

```rust
pub struct ApmConfig {
    pub settings: ApmSettings,
    pub registries: Vec<RegistryConfig>,
    pub scope: ProfileScope,
}

impl ApmConfig {
    /// Load config for the given scope.
    ///
    /// User scope: ~/.config/apm/ first, /etc/apm/ fallback.
    /// System scope: /etc/apm/ only.
    pub fn load(scope: ProfileScope) -> Result<Self>;

    /// Load apm.conf from a directory, with fallback.
    fn load_settings(primary: &Path, fallback: Option<&Path>) -> Result<ApmSettings>;

    /// Scan registries.d/ and parse each .toml file.
    /// User-level files with the same `name` override system-level.
    fn load_registries(primary: &Path, fallback: Option<&Path>) -> Result<Vec<RegistryConfig>>;

    /// Parse a single registry TOML file, including [registry.state] if present.
    fn parse_registry_file(path: &Path) -> Result<(RegistryConfig, Option<RegistryState>)>;

    /// Return the profile base path for this scope.
    pub fn profile_path(&self) -> PathBuf;

    /// Return the registry cache path for this scope.
    /// User: ~/.local/share/apm/remote/
    /// System: /var/lib/apm/remote/
    pub fn cache_path(&self) -> PathBuf;

    /// Return the state path for this scope.
    /// User: ~/.config/apm/registries.d/ (state appended to config files)
    /// System: /var/lib/apm/registries.d/
    pub fn state_path(&self) -> PathBuf;

    /// Return registries sorted by priority (highest first).
    pub fn registries_by_priority(&self) -> Vec<&RegistryConfig>;
}
```

### Tests

- Parse a well-formed `apm.conf` with all fields.
- Parse a minimal `apm.conf` with defaults.
- Parse a registry TOML file with `[signing]` and `[registry.state]`.
- User-level registry overrides system-level by name.
- Transport detection: `https://` → HttpBundle, `git+https://` → Git.
- Profile path for User vs System scope.

### Acceptance Criteria

- `ApmConfig::load(ProfileScope::User)` reads `~/.config/apm/` with
  `/etc/apm/` fallback.
- `ApmConfig::load(ProfileScope::System)` reads only `/etc/apm/`.
- All types derive `Debug`, `Clone`, `Serialize`, `Deserialize`.
- Registry files with `[registry.state]` are parsed without error.

---

## Chunk 1B: CLI Scaffolding & argv[0] Detection

### Files to Modify

**`src/main.rs`** — Add argv[0] detection and `Package` dispatch.

```rust
// Before Cli::parse(), detect argv[0]:
let argv0 = std::env::args().next().unwrap_or_default();
let is_apm = Path::new(&argv0)
    .file_name()
    .map(|n| n == "apm")
    .unwrap_or(false);

// If invoked as "apm", prepend "package" to args:
let cli = if is_apm {
    let mut args: Vec<String> = std::env::args().collect();
    args.insert(1, "package".to_string());
    Cli::parse_from(args)
} else {
    Cli::parse()
};

// In the command dispatch match:
Commands::Package(cmd) => {
    package::run(cmd, &printer).await?;
}
```

**`src/cli.rs`** — Add `Package` variant to `Commands` enum.

```rust
#[derive(Subcommand)]
pub enum Commands {
    // ... existing variants ...

    /// Package manager (apm)
    Package(PackageArgs),
}

#[derive(Args)]
pub struct PackageArgs {
    #[command(subcommand)]
    pub command: PackageCommand,

    /// Operate on the system profile (requires root)
    #[arg(long, global = true)]
    pub system: bool,

    /// Show what would be done without doing it
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Assume yes to all prompts
    #[arg(short = 'y', long, global = true)]
    pub yes: bool,
}

#[derive(Subcommand)]
pub enum PackageCommand {
    Install { packages: Vec<String>, #[arg(long)] registry: Option<String> },
    Remove { packages: Vec<String>, #[arg(long)] autoremove: bool },
    Autoremove,
    Reinstall { packages: Vec<String> },
    Update { #[arg(long)] registry: Option<String> },
    Upgrade { packages: Vec<String>, #[arg(long)] exclude: Vec<String> },
    FullUpgrade,
    Search { pattern: String, #[arg(long)] names_only: bool, #[arg(long)] installed: bool },
    Show { package: String },
    List { #[arg(long)] installed: bool, #[arg(long)] upgradable: bool, #[arg(long)] held: bool },
    Depends { package: String },
    Rdepends { package: String },
    Policy { package: String },
    Files { package: String },
    Hold { package: String },
    Unhold { package: String },
    Held,
    Clean { #[arg(long)] generations: bool, #[arg(long, default_value = "3")] keep: u32 },
    Gc,
    Verify { package: String },
    Source { package: String, #[arg(long)] fetch: bool, #[arg(long)] verify: bool },
    Rollback { #[arg(long)] generation: Option<u32> },
    Registry(RegistryCommand),
}

#[derive(Subcommand)]
pub enum RegistryCommand {
    List,
    Add { url: String, #[arg(long, default_value = "500")] priority: u32 },
    Remove { name: String },
}
```

**`src/error.rs`** — Add APM error variants.

```rust
pub enum AosError {
    // ... existing variants ...
    PackageNotFound { name: String },
    RegistryError { message: String },
    DownloadError { message: String },
    HashMismatch { expected: String, actual: String },
    ProfileError { message: String },
    RegistryHasPackages { name: String, count: usize },
    UserCancelled,
}
```

### Files to Create

**`src/package/mod.rs`** (~100 lines)

Top-level dispatch for all `aos package` subcommands.

```rust
pub mod config;
pub mod types;

/// Main entry point for `aos package` / `apm`.
pub async fn run(args: PackageArgs, printer: &Printer) -> Result<()> {
    let scope = if args.system {
        ProfileScope::System
    } else {
        ProfileScope::User
    };
    let config = ApmConfig::load(scope)?;

    match args.command {
        PackageCommand::Install { .. } => todo!("Phase 5A"),
        PackageCommand::Remove { .. } => todo!("Phase 5B"),
        // ... stub all commands with todo!() ...
    }
}
```

### Tests

- `apm install curl` parses to `PackageCommand::Install { packages: ["curl"] }`.
- `apm --system install curl` sets `system = true`.
- `apm -y upgrade` sets `yes = true`.
- `apm registry add https://... --priority=600` parses correctly.
- argv[0] = "apm" inserts "package" subcommand.
- All global flags (`--system`, `--dry-run`, `-y`) propagate to subcommands.

### Acceptance Criteria

- `aos package install curl` and `apm install curl` both dispatch to the
  same handler.
- All 23 subcommands are defined in clap (stubbed with `todo!()`).
- `AosError` has APM-specific variants with appropriate exit codes.
- Compiles and passes `cargo check`.

---

## Chunk 1C: Registry TOML Parsing & Hash Index

### Files to Create

**`src/package/registry/mod.rs`** (~150 lines)

Registry manager that holds parsed registry data.

```rust
pub mod parse;

/// A loaded registry with all its packages.
pub struct Registry {
    pub config: RegistryConfig,
    pub packages: HashMap<String, PackageMeta>,  // name -> meta
    hash_index: HashMap<String, String>,          // store hash -> package name
}

impl Registry {
    /// Load a registry from its local cache directory.
    pub fn load(cache_dir: &Path, config: &RegistryConfig) -> Result<Self>;

    /// Look up a package by name.
    pub fn get(&self, name: &str) -> Option<&PackageMeta>;

    /// Look up a package by store path hash.
    pub fn get_by_hash(&self, hash: &str) -> Option<&PackageMeta>;

    /// List all package names.
    pub fn names(&self) -> Vec<&str>;

    /// Search packages by pattern (name + description).
    pub fn search(&self, pattern: &str) -> Vec<&PackageMeta>;
}

/// Multi-registry resolver. Wraps multiple registries sorted by priority.
pub struct RegistrySet {
    registries: Vec<Registry>,
}

impl RegistrySet {
    pub fn new(registries: Vec<Registry>) -> Self;

    /// Resolve a package name: returns the package from the highest-priority
    /// registry that offers it.
    pub fn resolve(&self, name: &str) -> Option<(&Registry, &PackageMeta)>;

    /// Resolve a store path hash within a specific registry.
    /// Used for registry-scoped closure walking.
    pub fn resolve_hash_in(&self, registry_name: &str, hash: &str)
        -> Option<&PackageMeta>;

    /// Get all versions of a package across registries (for `apm policy`).
    pub fn all_versions(&self, name: &str) -> Vec<(&Registry, &PackageMeta)>;
}
```

**`src/package/registry/parse.rs`** (~200 lines)

Parse package TOML files from a registry cache directory.

```rust
/// Parse all package TOML files in a registry cache.
///
/// Registry layout:
///   {cache_dir}/{registry_name}/packages/{first_letter}/{name}.toml
///
/// Returns (packages, hash_index).
pub fn parse_registry(dir: &Path) -> Result<(HashMap<String, PackageMeta>, HashMap<String, String>)>;

/// Parse a single package TOML file.
pub fn parse_package_toml(content: &str) -> Result<PackageMeta>;

/// Build the hash-to-name reverse index from a set of packages.
/// Each package's store_path hash and all reference hashes are indexed.
pub fn build_hash_index(packages: &HashMap<String, PackageMeta>) -> HashMap<String, String>;

/// Extract the hash component from a store path.
/// "/var/lib/store/abc123-curl-8.5.0" -> "abc123"
pub fn store_path_hash(store_path: &str) -> &str;
```

### Tests

- Parse a valid package TOML (curl example from packages.md).
- Parse all fields including optional ones (`homepage`, `license`, `source_drv`).
- Hash index maps store path hash to package name.
- Hash index includes both the package's own hash and its reference hashes.
- `store_path_hash` extracts correctly from various path formats.
- `RegistrySet::resolve` picks highest-priority registry.
- `RegistrySet::resolve_hash_in` is scoped to one registry.
- `RegistrySet::all_versions` returns entries from all registries, priority-ordered.
- Missing fields produce clear error messages.
- Empty registry directory is valid (0 packages).

### Acceptance Criteria

- Can parse the complete TOML schema from packages.md.
- Hash index enables O(1) lookup by store path hash.
- `RegistrySet` resolves names by priority and hashes within a single registry.
- All parsing errors include the file path and field name.

---

## Integration Notes

After Phase 1 is complete:
- `aos package` / `apm` CLI is wired up (all commands stub to `todo!()`)
- Config system reads `apm.conf` and `registries.d/` with system/user fallback
- Registry TOML files can be parsed and queried
- Core types are defined for all subsequent phases
- No runtime functionality yet — pure data layer
