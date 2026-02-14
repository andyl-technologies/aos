# CLI Integration

> Part of the [AOS Cache Design](README.md)

No new subcommand group — remote build functionality integrates directly
into existing `aos` commands via `--remote` flags, plus two new top-level
commands (`serve`, `token`).

## New commands

```
aos serve [--config /etc/aos/serve.toml]
    Start the HTTP binary cache / remote build server.
    Creates AOS_ROOT subdirectories (gcroots/{view}/{bin,src}/,
    meta/{view}/{bin,src}/, views/) on first run.

aos token create --view VIEW --permissions PERMS [--expires DURATION]
    Create a provisioning secret (local Unix socket, requires root or
    aos-admins group membership). Prints the token.

aos token list
    List active provisioning tokens.

aos token revoke --token-id ID [--reason TEXT]
    Revoke a token immediately.

aos token rotate --token-id ID
    Rotate: create new token, old one expires in 1-hour grace period.
```

## Extended existing commands

```
aos build [PKG] --remote URL [--view VIEW] [--token TOKEN]
    Same as local build, but delegates to a remote server.
    Evaluates locally → uploads .drv closure → requests remote build.
    Streams build logs to terminal. On success, outputs are available
    via the server's binary cache for substitution.

    --remote: server URL (or AOS_REMOTE env)
    --view: target view (or AOS_VIEW env, default: "default")
    --token: provisioning secret (or AOS_TOKEN env)

    Without --remote: builds locally as before (existing behavior).

aos gc [--remote URL] [--view VIEW] [--collect] [--dry-run] [--all]
    Without --remote: local nix-store --gc (existing behavior).
    With --remote: expire TTL roots + DAG-aware eviction on the server.
    --collect: also run nix-store --gc after root removal
    --dry-run: show what would be evicted
    --all: force-remove all roots for a view (decommission)
    --pin PATH: protect a root from eviction
```

## CLI implementation (cli.rs)

```rust
#[derive(Subcommand)]
pub enum Commands {
    // ... existing commands (Build, System, Show, etc.) ...

    /// Start the HTTP build server
    Serve {
        #[arg(long, default_value = "/etc/aos/serve.toml")]
        config: PathBuf,
    },

    /// Manage authentication tokens
    Token {
        #[command(subcommand)]
        command: TokenCmd,
    },

    // Existing Build and Gc are extended with new flags:
    // Build { ..., remote: Option<String>, view: Option<String>, token: Option<String> }
    // Gc { ..., remote: Option<String>, view: Option<String>, pin: Option<String> }
}

#[derive(Subcommand)]
pub enum TokenCmd {
    /// Create a new provisioning token
    Create {
        #[arg(long)]
        view: String,
        #[arg(long, value_delimiter = ',')]
        permissions: Vec<String>,
        #[arg(long)]
        expires: Option<String>,
        #[arg(long)]
        comment: Option<String>,
    },
    /// List active tokens
    List,
    /// Revoke a token immediately
    Revoke {
        #[arg(long)]
        token_id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Rotate a token (new token, old expires after grace period)
    Rotate {
        #[arg(long)]
        token_id: String,
    },
}
```

## Build command extension

The existing `Build` variant gains remote flags:

```rust
Build {
    /// Package name
    package: Option<String>,
    /// Build all packages
    #[arg(long)]
    all: bool,
    /// Remote build server URL (enables remote mode)
    #[arg(long, env = "AOS_REMOTE")]
    remote: Option<String>,
    /// View on the remote server
    #[arg(long, env = "AOS_VIEW", default_value = "default")]
    view: String,
    /// Provisioning token for the remote server
    #[arg(long, env = "AOS_TOKEN")]
    token: Option<String>,
},
```

When `--remote` is present, `commands::build::run()` takes the remote path:
evaluate locally → upload .drv closure → request build → stream logs.
When absent, existing local build behavior is unchanged.
