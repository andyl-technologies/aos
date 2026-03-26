# Identity Management

The AOS daemon uses a unified identity manager for all credential and secret
management. This component is shared across the enrollment system, the fetch
engine, the store upload/download protocols, and any other subsystem that
requires authentication or signing.

## Design Principles

- **Single abstraction.** All credential access goes through one interface,
  regardless of where the credential is stored or how it's obtained.
- **Pluggable backends.** Credentials can come from local files, environment
  variables, cloud provider metadata, key management services, or the daemon's
  own key store. The backend is configured, not coded.
- **Lazy resolution.** Credentials are resolved on first use, not at startup.
  This supports dynamic credential sources (e.g., rotating cloud IAM tokens).
- **Scoped access.** Each subsystem declares which credentials it needs. The
  identity manager enforces that subsystems only access credentials they're
  authorized to use.

## Credential Sources

| Source | Description | Use cases |
|---|---|---|
| `keystore` | Local key store (see below) | Network key, cluster root keys, intermediate certs |
| `file` | Plain file on disk | Pre-provisioned tokens, SSH keys |
| `env` | Environment variable | CI tokens, development secrets |
| `instance-metadata` | Cloud provider instance metadata / IAM role | AWS IMDS, GCP metadata server |
| `aws-secretsmanager` | AWS Secrets Manager | Production secrets |
| `aws-ssm` | AWS Systems Manager Parameter Store | Configuration secrets |
| `gcp-secretmanager` | GCP Secret Manager | Production secrets |
| `vault` | HashiCorp Vault | Enterprise secret management |

## Key Store

The key store is the local credential backend. For the daemon, it stores
the peer keypair and any locally-provisioned credentials:

```
/etc/aos/
  peer.key                          # daemon's ed25519 private key
  enrollment/
    clusters/
      prod/
        peer.ucan                   # UCAN chain for this node in prod
        intermediate.cert           # intermediate cert
        cluster_root.pub            # cluster root public key
```

For the operator's CLI (`aos` tool), the key store holds network and cluster
keys:

```
~/.config/aos/keys/
  network.key                       # network private key
  network.pub                       # network public key
  clusters/
    prod/
      root.key                      # cluster root private key
      root.pub                      # cluster root public key
    staging/
      root.key
      root.pub
  intermediates/
    ops-admin.cert
    ci-admin.cert
```

The key store backend is configurable:

```toml
# Daemon node identity (key_file is under [node])
[node]
key_file = "/etc/aos/peer.key"

# Daemon credential store
[identity]
keystore_type = "directory"         # directory, sops, age
keystore_path = "/etc/aos/"

# CLI key store
# ~/.config/aos/keystore.toml
[keystore]
type = "directory"                  # directory, sops, age, aws-kms, vault
path = "~/.config/aos/keys/"
```

Encrypted backends (SOPS, age) decrypt on read and encrypt on write. The
encryption key itself may come from another source (e.g., age key from an
environment variable, SOPS key from AWS KMS).

## Credential Resolution

When a subsystem needs a credential, it calls the identity manager with a
credential descriptor:

```rust
struct CredentialRequest {
    name: String,           // e.g., "github-token", "prod-ucan"
    credential_type: CredentialType,  // Bearer, Basic, SigningKey, Certificate
    source: CredentialSource,         // Keystore, File, Env, InstanceMetadata, etc.
    domain: Option<String>,           // for domain-scoped credentials (fetch auth)
}
```

The identity manager resolves the credential from the configured source and
returns it. Resolved credentials are cached in memory with a configurable
TTL (default 5 minutes for dynamic sources like instance metadata, unlimited
for static sources like files).

### Resolution Flow

1. **Check cache.** If a non-expired cached value exists, return it.
2. **Resolve from source.** Read the credential from the configured backend.
3. **Validate.** Check that the credential is well-formed (e.g., valid PEM,
   non-empty token, unexpired certificate).
4. **Cache.** Store the resolved credential with appropriate TTL.
5. **Return.** Return the credential to the caller.

### Failure Handling

If resolution fails (file not found, API error, invalid credential):

- **Startup:** the daemon logs an error and retries with exponential backoff.
  If the credential is required for a cluster (e.g., UCAN), that cluster is
  not joined until the credential is available.
- **Runtime:** the operation that requested the credential fails. The error
  is propagated to the caller (e.g., a fetch request fails with 503).
- **Cached credentials:** if a cached credential expires and renewal fails,
  the stale credential is used with a warning. This prevents transient
  backend failures from immediately breaking all operations.

## Daemon Configuration

```toml
# key_file is under [node] (see daemon.md)

# Fetch engine credentials
[[identity.credentials]]
name = "github-token"
domain = "github.com"
type = "bearer"
source = "env"
key = "GITHUB_TOKEN"

[[identity.credentials]]
name = "s3-access"
domain = "*.s3.amazonaws.com"
type = "aws-sigv4"
source = "instance-metadata"

[[identity.credentials]]
name = "private-mirror"
domain = "mirror.internal.example.com"
type = "basic"
source = "file"
path = "/etc/aos/tokens/mirror-auth"
```

## Integration Points

### Enrollment

The enrollment system uses the identity manager for:
- Reading the network public key (for verifying enrollment requests)
- Storing issued UCANs and intermediate certs (on enrollment)
- Reading cluster UCANs (on startup, for topic subscriptions)

### Fetch Engine

The fetch engine uses the identity manager for:
- HTTP authentication (Bearer, Basic, AWS SigV4) per domain
- Domain-matched credential lookup (e.g., `github.com` -> GitHub token)

### Store Protocols

The store upload/download protocols use the identity manager for:
- UCAN presentation in stream protocol requests
- UCAN verification in stream protocol responses

### Workflow Engine

The workflow engine uses the identity manager for:
- Reading the cluster UCAN to verify it has `/aos/workflow/execute`
- Signing workflow transitions

## Security

- **No plaintext secrets in config.** The TOML config references credential
  sources (file paths, env var names, KMS key IDs), not the credentials
  themselves.
- **Memory protection.** Resolved credentials are stored in a `SecretVec`
  (zeroized on drop) to prevent secrets from lingering in memory.
- **Audit logging.** All credential accesses are logged (at debug level) with
  the requesting subsystem, credential name, and source -- but NOT the
  credential value.
- **Principle of least privilege.** Each subsystem declares which credentials
  it needs. The identity manager can enforce access control (TBD).

## Relationship to Other Docs

- [enrollment.md](enrollment.md) -- enrollment protocol uses the identity
  manager for key storage and UCAN management.
- [fetch.md](fetch.md) -- fetch engine uses the identity manager for HTTP
  authentication.
- [daemon.md](daemon.md) -- `[node]` and `[identity]` configuration sections.
- [auth.md](auth.md) -- UCAN chain verification uses the identity manager
  to access certificates.
- [cloud-init.md](cloud-init.md) -- cloud-init can configure credential
  sources (secrets manager integration).
