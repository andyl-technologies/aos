# External authority qualification bootstrap

`aos-hub-authority-bootstrap` is a separate operator tool installed by the
source-built `aos-hub` package. It exports current reviewed SQL metadata and
publishes exact current provider credential versions to the paired Worker. It
does not serve Native traffic, upload objects, produce a provider contract, sign
runtime acceptance, or establish provider readiness.

Run Export after the root operator has applied the actual physical authority,
alias, binding association, exclusivity attestation and admitted generation
through `StorageAuthorityService` Plan/Apply. Read, write and presign credentials
must be current, validated and included in that reviewed attestation. The
selected binding must use private access.

## Export current decisions

Prepare an existing private directory and owner-private input files. The SQL URL
file contains one database URL. The issuer configuration is the same explicit
configuration used by `aos-hub-authority initialize` and `serve`; its permanent
installation and executor must exactly match the reviewed authority. The public
verifier file contains the independently supplied lowercase hexadecimal Ed25519
public key. Export does not read the issuer's signing seed or publisher/renewal
keys.

The admitted qualification prefix must be within the actual reviewed binding and
attestation prefixes and contain a `.aos-direct-qualification` path component.
It identifies the separately configured qualification domain; its stage prefix
is exactly that prefix followed by `/.aos-direct-upload`.

```sh
aos-hub-authority-bootstrap --database-url-file ./operator/sql.url export \
  --authority-id '<permanent-authority-uuid>' \
  --association-id '<reviewed-association-id>' \
  --deployment-id '<paired-deployment-id>' \
  --issuer-configuration ./operator/issuer.json \
  --issuer-public-key-file ./operator/issuer-public-key.hex \
  --admitted-prefix 'binding-prefix/.aos-direct-qualification/probe' \
  --output ./operator/export
```

The new directory contains:

| File | Content |
| --- | --- |
| `publication.json` | Canonical current root-reviewed `StorageAuthorityPublication`, including aliases and complete attestation membership. |
| `bootstrap.json` | Closed version-one metadata: exact binding snapshot, public `DirectExternalProfileSelector`, issuer installation/public verifier/timing policy, independently derived read/write cohorts, and isolated stage prefix. |

The binding snapshot contains immutable secret-version references and
fingerprints, never provider material. Selector credential identities are stable
hashes of the actual binding, purpose, generation, reference and fingerprint.
The export contains no provider contract booleans, private-stage qualification,
accepted profile or runtime readiness claim. Use its actual aliases, publication
and cohorts when configuring the independent issuer and Worker consumers. Add
provider closure/private-stage evidence only from actual separately measured
qualification.

Output publication uses a new private directory and files with `0700`/`0600`
permissions. Traversal rejects symlinks, foreign custody and writable ancestors;
the final parent must be private. All documents are bounded to one MiB. The tool
publishes the final directory only after every file is durable and never
overwrites a prior export. A failed attempt may retain a private `.partial`
directory for inspection.

## Hydrate on the operator or Worker machine

After independent issuer initialization and Worker installation, run Hydrate
where the actual provider material is available. It requires live SQL both
before and after the authenticated Worker exchange; an old exported snapshot
alone cannot prove current authority. To keep provider material off Native, run
this separate executable on an operator or Worker machine with narrow protected
SQL connectivity. The Native service does not need a provider credential
manifest.

```sh
aos-hub-authority-bootstrap --database-url-file ./operator/sql.url hydrate \
  --bootstrap ./operator/export/bootstrap.json \
  --worker-url 'https://paired-worker.test' \
  --storage-work-key-file ./operator/storage-work.key \
  --secret-version-manifest ./operator/provider-versions.json \
  --output ./operator/hydration
```

The manifest is the existing owner-private map from exact immutable secret
references to private material files. Hydrate resolves and fingerprint-checks
those exact versions, then calls the existing protected binding publication
interface over the configured HTTPS origin. It verifies the exact acknowledged
revision and rechecks the entire original publication, binding and credential
set against live SQL. Changed pins refuse before publication; changes during
publication trigger exact remote revocation and refuse success. Remote failures
remain failures; they do not establish provider settlement.

`hydration/hydration.json` records the local acknowledgement, its exact snapshot
revision and bootstrap/publication commitments. It contains no material and
always reports `provider_readiness_evaluated: false`. It is an operator receipt,
not a permission, acceptance artifact or provider qualification. Continue with
the existing `aos-hub authority-control-sync`, actual issuer lease renewal,
fresh protected profile inspection, measured SDK/provider/runtime evidence and
independent acceptance review. Each of those steps retains its own trust checks.

## Existing SQL and least privilege

The helper attaches to an existing exact production schema. It creates no
database, runs no migration and changes no SQL rows. SQLite opens read-only and
does not change journal mode. PostgreSQL requires the package's `postgres`
feature, connection permission, schema usage and `SELECT` on these tables:

```sql
GRANT USAGE ON SCHEMA public TO operator_reader;
GRANT SELECT ON schema_version, hub_schema_identity,
  physical_storage_authorities, physical_storage_aliases,
  binding_storage_authority_revisions, storage_authority_attestations,
  storage_authority_admission_heads, storage_authority_admission_revisions,
  bindings, binding_credential_heads, binding_credential_revisions,
  binding_write_revisions TO operator_reader;
```

Limit the login and network audience independently. The subsequent Native
`authority-control-sync` step writes its exact SQL acknowledgement and uses its
existing operator authority. It does not require widening the helper's reader
role.
