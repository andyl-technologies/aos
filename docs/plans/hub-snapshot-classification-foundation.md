# Logical Hub snapshot row classification foundation

This implementation is an internal prerequisite for RFC-0023 state portability.
It classifies one bounded database row into retained metadata and exact-cell
private dependencies. It does not write an archive, implement a CLI, import
state, authenticate an artifact, fetch secrets, copy objects, or activate a Hub.

## Schema contract

`crates/aos-hub-core/src/snapshot/schema-v3.tsv` explicitly covers all 267 tables
and 2,586 columns of the current Native SQLite production initializer: the 266
application tables and the separately synthesized `schema_version` ledger.
Each row names a table disposition, column, storage class, nullability,
primary-key ordinal, and value rule. Classification has no default policy for
an unknown table or column. SQLite `sqlite_sequence` and automatic indices are
not application export tables; their exact schema treatment belongs to the
read-only SQLite adapter.

`SnapshotClassifier` requires the production lineage, current migration count,
and exact ordered hashes of all three scripts. The compiled scripts must also
match the classifier's checked-in hashes. A schema change requires deliberate
classification review even when it leaves table names unchanged. Catalogue
coverage requires the exact declared column order and rejects duplicate tables.
The Native convenience constructor accepts the validated read-only reader
catalogue. Other adapters must independently validate SQL definitions and real
metadata singleton values before constructing that catalogue.

The production-initializer regression compares every table, column order,
storage class, nullability, and primary-key ordinal with this contract. It also
checks that retained tables do not refer through declared foreign keys to an
excluded table. It does not establish complete application reference closure;
identities inside JSON, object references, and self-referencing rows still need
whole-Hub export/import validation.

## Retention and authentication

All tables are retained except these explicit transient authentication tables:

- `sessions`, `oidc_flows`, `magic_links`, and `webauthn_challenges`;
- `device_codes`, `refresh_tokens`, and `refresh_token_families`;
- `rate_limits`.

Restoration must require fresh authentication and replace runtime signing/sealing
configuration through an explicit private workflow. Transient table omission
is not permission to keep previously issued sessions or access JWTs valid.
Durable API-token rows, users, passkey registrations, invitation records, and
security configuration remain retained; secret-bearing cells require private
restoration rather than exposing credential material in the metadata model.

Neither expiry nor a table name containing `session`, `nonce`, `lease`, or
`receipt` authorizes dropping state. Upload/publication sessions, retention
leases, object mutation fences, deletion receipts, worker execution records,
outboxes, authority revisions, and recorded control watermarks survive. Derived
indexes are retained as well. There is no automatic expiry or cleanup here.

`schema_version` and `hub_schema_identity` are validated source metadata,
represented by the schema manifest rather than portable application rows.
This is not an instruction to rewrite source migration history. A future import
must create exactly the admitted destination lineage and separately validate its
markers; foreign or future lineage cannot be adopted implicitly.

## Private exact-cell dependencies

Private bytes never occur in `ClassifiedSnapshotRow`, its JSON serialization,
or its debug representation. Known credential cells include:

| Exact source cell | Classification |
| --- | --- |
| `users.password_hash` | Private credential hash |
| `tokens.hash`, `invitations.token_hash` | Private credential/token hash |
| `invitations.secret_enc`, `org_idp_configs.client_secret_enc` | Private source-sealed ciphertext |
| `instance_config.value` for `draft_signing_key` | Private source-sealed signing material |
| `topology_plans.input_versions_json` for `set_identity_provider` | Entire immutable secret-bearing JSON cell |

Registered free-form context and opaque JSON are conservatively withheld in whole
cells. This includes configuration history, projections, log/error details,
registry README/LLM bodies, configured mirror/webhook URLs, unrestricted mirror
auth references, and opaque serialized runtime state. The OCI SHA-256 tail is
actual unprocessed upload bytes encoded as hex, so it is private even though it
resembles a hash. Its current continuation version and shape are checked without
clearing any upload state or fence. Network address and partition-key BLOB columns remain
lossless byte values; no provider object bytes are fetched by this module.

A private dependency names the exact table and column, a domain-separated digest
of the ordered typed primary key, the domain-separated original typed-cell
digest, original payload length, and private reason. Primary keys are hashed in
the dependency manifest because a key can itself be private context. JSON is
never parsed and reserialized for its checksum or emitted in redacted form.
Identical bytes in different rows remain separate exact-cell dependencies through
the row locator. Digests are checksums, not authentication, encryption, or a
license to disclose low-entropy values through a publicly enumerable artifact.
The eventual archive must itself have appropriate private access controls.

A source-sealed ciphertext dependency does not provide its sealing key. A future
private completion workflow must bind source key provenance and destination
sealing policy explicitly. It must preserve immutable historical JSON bytes and
their existing confirmation/request/evidence hashes. It cannot replace a nested
secret and retain an old hash. Runtime/provider state also needs a typed
restoration or reconciliation contract; generic secret-file completion is not
sufficient. This foundation provides no private companion writer or reader.

Strict immutable secret-manager version references and credential fingerprints
remain metadata only after admission by the existing nonsecret provider-reference
grammar and 64-hex fingerprint shape. Nested authority credential members receive
the same checks. The unrestricted mirror auth-reference field is instead private. They neither fetch payloads nor prove equivalent credentials exist at
a new destination.

## Dynamic and structured values

`instance_config` has an explicit 17-key contract. Unknown keys reject the row.
Signing material is private; free-form branding, URLs, signup-domain lists,
robots and LLM bodies are private context. Policy/boolean/numeric keys have explicit accepted values.

Closed structured admission includes the current secret-bearing IdP plan and
role map, all five permanent physical-authority decision DTOs, signed release
receipt shapes, release records, image-delivery versions, permission arrays,
and other registered string arrays/maps. Unknown DTO members and wire versions
reject. Duplicate JSON members, trailing data, excessive nesting, and floats
reject through the existing strict release-document parser. This integer-only
policy deliberately rejects unsupported legacy JSON instead of converting it.

JSON whose current classification is opaque remains entirely outside retained
metadata. Its arbitrary business properties are not interpreted as portable
configuration. Reserved `schema_version`, `schemaVersion`, `format_version`,
`formatVersion`, `apiVersion`, and `$schema` markers in opaque values reject,
including nested objects. String-map keys and ordinary business `version`
properties retain their column-specific meaning; they are not inferred wire
versions. This boundary does not claim complete semantic admission of opaque
private JSON. A whole-Hub importer must add those contracts before claiming
restoration support for those dependencies.

IdP URL cells reject embedded credentials, query and fragment components, matching
the current producer contract. Historical debug loopback HTTP locators remain
recordable without consulting current runtime flags or granting network access.

Shape validation of signed receipts or archived authority DTOs does not verify
signatures, fresh provider evidence, credential equivalence, or remote authority.
The classifier preserves original JSON bytes and all permanent namespace,
qualification-prefix, admission generation, acknowledgement, and replay-fence
values. A recorded SQL acknowledgement cannot replace a freshly authenticated
executor watermark, and importing these values must never adopt a guard namespace
or admit pending provider work by itself.

## Bounds and remaining delivery

Classification admits at most one MiB of source payload per cell and eight MiB
per row. Schema cardinality fixes row width. Errors omit source values and
unknown setting names. Retained SQL integers use decimal strings, bytes use hex,
and NULL remains distinct from empty text/bytes. Real-number encoding is defined
losslessly, but the current declared schema has no REAL columns and rejects
REAL values in INTEGER/TEXT/BLOB cells.

The remaining snapshot work includes bounded archive chunks and verification,
private completion, complete application/FK/object closure, PostgreSQL and
Worker adapters, staged import, topology translation, and an explicit activation
fence. No runtime credentials or storage providers are touched by this foundation.
Existing staging reset authorization remains independent of this optional work.
