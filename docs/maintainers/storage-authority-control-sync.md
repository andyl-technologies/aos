# Native physical authority control reconciliation

`aos-hub authority-control-sync` delivers an existing root-reviewed desired
physical authority decision to the exactly paired Worker metadata ledger. It
uses the Native database selected by `--root` / `HUB_DATABASE_URL_FILE` and these
protected deployment values:

- `HUB_HYBRID_WORKER_URL`: the canonical HTTPS Worker origin.
- `HUB_DEPLOYMENT_ID`: the exact paired deployment identity.
- `HUB_STORAGE_WORK_KEY_FILE`: the existing owner-private control HMAC key file.
- `HUB_EXTERNAL_GUARD_NAMESPACE_ID`: the Worker's actual configured guard domain.
- `HUB_EXTERNAL_STORAGE_EXECUTOR_ID`: its actual configured executor identity.

```text
aos-hub --root /var/lib/aos-hub authority-control-sync \
  --authority-id 00000000-0000-4000-8000-000000000021
```

The command cannot create equivalence assertions or approve admission. Those
operations require fresh instance-root `StorageManage` permission through the
typed `StorageAuthorityService` plan/apply API. It never reads storage credential
payloads, qualifies provider access, executes object I/O, or enables deletion.
A successful JSON result reports the exact desired generation/digest,
`control_synchronized: true`, and `provider_readiness_evaluated: false`.

The publication includes every credential association in the immutable
attestation, including associations outside the admitted subset, and every alias
those associations reference. Current binding identity, resource version,
physical coordinates, and validated credential generations must still match.
The association's immutable writer remains pinned; changing the default writer
for new plans does not rotate it. The configured namespace and executor must
match reviewed facts, and the full serialized publication must fit the shared
aggregate protocol budget. Refusal leaves desired SQL state pending.

The helper observes a fresh signed watermark before publication, verifies the
signed exact publication receipt, then obtains another fresh nonce-bound
watermark. It rechecks current SQL facts and atomically acknowledges only the
same desired generation and digest. Response-loss retries republish identical
facts. Restored SQL behind a newer executor watermark, concurrent SQL changes,
credential revocation, and invalid signatures remain blocked. A persisted SQL
acknowledgement does not replace fresh authority validation at an I/O boundary.
Metadata can change after this acknowledgement; no provider readiness claim is
made by the synchronization result.

## Denial recovery across missing predecessor history

The helper delivers only the current reviewed generation. Ordinary publication
requires its exact predecessor or an exact immutable receipt replay. Current
blocked or retired state can use explicit `DenyFromWatermark` recovery from an
exact fresh remote CAS. It never reconstructs skipped historical decisions:

1. The executor accepts admitted generation 1.
2. SQL creates admitted generation 2 with attestation A; it is never delivered.
3. A expires, then SQL creates blocked generation 3 expecting generation 2.

Generation 2 cannot newly admit using expired A. The helper delivers the current
generation-3 denial directly from the freshly verified generation-1 watermark.
Generation 3 keeps its exact SQL generation-2 parent and immutable digest. The
ledger records the denial's separate transport edge atomically with its normal
publication receipt. Only generation 3 is acknowledged in SQL; generation 2 is
never temporarily admitted, receipted or acknowledged.

This recovery applies only to a higher blocked or retired floor. Admission gaps,
same-generation forks, known conflicting predecessor digests, restored SQL
behind the remote floor and changes after retirement remain blocked. Operators
must not alter historical facts or substitute a SQL backup for the latest
authenticated executor watermark. Response-loss retries first obtain fresh
remote state and replay the exact target publication receipt, proving its entire
fact bundle before SQL acknowledgement.

The current ledger is one control Durable Object. This synchronization uses
fresh authenticated observations and introduces no stale-cache authorization.
Future per-effect permits must reserve before provider I/O and retain unknown
pending effects until settled. Their global metadata hops and contention under
parallel uploads need separate performance qualification. Denial recovery does
not implement those permits or make a provider readiness claim.
