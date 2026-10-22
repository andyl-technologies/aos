# Use a local Terrane repository

The `terrane` CLI works with an absolute `file:///` bucket URL and a private
sibling authority directory. The authority contains signing credentials, a
capability token and protected registration history. Every invocation reopens
that existing configuration and checks current authorization.

Build the package from an AOS development checkout with:

```sh
aos-dev build package terrane --no-out-link
```

Use `bin/terrane` from the resulting store path, or an installed `terrane` on
your `PATH`. `terrane --help` lists the local commands and configured role
options. The following examples use Bash.

## Initialize private local state

Choose an existing directory you own on disk. This example creates a new
private directory under the current working directory. Use paths without URL
reserved characters in this example; the bucket argument is a file URL.

```sh
umask 077
terrane_demo="$PWD/terrane-demo"
mkdir -m 700 "$terrane_demo"

terrane_local=(
  --bucket "file://$terrane_demo/bucket"
  --authority "$terrane_demo/authority"
  --owner-uid "$(id -u)"
)
terrane_expiry=$(date -u -d '+1 hour' +%s)
terrane init "${terrane_local[@]}" --not-after "$terrane_expiry"
```

Let initialization create both leaves. Their common parent must already exist,
and directory ancestors must be real directories. The command refuses existing
authority state and never overwrites a partially initialized repository. Success
prints `initialized refs/heads/_/main`.

The defaults register issuer `local`, key ID `initial`, principal `owner`,
domain `private:owner`, store name `local`, and policy authority
`refs/heads/_/main`. If you override these options at initialization, retain
those choices for subsequent invocations. `--owner-uid` names the expected
filesystem owner; it does not change the process's credentials.

Keep the authority directory mode 0700 and its private credential files mode
0600, owned by the configured UID. Excluding authority state from a public
checkout does not make a bucket a standalone portable backup: protected
registration also binds the original physical backend and control state.

## Commit and check out a snapshot

```sh
mkdir "$terrane_demo/source"
printf '%s\n' 'hello from Terrane' > "$terrane_demo/source/message.txt"

terrane_first=$(terrane commit "${terrane_local[@]}" \
  "$terrane_demo/source" --message 'Add greeting')
terrane checkout "${terrane_local[@]}" \
  refs/heads/_/main "$terrane_demo/checkout"
cat "$terrane_demo/checkout/message.txt"
```

A successful commit prints its commit digest. Checkout creates a new directory
and prints the selected commit digest. It materializes a pinned SDK snapshot;
later branch updates do not change that completed directory. Choose a fresh
destination for another checkout.

To check out the original commit after the branch has advanced, use its digest:

```sh
terrane checkout "${terrane_local[@]}" \
  "commit:$terrane_first" "$terrane_demo/first-checkout"
```

A fixed commit still requires current policy authorization. Knowing its digest
does not grant access to its contents.

## Fork, edit and merge

The source branch is selected by `--reference`, which defaults to
`refs/heads/_/main`. Fork creates a new ref without copying the content.

```sh
terrane fork "${terrane_local[@]}" refs/heads/_/feature \
  --message 'Start feature'
printf '%s\n' 'feature content' > "$terrane_demo/source/feature.txt"
terrane commit "${terrane_local[@]}" --reference refs/heads/_/feature \
  "$terrane_demo/source" --message 'Add feature file'
terrane merge "${terrane_local[@]}" refs/heads/_/feature \
  --message 'Merge feature'
terrane checkout "${terrane_local[@]}" \
  refs/heads/_/main "$terrane_demo/merged-checkout"
```

Keep `--policy-authority` at its registered value while selecting another writer
branch. It identifies current policy for fixed historical reads, independently
of the branch being edited. A conflicting merge or stale writer is refused;
success is acknowledged only after durable guarded publication.

## Compare snapshots and inspect committed history

Compare two refs or fixed commit views through current read authorization:

```sh
terrane diff "${terrane_local[@]}" "commit:$terrane_first" refs/heads/_/main
terrane diff "${terrane_local[@]}" "commit:$terrane_first" refs/heads/_/main --stat
```

The default output lists added (`A`), deleted (`D`) and modified (`M`) entries in
path order. Paths are relative to each selected view, quoted, and byte-escaped;
embedded tabs, line breaks and non-ASCII bytes cannot create extra output rows.
Both views may select a subtree with `:/path`. Policy declaration changes are
reported separately as `policies_changed=true`, including changes that do not
modify entries. `--stat` reports added, removed and modified entry counts and
the policy-change flag. These are metadata differences, without plaintext reads
or text-line statistics. An unchanged comparison has no default output.

Audit the entry's current object through its signed commit history:

```sh
terrane blame "${terrane_local[@]}" refs/heads/_/main feature.txt
terrane blame "${terrane_local[@]}" "commit:$terrane_first" message.txt
```

`blame` reports the selected view, its actual introducing commit, and the merge
commits that carried the current object in parent-before-child order. Each
record includes the issuer, token identifier, subject, principal kind, workload,
process, advisory timestamps, writer epoch and source. String claims are quoted.
Embedded token chains, commit messages and object bodies are excluded. The path
is relative to the view, including a view selected with `:/subtree`. A later
metadata edit can preserve the original object introduction; replacing its
content produces a new introduction. Fixed views still require current path
read authorization.

```sh
terrane log "${terrane_local[@]}"
terrane log "${terrane_local[@]}" --reference refs/heads/_/feature \
  --from-sequence 1
```

Each committed history row includes its sequence, commit, writer epoch,
timestamp, principal and reason. Principal and reason strings are quoted so
embedded control characters cannot appear as additional log events. History
reads require current Read permission.

## Handle refusal and interrupted operations

An expired capability, changed ownership or permissions, mismatched registration,
denied current ACL, invalid input or failed publication makes the command fail.
Changing `--not-after` on a second `init` does not renew an existing token.
Preserve the existing bucket and authority for diagnosis; ordinary initialization
does not repair, relocate or reinitialize their protected records.

`terrane --config ... --check-config` checks configuration syntax and role
selection. Its successful exit does not establish backend readiness, valid
credentials, schema acceptance or completed exposure startup. Configured native
cache deployment also requires the separate host administration and publisher
protocol described in the [host administration guide](../../../crates/terrane/integration/aos-terrane-integration/README.md).
