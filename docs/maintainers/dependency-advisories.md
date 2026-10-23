# Dependency advisory gate

`checks.advisories` evaluates the two shipped Rust dependency graphs and the
native libraries selected by those graphs. The check runs without network
access. It builds `cargo-deny` from its pinned source package, reads a fixed
RustSec revision, resolves every supported application target with all
features, and validates the independent accache workspace.

Native components are listed in
`security/advisories/native-inventory.json`. Each entry is tied either to a
literal AOS package version or to an exact `*-sys` package in a lockfile. A
package update therefore fails the gate until the native identity and snapshot
are reviewed together.

Refresh the snapshot at least every 31 days:

1. Select a reviewed RustSec commit, update `rustsec_revision` and
   `generated_on` in `security/advisories/snapshot.json`, and update the
   `fetchgit` hash in `tests/advisory-gate/default.nix`.
2. Review every native component against its primary upstream advisory and
   stable-release records. Record applicable entries in `native_findings` with
   an exact component coordinate, corrected stable version, and source URL.
3. Run `nix-build -A checks.advisories --no-out-link`. Resolve new findings in
   focused package updates whenever a stable correction exists.
4. When an immediate correction is unavailable, add an exact disposition to
   `security/advisories/exceptions.json`. It must state an owner, reason,
   correction, and expiry no more than 90 days away. Cargo findings are parsed
   from the scanner's complete JSON output and matched to that exact coordinate.

The validator rejects stale snapshots, expired or oversized dispositions,
package-version drift, unused dispositions, scanner failures, and native
findings without a disposition. Its regression suite includes a deliberately
affected component and proves that the undisposed fixture fails.
