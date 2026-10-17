# Native Hub vulnerability scanning

AOS builds Grype 0.119.0 and Syft 1.52.0 from pinned upstream source and pinned
Go modules using its own Go toolchain. The vulnerability database is a separate,
hash-pinned data input; it is not bundled into the scanner runtime closure.

```sh
nix-build -A pkgs.grype --no-out-link
nix-build -A pkgs.syft --no-out-link
nix-build -A pkgs.grype.passthru.databaseArchive --no-out-link
nix-build -A checks.integration.grype-scan --no-out-link
```

The qualification check catalogs a small OCI image containing vulnerable
Lodash 4.17.20, imports the real upstream advisory database, and requires the
actual command injection advisory to be detected. It also requires a scan
without a database to fail specifically because the database is absent. Its
saved catalog, database status, vulnerability report, and failure log are
available in the check output. This immutable historical fixture disables the
database age check so that the qualification remains reproducible.

## Database freshness for delivery

Delivery must disable automatic database and application updates, enable
database hash validation, and require a valid schema-v6 database built within
120 hours. The database's actual status timestamp determines freshness; the
timestamp embedded in the archive filename is not the build timestamp.

Refresh [the database pin](../../pkgs/security/_grype-database.nix) using the
archive URL and SHA-256 from the [official upstream database
manifest](https://grype.anchore.io/databases/v6/latest.json). Review and commit
the new pin. A previously valid archive becomes too old for delivery after
120 hours and must be replaced. A missing or stale database must stop delivery.

## What the inventory covers

Syft catalogs the verified Native OCI image and supplies package identities for
the shipped Nix outputs and recognized binaries. Native Rust executables do not
currently carry a complete dependency inventory that Syft can recover. The
delivery producer therefore also reads the image's colocated
`nix-support/cargo-build-messages.jsonl` and checks that it belongs to the Hub
output containing the primary binary and its source build record.

The producer adds exact Cargo PURLs for crates.io library artifacts recorded
by that build. It excludes tests, procedural macros, build scripts, executables,
and local or Git packages. It binds this inventory to the OCI manifest, layer,
and build-message hashes. These are conservative compiled library candidates:
some may be build-only dependencies or contain code removed during linking.
Local and Git dependencies and native system libraries need their own evidence;
the Cargo inventory does not establish complete image coverage.

Grype scans the resulting catalog. The AOS closure SPDX document is retained
separately for closure and license provenance. A successful scanner exit or an
empty findings list alone does not prove that package coverage is adequate.

An actual scan on 2026-09-28 of the earlier Native credential baseline image
(`sha256:cdda6348df55191f3c16d368ee5856ffdca6d773c27304ab8467b4da52053e09`)
recognized seven Syft packages and 408 Cargo library candidates. It reported
one High finding, CVE-2026-85091 on zlib 1.3.2, and no Critical findings. A
separate vulnerable Rust fixture verified the Cargo schema against a real
Rust advisory using Grype's Rust matcher. These results qualify the scanner
and inventory path; the image selected for delivery requires its own scan.
