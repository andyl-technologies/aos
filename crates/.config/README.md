# Rust test environments

The `default` and `ci` Nextest profiles select the full configured suite.
`pkgs.aos` uses `nix-sandbox`, which inherits the same timeouts and failure
policy but excludes 110 explicitly named native-environment cases. Test names
are exact and package-qualified; unrelated and future tests remain selected.

The excluded cases require protected root-to-fixture ownership (96 Journal
tests), root-owned fixed Nix store ancestry (one Network test), working
`user.*` extended attributes (three GuestRoot tests), or a real readable
cgroup-v2 root (five Host/Linux and five Publisher tests). An isolated Nix build can expose
unmapped administrative UIDs and omit the host cgroup filesystem. These
tests retain their production ownership, mode and native checks.

The AOS QEMU `sandbox-domain-native-journal` check runs the complete Domain
unit suite under an unprivileged UID with protected guest ancestry. It reads
the exact Domain names from the sandbox profile and requires each to report
success, including all 52 Method46 initial-provisioning fixtures. This component
result does not qualify the installed producer, TPM floors or public lifecycle.

Complete qualification requires both the sandbox suite and a full
`host-native` run with identical source, application package roster, features,
compiler and native inputs. Host compilation retains its original source and
fixture paths; the discovered, hashed host artifacts are the same artifacts
that the host runner executes. Packaged and host objects are not required to
be bit-identical. The host entry must first verify the actual
protected ancestry, writable/readable `user.*` scratch attributes, and a real
cgroup-v2 root. A failed prerequisite fails host qualification; it must not
silently skip a case. Run `host-native` without a narrowing filter or `--skip`.
Retain the source and binary hashes, discovered test roster, results and the
pre-existing ignored-test census. A smaller curated run does not replace it.

Both runners use `RUST_MIN_STACK=33554432` (32 MiB) for Rust test threads.
This test setting is not evidence for production stack or service budgets.
Cargo doctests remain a separate check over the same application packages;
Nextest does not run them. Report host qualification separately until it
actually passes, including any unavailable host prerequisite.
