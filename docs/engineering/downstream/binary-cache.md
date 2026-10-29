# Use the AOS binary cache downstream

AOS builds its toolchains from an audited bootstrap seed. Rebuilding them
takes hours, and two machines that build them separately do not share
identical store paths unless the builds are bit-for-bit reproducible. A
downstream repository should therefore download every AOS toolchain from the
AOS binary cache. Shared action caches, such as a Bazel remote cache, depend on
it: their keys include toolchain paths and file contents, which then match on
every machine that uses the same AOS revision.

This guide covers the settings a downstream flake must carry, the trust setup
for a multi-user Nix daemon, and the check that proves CI downloads every
toolchain.

## Cache channel

AOS publishes to one cache channel today:

| Channel | URL | Public key |
| --- | --- | --- |
| experimental | `https://cdn.aos.andyl.org/andyl/experimental/` | `andyl-experimental-nix-cache-v1:1eydap438KfoN+1wAumCXOewnzzg2Cc5mq9WwEb9z/I=` |

Every release on this channel publishes the complete runtime closure of every
package it ships, including the [toolchain set](flake-api.md#toolchain-set),
for `x86_64-linux` and `aarch64-linux`. Only released AOS revisions are in
the cache. Pin the `aos` input to a release tag; an arbitrary commit can
change toolchain derivations and fall back to source builds.

## Flake settings

Nix reads `nixConfig` only from the flake being built, never from its inputs.
Copy this block into the downstream `flake.nix`, next to `inputs`:

```nix
nixConfig = {
  extra-substituters = ["https://cdn.aos.andyl.org/andyl/experimental/"];
  extra-trusted-public-keys = [
    "andyl-experimental-nix-cache-v1:1eydap438KfoN+1wAumCXOewnzzg2Cc5mq9WwEb9z/I="
  ];
  fallback = true;
};
```

The `extra-` prefix appends to the machine's existing substituters and keys
rather than replacing them. `fallback = true` builds a path from source when
the cache does not have it; omit it in CI that must never build toolchains,
and run the [cache check](#check-cache-coverage) instead.

Nix asks before it applies a flake's `nixConfig`. Answer the prompt, pass
`--accept-flake-config`, or set `accept-flake-config = true` for the user.

## Multi-user daemon trust

On a multi-user installation, the Nix daemon performs substitution, and it
accepts substituters and keys from a client only when that client is trusted.
For an untrusted user, Nix ignores the flake's `nixConfig` cache settings and
builds every toolchain from source. Choose one of these setups on each machine.

**Configure the daemon directly (recommended).** Add the cache to
`/etc/nix/nix.conf` and restart the daemon. Every user then substitutes from
it without further trust:

```text
extra-substituters = https://cdn.aos.andyl.org/andyl/experimental/
extra-trusted-public-keys = andyl-experimental-nix-cache-v1:1eydap438KfoN+1wAumCXOewnzzg2Cc5mq9WwEb9z/I=
```

On NixOS, set the same values in the system configuration:

```nix
nix.settings = {
  extra-substituters = ["https://cdn.aos.andyl.org/andyl/experimental/"];
  extra-trusted-public-keys = [
    "andyl-experimental-nix-cache-v1:1eydap438KfoN+1wAumCXOewnzzg2Cc5mq9WwEb9z/I="
  ];
};
```

**Allow the substituter for untrusted users.** List the URL in
`trusted-substituters` in `/etc/nix/nix.conf`. An untrusted user may then
enable it from a flake's `nixConfig`, and the daemon still verifies the
signature against a key it trusts, so `extra-trusted-public-keys` must also be
in the daemon's configuration:

```text
trusted-substituters = https://cdn.aos.andyl.org/andyl/experimental/
extra-trusted-public-keys = andyl-experimental-nix-cache-v1:1eydap438KfoN+1wAumCXOewnzzg2Cc5mq9WwEb9z/I=
```

**Trust the CI user.** Adding a user to `trusted-users` lets that user's
`nixConfig` take effect. A trusted user can also import unsigned store paths
and change any daemon setting, which is equivalent to root access on the
machine; reserve it for dedicated, single-purpose CI hosts.

Confirm the daemon's view with `nix config show substituters` and
`nix config show trusted-public-keys`.

## Check cache coverage

`toolchain-cache-check` fails when realizing the toolchain set would build any
store path locally. It checks both Linux platforms from either one, because
substitution does not depend on the host. Run it from the downstream checkout
so it uses the AOS revision in `flake.lock`:

```sh
nix run --inputs-from . aos#toolchain-cache-check
```

Without arguments, it asks Nix for a dry run and lists every derivation that
would be built. In CI that should prove a clean machine can download the
toolchains, realize them with no local build slots instead:

```sh
nix run --inputs-from . aos#toolchain-cache-check -- --realise
```

To test the published cache alone, independent of the machine's store and
other substituters, check against an empty local store with only the AOS
cache. `--store` copies the toolchain derivation files, and nothing else, into
that store:

```sh
store=$(mktemp -d)
nix run --inputs-from . aos#toolchain-cache-check -- --realise --store "$store" -- \
  --option substituters https://cdn.aos.andyl.org/andyl/experimental/ \
  --option trusted-public-keys \
    andyl-experimental-nix-cache-v1:1eydap438KfoN+1wAumCXOewnzzg2Cc5mq9WwEb9z/I=
chmod -R u+w "$store" && rm -rf "$store"
```

A local store in a directory is opened by the calling user without the
daemon, so these `--option` values apply even for an untrusted user. Without
`--store`, the daemon decides which substituters an untrusted user gets.

A failure names the derivations that would be built. The usual causes are an
`aos` input pinned to an unreleased commit, missing daemon trust, or a release
that did not publish a platform.
