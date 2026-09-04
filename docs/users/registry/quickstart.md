# Publish a signed local registry

This tutorial publishes the repository's real `zlib` package to a signed
registry on the local filesystem, then reads it through `apm`. It exercises the
same catalog, signature, release, and binary-cache paths used by a hosted
registry without requiring a server.

For production consumer configuration, including other public and internal
registries, use [Configure package registries](../aos/registries.md).

You need Nix with flakes enabled, Git with SHA-256 repository support, and an
incremental builds of the independent `apr` and `apm` programs:

```sh
nix develop -c cargo build --manifest-path crates/Cargo.toml --bin apr --bin apm
export PATH="$PWD/crates/target/debug:$PATH"
git init --object-format=sha256 /tmp/aos-sha256-probe
```

Remove the probe after Git accepts the command. Configure a real Git author
identity if one is not already present:

```sh
git config --global user.name "AOS Registry Maintainer"
git config --global user.email "registry@example.com"
```

## Build a package

Build `zlib` and capture its store path without creating a `result` symlink:

```sh
STORE_PATH="$(nix build .#pkg-zlib --no-link --print-out-paths)"
printf '%s\n' "$STORE_PATH"
```

`apr` reads the package version, platform, runtime closure, and NAR hashes from
the store path. Overrides such as `--name` and `--version` are available, but a
normal AOS package should not need them.

## Create a signed registry

Generate the first maintainer key. The private key is created with mode `0600`
under `~/.config/apm/keys`; the command prints the public trust line:

```sh
KEY_OUTPUT="$(apr keys generate initial --registry acme 2>&1)"
printf '%s\n' "$KEY_OUTPUT"
KEY="$HOME/.config/apm/keys/acme-initial.key"
TRUST_KEY="$(printf '%s\n' "$KEY_OUTPUT" | \
  awk '$NF ~ /^acme:Ed25519:/ { print $NF; exit }')"
test -n "$TRUST_KEY"
```

Create a bare Git origin on the local filesystem, then create the registry with
that remote. The public key enters the committed roster and the matching
private key signs the initial commit:

```sh
GIT_DIR="$PWD/acme-registry.git"
git init --bare --object-format=sha256 "$GIT_DIR"

apr create acme \
  --remote "file://$GIT_DIR" \
  --trust-key "$TRUST_KEY" \
  --trust-key-id initial \
  --key "$KEY"
```

The authoring clone is under `~/.local/share/apm/registries/acme`. The bare
origin will become the filesystem read surface after the first push.

## Release and publish it

Choose an empty absolute directory for the generated HTTP surface and binary
cache:

```sh
PUBLISH_DIR="$PWD/acme-registry-public"
mkdir -p "$PUBLISH_DIR"

apr release 1.0.0 \
  --registry acme \
  --store-path "$STORE_PATH" \
  --description "Compression library" \
  --license Zlib \
  --maintainer registry@example.com \
  --key "$KEY" \
  --cache-url "file://$PUBLISH_DIR" \
  --upload-url "file://$PUBLISH_DIR"

apr push --registry acme --branch stable --set-upstream
git -C "$HOME/.local/share/apm/registries/acme" \
  push origin refs/tags/1.0.0
```

The release command publishes and commits package metadata, records the store
closure, generates the static Nix cache, creates a signed `1.0.0` tag, and
uploads the generated HTTP origin in safe order. The following push makes the
branch and signed tag available through the bare filesystem Git origin. Inspect
both sides:

```sh
apr packages --registry acme
apr keys list --registry acme
git --git-dir "$GIT_DIR" show-ref
find "$PUBLISH_DIR" -maxdepth 2 -type f | sort | head
```

## Consume the registry

Add the bare Git origin as a user-scope registry. Select `stable` explicitly
because a newly initialized bare repository may retain a different default
`HEAD`. Supplying the trust key makes the first synchronization verifiable:

```sh
apm registry add "file://$GIT_DIR" \
  --name acme \
  --priority 900 \
  --branch stable \
  --trust-key "$TRUST_KEY"

apm search zlib --registry acme
apm show zlib --registry acme
apm install zlib --registry acme --dry-run
```

The filesystem transport is useful for development, removable media, and
shared storage. The package metadata comes from the bare Git repository; the
cache URL committed in the release points at `$PUBLISH_DIR`. Production rollout
channels require a static HTTP origin.

Now that `acme` has a local consumer configuration, register the private key
path so later producer commands can use the roster id instead of repeating a
path:

```sh
apr keys register initial --key "$KEY" --registry acme
apr status --registry acme
```

Continue with [Host a registry](hosting.md) to put the same static tree behind
HTTPS, or [Stage and schedule updates](rollouts.md) to introduce a channel.
