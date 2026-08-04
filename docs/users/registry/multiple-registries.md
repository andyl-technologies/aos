# Use multiple registries

AOS images seed the public `andyl` registry at
`https://cdn.aos.andyl.org/` with priority 50 and a built-in trust anchor. An
organization can add a higher-priority internal registry without replacing the
public catalog.

## Build registries into an image

Declare organization registries in the system variant:

```nix
{
  aos.apm.registries = {
    andyl.priority = 50;

    acme = {
      url = "https://packages.acme.example/production/";
      trustKeys = [
        "acme:Ed25519:BASE64_CURRENT_KEY"
        "acme:Ed25519:BASE64_NEXT_KEY"
      ];
      priority = 900;
      required = true;
    };

    acme-labs = {
      url = "https://packages.acme.example/labs/";
      trustKeys = ["acme-labs:Ed25519:BASE64_KEY"];
      priority = 700;
      required = true;
    };
  };
}
```

This writes read-only registry definitions and trust anchors under `/etc/apm`.
The first trust key is also the bootstrap signing key in the registry
definition; every listed key is written to the trust store. Multiple keys are
useful during a planned rotation.

Keep verification required in deployed images. `required = false` has the same
security effect as `--no-verify` and is appropriate only for isolated
development.

## Add registries at runtime

For the current user on a development machine or an account with writable XDG
and per-user profile storage:

```sh
apm registry add https://packages.acme.example/production/ \
  --name acme \
  --priority 900 \
  --trust-key 'acme:Ed25519:BASE64_CURRENT_KEY'
```

For machine-wide packages and OS updates:

```sh
apm registry --system add https://packages.acme.example/production/ \
  --name acme \
  --priority 900 \
  --trust-key 'acme:Ed25519:BASE64_CURRENT_KEY'
apm update --system --registry acme
```

User and system scopes have separate writable configuration and synchronized
metadata. A user-scope addition does not configure OS updates.

## Understand priority

Higher numbers win. Resolution chooses the highest-priority registry that
contains a package name before it considers the versions in lower-priority
registries. This makes an organizational registry an actual override:

- if `acme` contains `openssl`, its candidate wins over `andyl` even if the
  public registry advertises a numerically newer version;
- if `acme` does not contain `curl`, `curl` remains available from `andyl`;
- `apm search` and the normal available-package list show one winning entry per
  package name.

Inspect every candidate before relying on an override:

```sh
apm registry list
apm policy openssl
apm show openssl --registry acme
apm show openssl --registry andyl
```

`apm policy` is the clearest audit command because it shows the selected
candidate and the alternatives.

An explicit registry selection is stronger than priority and keeps dependency
resolution in that registry:

```sh
apm install acme-agent --registry acme --dry-run
apm search agent --registry acme
```

Use explicit selection in deployment automation when a package must come from
one catalog. Use priorities for the ordinary organization-wide policy.

## Overrides versus secondary catalogs

Use the same package name in the organization registry only when it is meant
to replace the public package. For unrelated internal software, choose unique
package names and let both registries remain visible.

If an override needs to be removed, first make sure hosts can safely select the
public package again. Removing the internal entry can change the selected
origin as soon as consumers synchronize. Check `apm policy`, package ABI, and
sysroot-lock implications before publishing that removal.

Registries can be disabled without deleting their configuration or cached
state:

```sh
apm registry disable acme-labs
apm registry enable acme-labs
```

For system scope, insert `--system` after `registry`. A registry built into
`/etc/apm` can be disabled through the writable overlay, but removing its seed
requires a new image.
