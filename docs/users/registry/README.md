# Operate an AOS package registry

An AOS registry is a signed package catalog, a Git object store, and one or
more binary caches. `apr` maintains the producer side. `apm` verifies and
consumes it.

The normal production path is static distribution over HTTPS. A maintainer
creates signed commits and release tags, `apr release` materializes immutable
Git and NAR objects, and the uploader writes those objects before it changes
the small mutable files that point at them. AOS Hub can own the HTTP surface
and its storage, but it is not required.

Three version numbers are easy to confuse:

- a package version identifies a package build, such as `curl` 8.10.1;
- a registry release is a signed snapshot of the whole catalog, such as
  `2026.8.0`;
- a channel maps 256 stable consumer buckets to registry releases.

Changing package metadata does not change consumers until a maintainer creates
and publishes a registry release. Publishing a registry release does not move
a channel unless the release command initializes or advances it.

## Start here

- [Publish a signed registry on the local filesystem](quickstart.md) is a
  complete tutorial using a real package from this repository.
- [Publish packages and releases](publishing.md) covers the routine maintainer
  workflow, signed Git remotes, and repair commands.
- [Automate registry releases](automation.md) covers CI credentials, guarded
  publication, staged advancement, and recovery.
- [Host a registry](hosting.md) covers a shared filesystem, static HTTP,
  object storage and CDNs, SFTP, smart Git, and AOS Hub.
- [Use multiple registries](multiple-registries.md) covers the built-in AOS
  registry, organizational overrides, priorities, and explicit selection.
- [Stage and schedule updates](rollouts.md) covers release channels, rollout
  partitions, automation, observation, and fix-forward recovery.
- [Manage trust and incidents](trust.md) covers trust bootstrap, key custody,
  planned and emergency rotation, and bad package versions.

Package consumers should begin with [Manage packages with APM](../aos/packages.md).
AOS Hub operators should also read [Operate AOS Hub](../aos-hub/).

## Command map

The command-line programs have separate parsers and responsibilities:

| Command | Job |
| --- | --- |
| `apr` | Author, sign, release, and upload a registry |
| `apm` | Configure registries and install or upgrade packages |
| `aos hub` | Administer a running AOS Hub through its HTTP API |
| `aos-hub` | Administer a native Hub through trusted local state |

Run `apr --help` and the relevant subcommand's `--help` against the build you
will deploy. Producer commands change signed state; review `apr status`,
`apr diff`, and `apr release --dry-run` before publishing.
