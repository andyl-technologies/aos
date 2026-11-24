# Downstream builds

A downstream repository can build with the AOS toolchains and builders by
taking AOS as its only flake input. These pages are written for the people
who maintain such a repository, and they define what AOS must keep stable for
them. The exported builders are implemented in `lib/downstream-api.nix`, and
`tests/downstream/` holds the checks that keep the contract and these pages in
step.

| Page | Covers |
| --- | --- |
| [Quickstart](quickstart.md) | Starting a repository from the template, using the builders, and testing against a local AOS checkout |
| [Flake API](flake-api.md) | The versioned contract: flake outputs, exported names, package attributes, builder arguments, the toolchain set, and the compatibility policy |
| [Binary cache](binary-cache.md) | Cache settings, multi-user daemon trust, and the `toolchain-cache-check` command |

`flake-api.md` is read by `checks.downstream.api-docs`, which compares its
marked tables with the exported attribute set. Keep the table format intact
when editing it.
