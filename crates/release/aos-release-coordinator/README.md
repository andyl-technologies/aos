# AOS release coordinator

`aos-release-coordinator` provides effectful release operations without a
command parser or terminal presentation. `aos-release-format` owns portable
schemas and semantic verification; `aos-release-signer` retains private key
custody behind its external process protocol.

| Module | Responsibility |
| --- | --- |
| `capture` | Bounded, no-follow snapshots and verified payload copies |
| `config` | Maintainer configuration decoding and policy checks |
| `credentials` | File and systemd credential resolution |
| `journal` | Verified transitions and durable output publication |
| `projection` | Release bundle to consumer-facing surface layout |
| `registry_entries` | Frozen build outputs and source evidence to publication entries |
| `readback` | Anonymous identity, content, size, and HTTP range verification |
| `signer` | Bounded external signing exchanges and independent verification |
| `tooling` | Installed tooling closure, executors, and bundled signer discovery |

The `aos-cli` release dispatcher consumes these APIs and retains Clap parsing,
command output, and the Hub/static publication adapters. Libraries can perform
publication preparation, signing, and verification without depending on the
CLI application. Persisted documents and signing domains are unchanged.
