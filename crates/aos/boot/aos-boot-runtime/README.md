# AOS boot runtime

`aos-boot-runtime` owns retained boot preparation, authenticated image staging,
paired recovery payloads, boot selection, measurement evidence, and initrd
journal store transport. Systemd service resources and credential encryption
belong to `aos-activation-systemd`; immutable tool-path validation is shared
through `aos-nix`.

The Cargo package retains the installed executable contracts:

| Executable | Responsibility |
| --- | --- |
| `aos-boot-preparation-provider` | Transaction-scoped authenticated preparation |
| `aos-systemd-image-stage` | Inactive-root image staging and read-back |
| `aos-systemd-image-evidence` | Signed boot measurement evidence |
| `aos-systemd-boot-platform` | Retained artifact, selection, health, and restart operations |
| `aos-systemd-initrd-store` | Journal-owned store transport restoration |

The default `boot-tools` feature enables the complete image and initrd tools.
The preparation executable is also built with `--no-default-features` for the
static preboot package. This keeps its dependency and test scope independent
of image tools while sharing the preparation implementation and package name.

Executable names, input protocols, digest domains, and retained on-disk formats
are compatibility surfaces. Moving their implementation between Cargo crates
does not rename them. Private-store transport tests require `AOS_NIX_STORE` to
name the source-built Nix store executable.

`standalone/initrd_preparation.rs` implements the installed
`aos-boot-preparations` command. Its Nix derivation compiles the std-only target
directly with `rustc`, freezing the selected package-runtime and configuration
tools through `env!`. It intentionally stays outside ordinary Cargo targets:
compiling it with absent or substitute tool paths would lose its authenticated
closure contract. Its tests run in the same Nix derivation with those paths.
