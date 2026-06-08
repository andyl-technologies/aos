# AOS

AOS is a Linux distribution tailored for headless environments like servers and IoT devices. AOS is bootstrapped with an x86 ELF [`hex0` seed] and built with [Nix]. From `hex0` a "Nix stdenv" like to [the one] found in Nixpkgs is setup after several stages similar to the [Guix full-source bootstrap].

In other words, the only dependencies for AOS are an x86 machine and a Nix interpreter. In particular, AOS does not depend on Nixpkgs, and its flake inputs are empty.

Instead, AOS provides its own package registry and [UEFI]-compatible disk images. AOS does not run a nix-daemon: only packages built ahead of time and published on the registry can be installed.

The absence of a nix-daemon reduces the attack surface and guarantees that packages can never be built locally. The binary-only approach is modeled after Debian's `apt` user experience, with additional benefits from the `/nix/store` such as system and per-user [profiles].

Instead of using host/machine-specific configurations (as in the `nixosConfigurations` [flake output]), AOS system profiles are meant to be installed on more than one machine. AOS system profiles are defined in the `systems` directory using Nix similarly to NixOS.

A single AOS golden image (built from an AOS system profile) can be re-used across many clouds and bare-metal. The generic system is specialized using [Ignition] from CoreOS. Ignition can read instance userdata for most cloud providers and:

- Re-partitions disks and create filesystems on the first boot;
- Manage host-specific state such as `/etc/hostname` or the SSH host key;
- Enable one or more AOS roles that bundled in the system profile.

An AOS role is an [Ignition configuration] created from Nix, shipped under `/etc/aos/ignition-roles/`, and merged from the top-level Ignition configuration in the instance userdata. AOS roles delay part of the configuration from build-time to system activation time (at boot and when a new system profile is installed). Therefore AOS bends the Ignition execution model by executing Ignition more than once and adding support for the `file://` scheme to point to a config under `/etc/aos/ignition-roles`. AOS restricts the usage of Ignition to its idempotent subset.

AOS is currently in an alpha stage / technical preview state. AOS was developed to answer the pain points we ran into trying to run NixOS and Kubernetes at scale across many points of presence.

More documentation to come along the way.

## Acknowledgements

AOS would not be possible without the incredible work from those incredible open source projects and their communities: Nix, NixOS, Nixpkgs ❄️, full-source bootstrap towers 🚀, CoreOS ⚛️…

AOS is developed hand-in-hand with LLMs agents 🤖.

[`hex0` seed]: https://github.com/oriansj/bootstrap-seeds/blob/cedec6b8066d1db229b6c77d42d120a23c6980ed/POSIX/x86/hex0-seed
[Nix]: https://nix.dev/manual/nix/stable/
[the one]: https://nixos.org/manual/nixpkgs/unstable/#chap-stdenv
[Guix full-source bootstrap]: https://guix.gnu.org/en/blog/2023/the-full-source-bootstrap-building-from-source-all-the-way-down/
[UEFI]: https://en.wikipedia.org/wiki/UEFI
[profiles]: https://nix.dev/manual/nix/2.28/package-management/profiles.html?highlight=prof#profiles
[flake output]: https://nix.dev/manual/nix/2.28/command-ref/new-cli/nix3-flake-check.html#evaluation-checks
[Ignition]: https://coreos.github.io/ignition/
[Ignition configuration]: https://coreos.github.io/ignition/configuration-v3_5/
