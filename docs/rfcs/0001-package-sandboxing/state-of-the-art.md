# State of the art: AOS package sandboxing vs. other operating systems

This doc situates the RFC against the state of the art (2024–2026) across package
integration, sandboxing, supply chain, and attestation, and records *why* each
improvement folded into the rest of the RFC is there. It is the comparison; the
*how-to-build* for each gap lives in the topic docs cited inline.

Siblings: [README.md](README.md) · [enforcement.md](enforcement.md) ·
[attestation.md](attestation.md) · [permissions.md](permissions.md) ·
[implementation-plan.md](implementation-plan.md).

## Where AOS already leads

- **Supply-chain foundation.** Hermetic-from-source + content-addressed closures
  + Ed25519 registry signatures + the manifest bound to the NAR hash + the
  fail-closed capability gate (Decision 19) is a stronger base than any shipping
  system. Flatpak is still on GPG (ed25519 partial, key rotation an open bug);
  Snap has a solid Canonical-rooted assertion chain; Android's APK v2–v4 + APEX
  dual-signing + AVB rollback indexes is the strongest incumbent — but **none
  build from source reproducibly**, so none can claim "the artifact is the
  source."
- **Model unification.** Everyone else is bifurcated: trusted "system packages"
  with imperative postinst (deb/rpm) vs. sandboxed "apps" in a separate manifest
  world (Flatpak/Snap). AOS makes *every* package one uniform sandboxed unit with
  one signed manifest — the nixpkgs Modular Services insight (RFC 163) taken to
  its conclusion and made **eval-free + signable**, which Modular Services is not.
- **Compiled declarative manifest.** Rendering `expose` to eval-free artifacts at
  build time mirrors Fuchsia compiling `.cml` → binary `.cm` — the one peer that
  also compiles a declarative integration manifest.
- **Single-switch sandbox invariant.** `aos-pkg-<name>.target` as the sole
  activation root with zero global side-channels, build-time-checkable, is
  cleaner than deb/rpm preset+postinst sprawl and fixes Snap's documented "no
  cross-snap ordering" pain point.
- **Substrate alignment.** Per-unit sandboxing via portable-services directives
  (without `portabled`) is exactly where systemd itself is heading (v257–258:
  `PrivatePIDs=`, `PrivateUsers=identity|full`, `ProtectControlGroups=private`,
  `DelegateNamespaces=`, `PrivateBPF=`).
- **Update granularity.** Nix generations give per-package atomic install/rollback
  — finer than the whole-OS A/B slots ChromeOS, Android (Virtual A/B), Talos, and
  Flatcar all engineer partitions for.

## Where AOS was lagging, and what now closes each gap

| Gap | SOTA comparator | Closed by |
|---|---|---|
| Only one enforcement layer (namespaces/caps/seccomp) | Android (per-app SELinux + seccomp), Fedora/RHEL (SELinux), all-distro **Landlock**, Cloudflare/KubeArmor (**eBPF-LSM**) | [enforcement.md](enforcement.md) — Landlock + MAC + eBPF-LSM, all manifest-derived |
| Ambient path authority (`host-paths`→`BindPaths`) | Flatpak portals (Documents fd), macOS Powerbox + security-scoped bookmarks, Capsicum/seL4/Fuchsia capabilities | [permissions.md](permissions.md)/[container-model.md](container-model.md) — prefer fd-passing; Decision 18 typed routing |
| No runtime integrity over package bytes | ChromeOS/Android/Talos/Flatcar/bootc dm-verity & composefs | [attestation.md](attestation.md) — verity-signed `RootImage=` against the `.platform` keyring |
| No hardware-rooted runtime attestation | Android **Key Attestation**, Apple **App Attest**, Keylime/TPM quotes | [attestation.md](attestation.md) — measure package+manifest into PCR 15, TPM quote, registry golden catalog |
| Single-key supply chain, no transparency | Sigstore/Rekor, TUF, in-toto/SLSA; Nix's own Trustix | [apm-integration.md](apm-integration.md) — provenance + transparency log + TUF hardening |
| Host-global firewall set mutation | Cilium/eBPF per-identity, Android per-UID, Landlock TCP rules | [container-model.md](container-model.md) — per-package eBPF + Landlock egress |
| Partial systemd hardening | the `systemd-analyze security` consensus baseline | [enforcement.md](enforcement.md) — full baseline + per-package CI gate |
| Open secret delivery | TPM2-sealed systemd-creds (signed-PCR policy) | [config.md](config.md) — Decision 9 RESOLVED (signed off): layered (TPM2 creds / schema'd artifact / EnvironmentFile) |

## The novel result

Two improvements put AOS **ahead** of the field rather than level with it:

1. **Attestation-bound per-package privilege.** AOS measures each package's
   content digest **and its signed `[permissions]` manifest** into the TPM event
   log, so a fleet verifier can attest not just *what code* a node runs but *what
   privilege* it runs under. Android/Apple attest app/boot integrity; **none
   attest per-package privilege manifests.** Confirmed against the research: no
   NixOS path today measures or attests the realized store closure at all (PCR 11
   measures the UKI, not store paths) — AOS would be the first Nix-based OS to
   bind the realized package set into a hardware-rooted, attestable chain.
   ([attestation.md](attestation.md))

2. **The registry as the golden-measurements oracle.** The registry's role in
   attestation is the RFC-0006 SB-catalog pattern generalized: it is the
   catalog/policy/provenance plane that records *expected* measurements and hosts
   provenance — **never a runtime signer**, never holding a TPM. This keeps the
   blast radius of a registry compromise contained (publish a new signed package,
   yes; forge a node's measured state, no). ([attestation.md](attestation.md))

## Where AOS deliberately differs (and is right to)

Not everything other systems do applies to a hermetic, server/fleet, no-
interactive-user OS:

- **No interactive portal/file-picker.** Flatpak/macOS broker access through a
  *user* at a dialog; a fleet node has no such user. AOS adopts the *fd-passing
  principle* (handle, not path) without the interactive powerbox UI.
- **No VM-per-app isolation** (Qubes/Spectrum). That is a different threat model
  (untrusted desktop apps); AOS's per-unit + Landlock + MAC + attestation stack
  is the right weight for trusted-but-confined fleet workloads.
- **No app-store gatekeeping** (APK review, notarization). The registry + signed
  manifest + host policy is the fleet-appropriate analog.
- **nspawn stays deferred.** Not a cost cut — it is correctness-driven (the
  `KillMode=process` regression; no multi-unit-init package exists). The budget
  mandate does not change this. ([container-model.md](container-model.md))

## Comparator references

Capability/component OSes: Fuchsia CFv2 (`use`/`offer`/`expose` capability
routing; `expose` is directional + non-transitive), Genode (parent-brokered
caps), seL4 (formally-verified caps). Linux sandboxing: Landlock (ABI 1–6,
5.13–6.12), eBPF-LSM/KRSI (5.7), seccomp, systemd portable services + credentials
+ TPM2. App sandboxing: Flatpak (bubblewrap + xdg-portals), Snap (AppArmor
interfaces), Android (per-UID + SELinux + seccomp + APEX + SDK runtime sandbox +
Key Attestation), iOS/macOS (Seatbelt/TCC + entitlements + Powerbox + App Attest +
Secure Enclave). Immutable OS + supply chain: rpm-ostree/bootc (composefs), Talos
(UKI + TPM-sealed LUKS2), Flatcar (USR-A/B dm-verity + Ignition + sysext),
ChromeOS/Android verified boot (dm-verity + AVB + A/B + attestation), Sigstore/
TUF/in-toto/SLSA, Trustix.
