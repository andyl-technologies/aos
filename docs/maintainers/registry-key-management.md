# Registry key management

`andyl/testing` does not use an HSM. Its trust root and signing keys are
independent of `andyl/main`.

## Intended management for andyl/main

This is the intended production key-management policy. It is not a statement
that the provider integrations or the main launch gates have been completed.
GCP and AWS KMS/HSM integration is future work; introducing a provider requires
implementation and qualification against the AOS signing protocols.

Keep private release authority outside the Hub and outside Nix derivations,
store closures, source checkouts, and published bundles. The Hub receives signed
artifacts and public verification material. Its login credentials, encryption
key, upload grants, and environment receipt signers are separate authorities.

| Authority | Intended custody and policy |
| --- | --- |
| TUF root | Three offline hardware-backed keys in independent custody; 2-of-3 threshold |
| TUF top-level targets and delegations | Separate offline hardware-backed keys; 2-of-3 threshold |
| TUF stable release | Separate offline hardware-backed keys in independent custody; 2-of-3 threshold |
| TUF candidate release | Dedicated operator-present hardware-backed keys; 1-of-2 policy |
| TUF snapshot | Dedicated restricted online signer; may bind only authorized metadata |
| TUF timestamp | Separate restricted online signer; may renew only an authorized snapshot |
| Registry Git commit and tag | Dedicated hardware-backed Ed25519 signer |
| Edge, candidate, and stable channels | A distinct signer for each named channel; cannot authorize release content |
| Nix cache | Dedicated non-exportable Ed25519 key for approved narinfo fingerprints |
| Release evidence and qualification | Separate hardware-backed authorities bound to exact release and qualification evidence |
| Secure Boot PK, KEK, db, module and PCR policy | Distinct hardware-backed authorities, with offline custody or operator approval appropriate to each role |

Both registries accept edge, candidate, stable, and emergency release classes.
Main requires strict pipeline provenance for every class, including edge;
testing exercises new build and release mechanisms with lighter assurance. Do not import testing keys into main's trust policy. A threshold is
meaningful only when its custodians and administrative access are independent;
several keys accessible through one online credential do not provide that
separation.

## Provider integration requirements

Provision dedicated AOS keys and narrowly scoped signing identities. Pin exact
key versions and public fingerprints, separate key administration from signing,
enable signing audit records, and protect keys from accidental destruction.
Neither a mutable `latest` alias nor a provider account name is a trust anchor.

Qualify the complete algorithm and wire format before adopting a provider:
Ed25519 signatures, OpenSSH SSHSIG for Git, Nix narinfo signatures, and the
appropriate boot-signing formats. Existing ECDSA infrastructure keys cannot
replace an Ed25519 authority. Provider credentials authorize access to a key;
the AOS signer must additionally enforce role, registry, metadata version,
release identity, and payload binding through its external-signer protocol.

An HSM integration must verify signatures independently using pinned public
material and reject wrong-role requests, substituted keys, malformed responses,
and unexpected provider versions. Provider availability and account recovery
are part of the release recovery procedure. Non-exportable private keys are
not ordinary secret-manager export items.

## Inventory, rotation, and recovery

Maintain a public inventory with key ID, role, registry, algorithm, fingerprint,
immutable provider version or device identity, custodian, activation and review
dates, successor, recovery status, and last verified use. Private credentials
and recovery material are separate from the public inventory.

For planned rotation, establish new public authority before switching signers:

1. Publish every intermediate TUF root signed by the required old and new
   thresholds. Preserve metadata version floors and delegated path policy.
2. Carry registry keys through a signed roster overlap, test a client with the
   old baked anchor, and update Hub trust sets with the complete overlap set.
3. Rotate cache and channel authorities independently. Keep verification keys
   needed by retained artifacts, bootstrap images, and recovery media.
4. For boot keys, establish firmware and recovery coverage before retiring old
   authority or distributing revocations.
5. Retire the old signer only after the required client and recovery coverage
   is proven. Never delete a key version still needed for recovery.

Rehearse both loss and compromise. Loss may use a surviving threshold or
provider recovery; compromise requires reviewing all affected authorizations
and using uncompromised authority or an explicit out-of-band bootstrap. Freeze
affected publication, retain evidence, and recover with verified fix-forward
releases. Do not weaken verification to restore availability.

Hub seal-key rotation is a separate operation: preserve the key paired with
each backup, migrate and verify every sealed value, and only then retire old
decryption material. JWT rotation invalidates issued access tokens and does not
rotate artifact trust.

See the [security and key architecture](../rfcs/0017-canonical-hub-publishing/03-security-and-keys.md),
[main runbook](registry-main.md), and
[Hub backup and recovery runbook](aos-hub-backup-recovery.md) for release and
recovery gates.
