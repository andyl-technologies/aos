# Manage certificates and CA trust

AOS installs the Mozilla CA bundle for ordinary TLS verification. A deployment
may append organizational certificate authorities needed for internal package
registries, identity providers, monitoring, or application services.

CA certificates and public keys are public trust material. Their private keys
are secrets and must never enter the repository, Nix evaluation, a derivation,
the Nix store, or an image.

## Add an organizational CA

Reference a reviewed public certificate from image policy or authenticated
configuration:

```nix
{
  aos.security.pki.certificateFiles = [
    ./acme-root-ca.pem
  ];
}
```

The resulting bundle is installed at
`/etc/ssl/certs/ca-certificates.crt` and its compatibility paths. Adding a root
extends trust for every consumer of that bundle; review its name constraints,
issuance policy, lifetime, and intended environment before fleet rollout.

Do not add a leaf server certificate as a general CA merely to make one TLS
connection succeed. Correct the server chain or use a narrowly configured
application pin when the application supports it.

## Verify the installed chain

Check both the installed root and a real service endpoint:

```sh
test -r /etc/ssl/certs/ca-certificates.crt
openssl s_client \
  -connect packages.example.com:443 \
  -servername packages.example.com \
  -CAfile /etc/ssl/certs/ca-certificates.crt </dev/null
```

Verify the hostname, complete chain, validity interval, expected issuer, and
revocation policy used by the application. A successful TCP connection is not
TLS identity evidence.

## Distinguish certificate roles

Do not conflate these public materials:

| Material | Purpose |
| --- | --- |
| TLS CA root | Authenticates a network service certificate |
| Registry Ed25519 key | Authenticates signed registry history and catalogs |
| Nix-cache public key | Authenticates narinfo fingerprints for substitution |
| Secure Boot db certificate | Authenticates bootable PE artifacts |
| PCR-policy public key | Authenticates measurements allowed to unlock sealed state |
| Signed-configuration public key | Authenticates `host.nix` input |

Serving a registry over valid organizational TLS does not authorize its
packages. Configure its registry key independently as described in [Configure
package registries](registries.md).

## Rotate a CA safely

Use an overlap:

1. Add the successor CA while the old CA remains trusted.
2. Deploy service certificates chaining to the successor.
3. Verify every required client and recovery environment.
4. Remove the old CA in a later image or configuration generation.

Account for offline machines and rollback images before removing a root. An old
image may lack the successor; a new service certificate may therefore break
recovery, registry access, or identity-provider access even when the running
fleet is healthy.

If an issuing private key is compromised, stop issuance, revoke or distrust the
affected hierarchy according to deployment policy, replace service
certificates, and distribute a corrected trust bundle through an independently
trusted path. Do not disable TLS verification to bridge the incident.

See [Manage secrets on AOS](secrets.md) for private-key storage and exposure
response.
