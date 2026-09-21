# andyl/testing public release authorities

Public trust inputs for the `aos-testing` canonical release image. Every file
here is a public half; the matching private keys are operator custody and must
never enter this repository.

| File | Role | Private half |
| --- | --- | --- |
| `db.crt` | Secure Boot db certificate the firmware checks loaded PEs against | `andyl-testing-secure-boot-db-v1` |
| `modsign.crt` | X.509 certificate the kernel trusts for module signatures | `andyl-testing-kernel-module-v1` |
| `pcr.pem` | Public key that verifies signed PCR policies | `andyl-testing-pcr-policy-v1` |
| `enrollment/PK.auth` | Signed Platform Key variable, self-signed | offline PK |
| `enrollment/KEK.auth` | Signed Key Exchange Key variable, signed by PK | offline KEK |
| `enrollment/db.auth` | Signed db variable, signed by KEK | offline KEK |

The three signature lists carry owner GUID
`2fcfa16d-d7b1-5321-9915-ba7d74b47648` and a fixed signing timestamp, so
regenerating them from the same certificates reproduces identical bytes.
Initial enrollment happens in Setup Mode, which does not enforce timestamp
monotonicity.

`db.crt`, `modsign.crt`, and `pcr.pem` are three deliberately distinct trust
domains. UEFI Secure Boot, kernel module loading, and TPM policy sealing must
not collapse onto one key: the release signer holds each under a separate role
so compromising one does not authorize the others.

Signing itself never happens here. The Nix half of the image build emits an
unsigned assembly and `aos release finalize-image` applies the signatures
through the configured signer adapter.
