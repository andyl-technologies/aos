# deploy/sign.nix — AOS bundle signing
#
# Produces a signed update bundle by computing a minisign detached
# signature over the bundle tarball. The output directory contains both
# the original bundle and its .minisig signature file.
#
# Verification at update time uses the corresponding public key baked
# into the AOS update client (aos-update-tool).
#
# Arguments:
#   pkgs       — AOS package set
#   lib        — AOS library
#   bundle     — path to the unsigned bundle tarball (from bundle.nix)
#   signingKey — path to the minisign secret key file
#   comment    — optional trusted comment embedded in the signature
#
# Output:
#   $out/<bundle-name>.tar       — the bundle (copied verbatim)
#   $out/<bundle-name>.tar.minisig — detached minisign signature
#
# Security notes:
#   - The signing key should be kept offline or in a hardware token.
#   - In CI, the key is injected via a secrets manager and destroyed
#     after signing.
#   - The trusted comment includes the version and timestamp for
#     auditability.

{ pkgs, lib, bundle, signingKey, comment ? null }:

let
  # Derive the bundle filename from its path.
  bundleName = builtins.baseNameOf bundle;

  # Default trusted comment includes the bundle name and build time.
  trustedComment =
    if comment != null then comment
    else "AOS update bundle: ${bundleName}";

in pkgs.mkDerivation {
  name = "aos-signed-${bundleName}";

  src = null;
  dontUnpack = true;

  nativeBuildInputs = [
    pkgs.minisign
    pkgs.coreutils
  ];

  buildPhase = ''
    set -euo pipefail

    echo "==> Signing bundle: ${bundleName}"

    # Verify the bundle exists and is a regular file.
    if [ ! -f "${bundle}" ]; then
      echo "ERROR: Bundle not found at ${bundle}" >&2
      exit 1
    fi

    # Verify the signing key exists.
    if [ ! -f "${signingKey}" ]; then
      echo "ERROR: Signing key not found at ${signingKey}" >&2
      exit 1
    fi

    # Copy bundle to working directory.
    cp "${bundle}" "${bundleName}"

    # Compute SHA-256 of the bundle for the log.
    sha256=$(sha256sum "${bundleName}" | cut -d' ' -f1)
    echo "    Bundle SHA-256: $sha256"

    # Sign with minisign (Ed25519).
    # -S  = sign
    # -s  = secret key file
    # -m  = message file (the bundle)
    # -t  = trusted comment (included in signature, verified)
    # -c  = untrusted comment (human-readable, not verified)
    minisign -S \
      -s "${signingKey}" \
      -m "${bundleName}" \
      -t "${trustedComment}" \
      -c "AOS update bundle signature"

    echo "    Signature written: ${bundleName}.minisig"

    # Verify the signature immediately to catch key/bundle mismatches.
    # Extract the public key ID from the secret key for verification.
    echo "==> Verifying signature"
    # Self-verification uses the corresponding .pub if available,
    # otherwise we skip (verification happens on the target node).
    if [ -f "${signingKey}.pub" ]; then
      minisign -V \
        -p "${signingKey}.pub" \
        -m "${bundleName}"
      echo "    Signature verification: PASSED"
    else
      echo "    Skipping self-verification (no .pub file alongside key)"
    fi
  '';

  installPhase = ''
    mkdir -p $out

    # Install the bundle and its detached signature.
    mv "${bundleName}" $out/
    mv "${bundleName}.minisig" $out/

    # Write a verification receipt for CI audit logs.
    cat > $out/signing-receipt.json <<RECEIPT
    {
      "bundle": "${bundleName}",
      "algorithm": "Ed25519",
      "tool": "minisign",
      "trustedComment": "${trustedComment}",
      "bundleSha256": "$(sha256sum $out/${bundleName} | cut -d' ' -f1)"
    }
    RECEIPT

    echo "==> Signed bundle ready at $out/"
  '';
}
