##! Publishes the selected immutable public PCR-policy key to native boot policy.
{package, ...}: {
  aos.boot.secureBoot.measuredBoot._effectivePcrPublicKey = "${package}/pcr.pem";
}
