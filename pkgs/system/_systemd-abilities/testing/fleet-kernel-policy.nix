##! Matches direct-kernel image policy across both authenticated boot scopes.
{lib, ...}: {
  # Direct-kernel tests supply no authenticated root hash; image boots retain
  # their configured verification policy and never import this fragment.
  aos.security.verity.enable = lib.mkForce false;
}
