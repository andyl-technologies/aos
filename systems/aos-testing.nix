##! systems/aos-testing.nix — Public experimental AOS disk and OCI artifacts
{
  imports = [./server.nix];

  aos.profiles.testingRelease.enable = true;

  # Public half of the dedicated experimental registry root. The private half
  # is operator state and must never enter this repository.
  aos.release.trustKeys = [
    "andyl-testing:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAID1J77zx10Z/VmgFa5qab2phnJEJ2JEp8mS2HnBAnzbH"
  ];
}
