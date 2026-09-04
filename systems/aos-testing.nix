##! systems/aos-testing.nix — Public experimental AOS disk and OCI artifacts
{
  imports = [./server.nix];

  aos.system.name = "AOS Testing";
  aos.profiles.testingRelease.enable = true;

  # Public half of the dedicated experimental registry root. The private half
  # is operator state and must never enter this repository.
  aos.release.trustKeys = [
    "andyl-testing:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPWdD0Q8y3CRgPouHV03ay7bY2MyQKsKYIyejGL9DVZA"
  ];
}
